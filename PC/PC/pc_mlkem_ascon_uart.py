import argparse
import hashlib
import sys
import time
from typing import Dict, Optional

import serial

from pqcrypto.kem.ml_kem_768 import generate_keypair, decrypt

try:
    from ascon import ascon_decrypt
except ImportError:
    print("[ERREUR] Impossible d'importer ascon.py")
    print("Placez le fichier ascon.py dans le même dossier que ce script.")
    sys.exit(1)


# Tailles ML-KEM-768
MLKEM_PUBLICKEYBYTES = 1184
MLKEM_CIPHERTEXTBYTES = 1088
MLKEM_SHAREDSECRETBYTES = 32

# Tailles ASCON-AEAD128
ASCON_KEY_SIZE = 16
ASCON_NONCE_SIZE = 16
ASCON_TAG_SIZE = 16
ASCON_TEMP_SIZE = 4

# Doit être identique au code STM32
KDF_LABEL = b"PFE_MLKEM768_ASCON_AEAD128_V1"
AD_LABEL = b"PFE_TEMP_V1"


def derive_ascon_session(shared_secret: bytes):
    """
    Même dérivation que dans ASCON_App_InitFromSharedSecret côté STM32 :

    SHAKE256(label || shared_secret) -> 32 octets

    derived[0:16]   = key_ascon
    derived[16:28]  = nonce_prefix
    derived[28:32]  = session_id
    """
    if len(shared_secret) != MLKEM_SHAREDSECRETBYTES:
        raise ValueError(f"shared_secret invalide: {len(shared_secret)} octets")

    derived = hashlib.shake_256(KDF_LABEL + shared_secret).digest(32)

    key_ascon = derived[0:16]
    nonce_prefix = derived[16:28]
    session_id = int.from_bytes(derived[28:32], "big")

    return key_ascon, nonce_prefix, session_id


def build_associated_data(seq: int, session_id: int) -> bytes:
    """
    Doit être identique à build_associated_data() côté STM32 :

    AD = "PFE_TEMP_V1" || session_id_be || seq_be
    """
    return (
        AD_LABEL
        + session_id.to_bytes(4, "big")
        + seq.to_bytes(4, "big")
    )


def parse_key_value_line(line: str) -> Dict[str, str]:
    """
    Parse une ligne du type :

    DEMO|seq=1|sid=4153434F|clear=2741|nonce=...|cipher=...|tag=...

    Retourne :
    {
        "type": "DEMO",
        "seq": "1",
        "sid": "4153434F",
        ...
    }
    """
    parts = line.strip().split("|")
    result = {"type": parts[0] if parts else ""}

    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            result[key] = value

    return result


def read_line(ser: serial.Serial, timeout_s: Optional[float] = None) -> Optional[str]:
    """
    Lit une ligne UART. Retourne None si timeout.
    """
    old_timeout = ser.timeout

    if timeout_s is not None:
        ser.timeout = timeout_s

    raw = ser.readline()

    if timeout_s is not None:
        ser.timeout = old_timeout

    if not raw:
        return None

    return raw.decode(errors="replace").strip()


def wait_for_stm32_ready(ser: serial.Serial):
    """
    Attend que la STM32 soit prête à recevoir la public key.
    Version robuste :
    - accepte WAIT_PK exact
    - accepte une ligne partiellement corrompue contenant WAIT ou bytes=1184
    - envoie PING si la carte est déjà bloquée en attente de PK
    """
    print("[PC] Attente de la STM32...")
    print("[PC] Si rien n'apparaît, appuyez sur RESET sur la carte.")

    last_ping = time.time()
    start = time.time()

    while True:
        line = read_line(ser, timeout_s=1.0)

        if line is not None:
            print(f"[STM32] {line}")

            if line.startswith("WAIT_PK"):
                print("[PC] La carte attend la public key ML-KEM.")
                return

            if "WAIT_PK" in line:
                print("[PC] La carte attend la public key ML-KEM.")
                return

            if "bytes=1184" in line or "hex_chars=2368" in line:
                print("[PC] Ligne WAIT_PK partielle détectée.")
                print("[PC] On considère que la carte attend la public key.")
                return

            if line == "PONG":
                print("[PC] PONG reçu : la carte est bien en attente UART.")
                print("[PC] On envoie la public key.")
                return

        now = time.time()

        if now - last_ping > 3.0:
            print("[PC] Envoi PING pour vérifier si la carte attend déjà la PK...")
            ser.write(b"PING\n")
            ser.flush()
            last_ping = now

        if now - start > 20.0:
            print("[PC] Toujours pas de WAIT_PK clair.")
            print("[PC] Appuyez sur RESET sur la carte STM32.")
            start = now


def send_public_key(ser: serial.Serial, public_key: bytes):
    """
    Envoie la public key en HEX à la STM32.

    Format accepté par votre firmware :
    PK|2368|<public_key_hex>
    """
    if len(public_key) != MLKEM_PUBLICKEYBYTES:
        raise ValueError(f"public key invalide: {len(public_key)} octets")

    pk_hex = public_key.hex().upper()
    line = f"PK|{len(pk_hex)}|{pk_hex}\n"

    print(f"[PC] Envoi public key : {len(public_key)} octets / {len(pk_hex)} caractères HEX")
    ser.write(line.encode())
    ser.flush()


def wait_for_ciphertext_and_session(ser: serial.Serial) -> bytes:
    """
    Lit les lignes STM32 jusqu'à trouver :

    CT|2176|<ct_hex>

    Retourne le ciphertext ML-KEM en bytes.
    """
    print("[PC] Attente du ciphertext ML-KEM depuis la STM32...")

    ct_kem = None

    while True:
        line = read_line(ser, timeout_s=30.0)

        if line is None:
            raise TimeoutError("Timeout: aucun CT reçu depuis la STM32")

        print(f"[STM32] {line[:120]}{'...' if len(line) > 120 else ''}")

        if line.startswith("ERR|"):
            raise RuntimeError(f"Erreur STM32: {line}")

        if line.startswith("CT|"):
            parts = line.split("|", 2)

            if len(parts) != 3:
                raise ValueError(f"Ligne CT invalide: {line}")

            expected_hex_len = int(parts[1])
            ct_hex = parts[2].strip()

            if len(ct_hex) != expected_hex_len:
                raise ValueError(
                    f"Taille CT HEX incorrecte: reçu {len(ct_hex)}, attendu {expected_hex_len}"
                )

            ct_kem = bytes.fromhex(ct_hex)

            if len(ct_kem) != MLKEM_CIPHERTEXTBYTES:
                raise ValueError(
                    f"Taille CT incorrecte: reçu {len(ct_kem)}, attendu {MLKEM_CIPHERTEXTBYTES}"
                )

            print(f"[PC] CT ML-KEM reçu : {len(ct_kem)} octets")

        if line.startswith("SESSION_OK"):
            if ct_kem is None:
                raise RuntimeError("SESSION_OK reçu avant CT")
            return ct_kem


def decrypt_temperature_line(line: str, key_ascon: bytes) -> Optional[int]:
    """
    Déchiffre une ligne DEMO ou DATA.

    Retourne temp_centi si OK.
    Retourne None si ce n'est pas une ligne DATA/DEMO.
    Lève une erreur si le tag est invalide.
    """
    if not (line.startswith("DEMO|") or line.startswith("DATA|")):
        return None

    fields = parse_key_value_line(line)

    seq = int(fields["seq"])
    sid_hex = fields["sid"]
    session_id = int(sid_hex, 16)

    nonce = bytes.fromhex(fields["nonce"])
    cipher = bytes.fromhex(fields["cipher"])
    tag = bytes.fromhex(fields["tag"])

    if len(nonce) != ASCON_NONCE_SIZE:
        raise ValueError(f"Nonce invalide: {len(nonce)} octets")

    if len(tag) != ASCON_TAG_SIZE:
        raise ValueError(f"Tag invalide: {len(tag)} octets")

    if len(cipher) != ASCON_TEMP_SIZE:
        raise ValueError(f"Cipher température invalide: {len(cipher)} octets")

    associated_data = build_associated_data(seq, session_id)

    plaintext = ascon_decrypt(
        key_ascon,
        nonce,
        associated_data,
        cipher + tag,
        variant="Ascon-AEAD128",
    )

    if plaintext is None:
        raise ValueError(f"TAG FAIL pour seq={seq}")

    if len(plaintext) != 4:
        raise ValueError(f"Plaintext invalide: {len(plaintext)} octets")

    temp_centi = int.from_bytes(plaintext, "big", signed=True)

    clear_from_demo = fields.get("clear")
    if clear_from_demo is not None:
        clear_int = int(clear_from_demo)
        compare = "OK" if clear_int == temp_centi else "DIFF"
        print(
            f"[DATA] seq={seq} | temp_dec={temp_centi / 100:.2f} °C "
            f"| clear_STM32={clear_int / 100:.2f} °C | integrity=OK | compare={compare}"
        )
    else:
        print(
            f"[DATA] seq={seq} | temp_dec={temp_centi / 100:.2f} °C | integrity=OK"
        )

    return temp_centi


def main():
    parser = argparse.ArgumentParser(
        description="Demo PC ML-KEM-768 + ASCON-AEAD128 + UART STM32"
    )
    parser.add_argument("--port", default="COM5", help="Port série, ex: COM5")
    parser.add_argument("--baud", type=int, default=115200, help="Baudrate UART")
    parser.add_argument(
        "--show-key",
        action="store_true",
        help="Affiche la clé ASCON dérivée. Debug uniquement.",
    )
    args = parser.parse_args()

    print("=== PC Demo ML-KEM-768 + ASCON-AEAD128 ===")
    print(f"[PC] Port: {args.port}")
    print(f"[PC] Baud: {args.baud}")

    print("[PC] Génération keypair ML-KEM-768...")
    public_key, secret_key = generate_keypair()

    print(f"[PC] public_key = {len(public_key)} octets")
    print(f"[PC] secret_key = {len(secret_key)} octets")

    if len(public_key) != MLKEM_PUBLICKEYBYTES:
        print("[ERREUR] La taille de public_key ne correspond pas à ML-KEM-768 attendu.")
        print("Vérifiez que vous utilisez bien pqcrypto.kem.ml_kem_768.")
        sys.exit(1)

    with serial.Serial(args.port, args.baud, timeout=1) as ser:
        print("[PC] Port série ouvert.")
        print("[PC] Appuyez maintenant sur RESET sur la carte STM32 si rien ne se passe.")
        time.sleep(0.5)

        wait_for_stm32_ready(ser)
        send_public_key(ser, public_key)

        ct_kem = wait_for_ciphertext_and_session(ser)

        print("[PC] Décapsulation ML-KEM avec la private key côté PC...")
        shared_secret = decrypt(secret_key, ct_kem)

        print(f"[PC] shared_secret obtenu : {len(shared_secret)} octets")

        key_ascon, nonce_prefix, session_id = derive_ascon_session(shared_secret)

        print(f"[PC] ASCON session_id dérivé = {session_id:08X}")
        print(f"[PC] nonce_prefix dérivé = {nonce_prefix.hex().upper()}")

        if args.show_key:
            print(f"[DEBUG] key_ascon = {key_ascon.hex().upper()}")

        print("[PC] Attente des températures chiffrées...")
        print("[PC] Ctrl+C pour arrêter.\n")

        last_seq = 0

        while True:
            line = read_line(ser, timeout_s=10.0)

            if line is None:
                print("[PC] Timeout lecture DATA...")
                continue

            if line.startswith("ERR|"):
                print(f"[STM32] {line}")
                continue

            if line.startswith("DEMO|") or line.startswith("DATA|"):
                fields = parse_key_value_line(line)

                seq = int(fields["seq"])
                if seq <= last_seq:
                    print(f"[WARN] Replay ou ancien message détecté: seq={seq}, dernier={last_seq}")
                    continue

                decrypt_temperature_line(line, key_ascon)
                last_seq = seq
            else:
                print(f"[STM32] {line}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[PC] Arrêt demandé par l'utilisateur.")
    except Exception as exc:
        print(f"\n[ERREUR] {exc}")
        sys.exit(1)