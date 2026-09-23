# KEM_768_PQM4_DEMO — Démo ML-KEM-768 + ASCON-AEAD128 sur STM32

## 1. Objectif du projet

Ce projet met en place une démonstration complète de communication sécurisée entre un **ordinateur** et une **carte STM32 NUCLEO-L496ZG**.

Chaîne cryptographique utilisée :

```text
ML-KEM-768
↓
shared_secret
↓
SHAKE256
↓
key_ascon + nonce_prefix + session_id
↓
ASCON-AEAD128
↓
température chiffrée + tag d’intégrité
```

Principe de la démonstration :

1. Le PC génère une paire de clés ML-KEM-768.
2. Le PC envoie uniquement la **clé publique** à la STM32.
3. La STM32 encapsule un secret partagé avec ML-KEM.
4. La STM32 renvoie le **ciphertext ML-KEM** au PC.
5. Le PC décapsule avec sa **clé privée**, qui ne quitte jamais le PC.
6. Les deux côtés obtiennent le même `shared_secret`.
7. Les deux côtés dérivent une clé ASCON avec SHAKE256.
8. La STM32 lit la température via le capteur BMP280.
9. La STM32 chiffre et authentifie la température avec ASCON-AEAD128.
10. Le PC vérifie le tag ASCON, déchiffre la température et l’affiche.

---

## 2. Matériel nécessaire

- Carte **STM32 NUCLEO-L496ZG**
- Câble USB data branché sur le port **ST-LINK**
- Capteur **BMP280**
- Ordinateur Windows avec :
  - STM32CubeIDE
  - Python 3
  - PuTTY ou Tera Term pour un test série optionnel

---

## 3. Arborescence minimal attendue

```text
KEM_768_PQM4_DEMO/
├── Core/
│   ├── Inc/
│   │   ├── main.h
│   │   ├── pqm4.h
│   │   ├── putty.h
│   │   ├── randombytes.h
│   │   ├── temperature_sensor.h
│   │   ├── ascon.h
│   │   └── uart_connection.h
│   │
│   └── Src/
│       ├── main.c
│       ├── pqm4.c
│       ├── putty.c
│       ├── randombytes.c
│       ├── temperature_sensor.c
│       ├── ascon.c
│       └── uart_connection.c
│
├── Drivers/
├── PQC/
│   ├── common/
│   │   ├── fips202.c
│   │   ├── fips202.h
│   │   ├── keccakf1600.h
│   │   └── keccakf1600.S
│   │
│   ├── m4fspeed/
│   │   └── fichiers ML-KEM-768 PQM4
│   │
│   └── ascon/
│       └── asconaead128-ref/
│           ├── aead.c
│           ├── api.h
│           ├── ascon.h
│           ├── constants.h
│           ├── crypto_aead.h
│           ├── permutations.h
│           ├── printstate.c
│           ├── printstate.h
│           ├── round.h
│           └── word.h
│
├── python/
│   ├── pc_mlkem_ascon_uart.py
│   ├── ascon.py
│   └── requirements.txt
│
├── KEM_768_PQM4_DEMO.ioc
├── STM32L496ZGTX_FLASH.ld
├── .project
├── .cproject
└── README.md
```

---

## 4. Configuration STM32CubeIDE

### 4.1 Ouvrir le projet

1. Ouvrir **STM32CubeIDE**.
2. Aller dans :

```text
File > Open Projects from File System
```

3. Sélectionner le dossier du projet :

```text
KEM_768_PQM4_DEMO/
```

4. Importer le projet.

---

### 4.2 Vérifier les périphériques

Dans CubeMX ou dans le fichier `.ioc`, vérifier que les périphériques suivants sont activés :

| Périphérique | Utilisation |
|---|---|
| `LPUART1` | Communication UART avec le PC |
| `I2C1` | Communication avec le BMP280 |
| `RNG` | Génération d’aléa pour ML-KEM |
| `GPIO` | Configuration carte / alimentation GPIOG |

Configuration UART attendue :

```text
Baudrate : 115200
Data bits : 8
Parity : None
Stop bits : 1
Flow control : None
```

---

### 4.3 Vérifier les include paths

Dans :

```text
Project > Properties > C/C++ Build > Settings
```

Vérifier que les dossiers suivants sont inclus côté compilateur C :

```text
Core/Inc
PQC/common
PQC/m4fspeed
PQC/ascon/asconaead128-ref
Drivers/CMSIS/Include
Drivers/CMSIS/Device/ST/STM32L4xx/Include
Drivers/STM32L4xx_HAL_Driver/Inc
Drivers/STM32L4xx_HAL_Driver/Inc/Legacy
```

Vérifier aussi que les include paths assembleur contiennent au minimum :

```text
PQC/common
PQC/m4fspeed
```

---

### 4.4 Vérifier les fichiers compilés

Lors du build, la console doit montrer la compilation ou l’assemblage de fichiers comme :

```text
Core/Src/main.c
Core/Src/pqm4.c
Core/Src/ascon.c
Core/Src/uart_connection.c
Core/Src/temperature_sensor.c
PQC/common/fips202.c
PQC/common/keccakf1600.S
PQC/m4fspeed/kem.c
PQC/m4fspeed/indcpa.c
PQC/m4fspeed/poly.c
PQC/m4fspeed/polyvec.c
PQC/ascon/asconaead128-ref/aead.c
```

Si `aead.c` n’est pas compilé, les fonctions ASCON ne seront pas trouvées au link.

---

## 5. Compiler et flasher la carte

Dans STM32CubeIDE :

1. Faire :

```text
Project > Clean
```

2. Puis :

```text
Project > Build Project
```

3. Brancher la carte STM32 sur le port **ST-LINK**.
4. Flasher avec :

```text
Run
```

ou :

```text
Debug
```

---

## 6. Vérifier le démarrage avec PuTTY

Avant d’utiliser Python, il est possible de vérifier rapidement que la carte démarre.

1. Ouvrir PuTTY.
2. Sélectionner le port COM de la carte, par exemple :

```text
COM5
```

3. Configurer :

```text
Speed : 115200
Data bits : 8
Stop bits : 1
Parity : None
Flow control : None
```

4. Appuyer sur RESET sur la carte.

La carte doit afficher :

```text
=== Demarrage BMP280 ===
BMP280 detecte
=== Demarrage session ML-KEM-768 + ASCON-AEAD128 ===
La carte attend une public key ML-KEM envoyee par le PC.
Format attendu : PK|<hex public key>
La private key reste cote PC et n'est jamais envoyee a la carte.

HELLO|STM32|MLKEM768|ASCONAEAD128
WAIT_PK|bytes=1184|hex_chars=2368
```

À ce stade, la carte attend que le PC envoie une clé publique ML-KEM.

Fermer PuTTY avant de lancer le script Python, car le port COM ne peut pas être utilisé par deux logiciels en même temps.

---

## 7. Environnement Python côté PC

Le script Python se trouve dans le dossier :

```text
python/
```

Il sert à :

1. ouvrir le port série ;
2. attendre que la STM32 soit prête ;
3. générer la paire de clés ML-KEM-768 ;
4. envoyer la clé publique à la STM32 ;
5. recevoir le ciphertext ML-KEM ;
6. décapsuler avec la clé privée côté PC ;
7. dériver la clé ASCON ;
8. recevoir les températures chiffrées ;
9. vérifier le tag ASCON ;
10. déchiffrer et afficher les températures.

---

## 8. Créer l’environnement virtuel Python

Se placer dans le dossier `python/` :

```bash
cd python
```

Créer un environnement virtuel :

```bash
python -m venv .venv
```

Activer l’environnement virtuel sous Windows PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
```

Si PowerShell bloque l’activation :

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

Sous CMD Windows :

```bat
.\.venv\Scripts\activate.bat
```

Sous Linux/macOS :

```bash
source .venv/bin/activate
```

Mettre `pip` à jour :

```bash
python -m pip install --upgrade pip
```

Installer les dépendances :

```bash
pip install -r requirements.txt
```

---

## 9. Fichier `requirements.txt`

Le fichier `python/requirements.txt` doit contenir :

```text
pyserial
pqcrypto
```

Le fichier `ascon.py` doit être présent dans le même dossier que le script Python :

```text
python/
├── pc_mlkem_ascon_uart.py
├── ascon.py
└── requirements.txt
```

---

## 10. Lancer la démo Python

Fermer PuTTY.

Lancer le script :

```bash
python pc_mlkem_ascon_uart.py --port COM5
```

Si le port COM est différent, adapter :

```bash
python pc_mlkem_ascon_uart.py --port COM7
```

Pour afficher la clé ASCON dérivée côté PC en mode debug :

```bash
python pc_mlkem_ascon_uart.py --port COM5 --show-key
```

Attention : `--show-key` ne doit être utilisé que pour du debug. Ne pas publier de logs contenant la clé ASCON.

---

## 11. Résultat attendu côté Python

Le script doit afficher quelque chose comme :

```text
=== PC Demo ML-KEM-768 + ASCON-AEAD128 ===
[PC] Port: COM5
[PC] Baud: 115200
[PC] Génération keypair ML-KEM-768...
[PC] public_key = 1184 octets
[PC] secret_key = 2400 octets
[PC] Port série ouvert.
[PC] Attente de la STM32...
[STM32] PONG
[PC] PONG reçu : la carte est bien en attente UART.
[PC] On envoie la public key.
[PC] Envoi public key : 1184 octets / 2368 caractères HEX
[PC] Attente du ciphertext ML-KEM depuis la STM32...
[STM32] PK_OK|bytes=1184
[STM32] MLKEM|ENCAPS_START
[STM32] MLKEM|ENCAPS_OK
[STM32] ASCON|KEY_DERIVED|sid=00332B95
[STM32] CT|2176|...
[PC] CT ML-KEM reçu : 1088 octets
[STM32] SESSION_OK|sid=00332B95
[PC] Décapsulation ML-KEM avec la private key côté PC...
[PC] shared_secret obtenu : 32 octets
[PC] ASCON session_id dérivé = 00332B95
[PC] nonce_prefix dérivé = ...
[PC] Attente des températures chiffrées...

[DATA] seq=1 | temp_dec=27.00 °C | clear_STM32=27.00 °C | integrity=OK | compare=OK
[DATA] seq=2 | temp_dec=27.00 °C | clear_STM32=27.00 °C | integrity=OK | compare=OK
```

La ligne importante est :

```text
integrity=OK | compare=OK
```

Cela signifie que :

- le PC a obtenu le bon secret partagé ML-KEM ;
- le PC a dérivé la même clé ASCON que la STM32 ;
- le tag ASCON est valide ;
- la température déchiffrée est identique à la température envoyée en clair en mode démonstration.

---

## 12. Mode DEMO et mode réel

Actuellement, la STM32 peut envoyer une trame de démonstration :

```text
DEMO|seq=1|sid=...|clear=2700|nonce=...|cipher=...|tag=...
```

Le champ `clear=2700` sert uniquement à vérifier que :

```text
température claire STM32 = température déchiffrée PC
```

Pour passer en mode réel, il faut ne plus envoyer la température claire.

Dans `uart_connection.c`, remplacer :

```c
ASCON_App_PrintFrame(&frame, 1);
```

par :

```c
ASCON_App_PrintFrame(&frame, 0);
```

La trame deviendra :

```text
DATA|seq=1|sid=...|nonce=...|cipher=...|tag=...
```

---

## 13. Données échangées entre PC et STM32

### 13.1 Démarrage

```text
STM32 → PC : HELLO|STM32|MLKEM768|ASCONAEAD128
STM32 → PC : WAIT_PK|bytes=1184|hex_chars=2368
```

Ces messages sont en clair et non secrets.

### 13.2 Envoi de la clé publique

```text
PC → STM32 : PK|2368|<public_key_hex>
```

La clé publique ML-KEM fait :

```text
1184 octets = 2368 caractères hexadécimaux
```

Elle n’est pas secrète.

### 13.3 Encapsulation côté STM32

La STM32 fait localement :

```text
(ct_kem, shared_secret) = ML-KEM.Encaps(public_key)
```

Le `shared_secret` n’est jamais envoyé.

### 13.4 Envoi du ciphertext ML-KEM

```text
STM32 → PC : CT|2176|<ciphertext_mlkem_hex>
```

Le ciphertext ML-KEM fait :

```text
1088 octets = 2176 caractères hexadécimaux
```

### 13.5 Décapsulation côté PC

Le PC fait localement :

```text
shared_secret = ML-KEM.Decaps(private_key, ct_kem)
```

La clé privée ML-KEM reste uniquement côté PC.

### 13.6 Dérivation de clé ASCON

Les deux côtés font :

```text
derived = SHAKE256("PFE_MLKEM768_ASCON_AEAD128_V1" || shared_secret)

key_ascon    = derived[0..15]
nonce_prefix = derived[16..27]
session_id   = derived[28..31]
```

### 13.7 Envoi des températures

En mode démo :

```text
STM32 → PC : DEMO|seq=...|sid=...|clear=...|nonce=...|cipher=...|tag=...
```

En mode réel :

```text
STM32 → PC : DATA|seq=...|sid=...|nonce=...|cipher=...|tag=...
```

---

## 14. Rôle des principaux champs

| Champ | Rôle |
|---|---|
| `public_key` | clé publique ML-KEM envoyée du PC vers la STM32 |
| `private_key` | clé privée ML-KEM conservée uniquement côté PC |
| `ct_kem` | ciphertext ML-KEM renvoyé par la STM32 |
| `shared_secret` | secret partagé obtenu des deux côtés, jamais envoyé |
| `key_ascon` | clé symétrique dérivée avec SHAKE256, jamais envoyée |
| `nonce_prefix` | préfixe de nonce dérivé pour la session |
| `session_id` | identifiant public de session |
| `seq` | compteur de message |
| `nonce` | valeur unique utilisée par ASCON |
| `cipher` | température chiffrée |
| `tag` | preuve d’intégrité/authenticité ASCON |

---

## 15. Dépannage

### Le script Python ne reçoit rien

Vérifier :

- PuTTY est fermé ;
- le bon port COM est utilisé ;
- la carte est branchée sur le port ST-LINK ;
- le baudrate est bien `115200` ;
- appuyer sur RESET après avoir lancé le script.

---

### Erreur `PermissionError` ou port occupé

Le port COM est probablement utilisé par PuTTY ou un autre terminal.

Fermer PuTTY puis relancer :

```bash
python pc_mlkem_ascon_uart.py --port COM5
```

---

### Erreur `TAG FAIL`

Cela signifie que le tag ASCON n’est pas valide.

Causes possibles :

- la clé ASCON dérivée côté PC n’est pas la même que côté STM32 ;
- le label SHAKE256 est différent entre PC et STM32 ;
- les associated data sont différentes ;
- le nonce reçu est incorrect ;
- la version Python d’ASCON n’est pas compatible avec la version C ;
- une donnée a été modifiée ou mal transmise.

À vérifier :

```text
session_id côté STM32 == session_id côté PC
nonce_prefix côté STM32 == nonce_prefix côté PC
AD_LABEL identique : "PFE_TEMP_V1"
KDF_LABEL identique : "PFE_MLKEM768_ASCON_AEAD128_V1"
```

---

### Erreur `ModuleNotFoundError`

Vérifier que l’environnement virtuel est activé :

```powershell
.\.venv\Scripts\Activate.ps1
```

Puis réinstaller :

```bash
pip install -r requirements.txt
```

---

### Erreur ML-KEM côté Python

Vérifier que `pqcrypto` est installé :

```bash
pip show pqcrypto
```

Si besoin :

```bash
pip install pqcrypto
```

---

### La carte reste bloquée sur `WAIT_PK`

Cela signifie que la STM32 attend la public key.

Vérifier que :

- le script Python est lancé ;
- PuTTY est fermé ;
- le bon port COM est utilisé ;
- le script envoie bien une ligne `PK|...`.