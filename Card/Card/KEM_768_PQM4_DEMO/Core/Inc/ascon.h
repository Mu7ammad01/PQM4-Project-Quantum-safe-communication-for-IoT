#ifndef ASCON_APP_H
#define ASCON_APP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define ASCON_APP_KEY_SIZE        16U
#define ASCON_APP_NONCE_SIZE      16U
#define ASCON_APP_TAG_SIZE        16U
#define ASCON_APP_TEMP_SIZE       4U
#define ASCON_APP_CIPHERTEXT_SIZE ASCON_APP_TEMP_SIZE

typedef struct
{
    uint32_t seq;
    uint32_t session_id;
    int32_t temp_centi_clear;

    uint8_t nonce[ASCON_APP_NONCE_SIZE];
    uint8_t ciphertext[ASCON_APP_CIPHERTEXT_SIZE];
    uint8_t tag[ASCON_APP_TAG_SIZE];

} ASCON_App_TempFrame;

/*
 * Mode test rapide :
 * Initialise ASCON avec une clé fixe.
 * À utiliser uniquement pour vérifier que ASCON compile et fonctionne.
 */
void ASCON_App_InitFixedTestKey(void);

/*
 * Mode final :
 * Dérive key_ascon à partir du shared_secret ML-KEM avec SHAKE256.
 * ss_len doit normalement valoir 32 pour ML-KEM.
 */
int ASCON_App_InitFromSharedSecret(const uint8_t *ss, size_t ss_len);

/*
 * Test local STM32 :
 * Chiffre puis déchiffre une température fixe.
 * Retourne 0 si OK.
 */
int ASCON_App_SelfTest(void);

/*
 * Chiffre une température encodée en centi-degrés.
 * Exemple : 24.60 °C => temp_centi = 2460.
 */
int ASCON_App_EncryptTemperature(int32_t temp_centi, ASCON_App_TempFrame *frame);

/*
 * Déchiffre une trame ASCON.
 * Utile pour le self-test côté STM32.
 * Dans la démo finale, le déchiffrement sera plutôt fait côté PC.
 */
int ASCON_App_DecryptTemperature(const ASCON_App_TempFrame *frame, int32_t *temp_centi);

/*
 * Affiche une trame prête à être parsée côté PC.
 * show_clear = 1 : mode démo, affiche aussi la température claire.
 * show_clear = 0 : mode réel, n’affiche que la partie chiffrée.
 */
void ASCON_App_PrintFrame(const ASCON_App_TempFrame *frame, int show_clear);

uint32_t ASCON_App_GetSessionId(void);
void ASCON_App_ResetSequence(void);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_APP_H */
