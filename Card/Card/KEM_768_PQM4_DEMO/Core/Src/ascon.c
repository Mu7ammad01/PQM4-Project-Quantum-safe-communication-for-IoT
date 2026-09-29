#include "ascon.h"

#include <stdio.h>
#include <string.h>

#include "fips202.h"

/*
 * IMPORTANT :
 * On n'inclut PAS api.h ici pour éviter le conflit avec PQM4/m4fspeed/api.h.
 *
 * L'implémentation ASCON officielle expose normalement ces deux fonctions
 * via l'interface eBACS / NIST LWC :
 *
 * crypto_aead_encrypt()
 * crypto_aead_decrypt()
 *
 * Le fichier PQC/ascon/asconaead128_ref/aead.c doit être compilé dans le projet.
 */
extern int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
);

extern int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
);

#define ASCON_APP_AD_LABEL        "PFE_TEMP_V1"
#define ASCON_APP_AD_LABEL_SIZE   11U
#define ASCON_APP_AD_MAX_SIZE     32U

static uint8_t g_key_ascon[ASCON_APP_KEY_SIZE];
static uint8_t g_nonce_prefix[12U];
static uint32_t g_seq = 0;
static uint32_t g_session_id = 0;
static uint8_t g_ready = 0;

static void secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (len--)
    {
        *p++ = 0;
    }
}

static void write_u32_be(uint8_t *out, uint32_t x)
{
    out[0] = (uint8_t)((x >> 24) & 0xFFU);
    out[1] = (uint8_t)((x >> 16) & 0xFFU);
    out[2] = (uint8_t)((x >> 8)  & 0xFFU);
    out[3] = (uint8_t)(x & 0xFFU);
}

static uint32_t read_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24)
         | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8)
         | ((uint32_t)in[3]);
}

static void build_nonce(uint32_t seq, uint8_t nonce[ASCON_APP_NONCE_SIZE])
{
    /*
     * Nonce ASCON = 16 octets.
     *
     * Ici :
     * - 12 octets de préfixe de session
     * - 4 octets de compteur seq
     *
     * Règle importante :
     * ne jamais réutiliser le même nonce avec la même clé ASCON.
     */
    memcpy(nonce, g_nonce_prefix, sizeof(g_nonce_prefix));
    write_u32_be(&nonce[12], seq);
}

static size_t build_associated_data(uint32_t seq,
                                    uint32_t session_id,
                                    uint8_t ad[ASCON_APP_AD_MAX_SIZE])
{
    size_t pos = 0;

    memcpy(&ad[pos], ASCON_APP_AD_LABEL, ASCON_APP_AD_LABEL_SIZE);
    pos += ASCON_APP_AD_LABEL_SIZE;

    write_u32_be(&ad[pos], session_id);
    pos += 4U;

    write_u32_be(&ad[pos], seq);
    pos += 4U;

    return pos;
}

static void print_hex_no_newline(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
}

void ASCON_App_InitFixedTestKey(void)
{
    /*
     * Clé fixe uniquement pour intégrer et tester ASCON rapidement.
     * À ne pas utiliser comme solution finale.
     */
    static const uint8_t test_key[ASCON_APP_KEY_SIZE] =
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    static const uint8_t test_nonce_prefix[12U] =
    {
        0xA5, 0xC0, 0x4A, 0x10,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88
    };

    memcpy(g_key_ascon, test_key, sizeof(g_key_ascon));
    memcpy(g_nonce_prefix, test_nonce_prefix, sizeof(g_nonce_prefix));

    g_seq = 0;
    g_session_id = 0x4153434FU; /* ASCII approximatif : ASCO */
    g_ready = 1;
}

int ASCON_App_InitFromSharedSecret(const uint8_t *ss, size_t ss_len)
{
    /*
     * Dérivation finale :
     *
     * shared_secret ML-KEM
     *        ↓
     * SHAKE256(label || ss)
     *        ↓
     * key_ascon     : 16 octets
     * nonce_prefix  : 12 octets
     * session_id    : 4 octets
     */
    static const uint8_t label[] = "PFE_MLKEM768_ASCON_AEAD128_V1";

    uint8_t input[96];
    uint8_t derived[32];
    size_t label_len = sizeof(label) - 1U;
    size_t input_len;

    if (ss == NULL || ss_len == 0U)
    {
        return -1;
    }

    if ((label_len + ss_len) > sizeof(input))
    {
        return -2;
    }

    memcpy(input, label, label_len);
    memcpy(input + label_len, ss, ss_len);
    input_len = label_len + ss_len;

    shake256(derived, sizeof(derived), input, input_len);

    memcpy(g_key_ascon, derived, 16U);
    memcpy(g_nonce_prefix, derived + 16U, 12U);
    g_session_id = read_u32_be(derived + 28U);

    g_seq = 0;
    g_ready = 1;

    secure_wipe(input, sizeof(input));
    secure_wipe(derived, sizeof(derived));

    return 0;
}

int ASCON_App_EncryptTemperature(int32_t temp_centi, ASCON_App_TempFrame *frame)
{
    uint8_t plaintext[ASCON_APP_TEMP_SIZE];
    uint8_t output[ASCON_APP_CIPHERTEXT_SIZE + ASCON_APP_TAG_SIZE];
    uint8_t ad[ASCON_APP_AD_MAX_SIZE];

    unsigned long long output_len = 0;
    size_t ad_len;
    int ret;
    uint32_t seq;

    if (!g_ready)
    {
        return -1;
    }

    if (frame == NULL)
    {
        return -2;
    }

    memset(frame, 0, sizeof(*frame));

    seq = ++g_seq;

    frame->seq = seq;
    frame->session_id = g_session_id;
    frame->temp_centi_clear = temp_centi;

    build_nonce(seq, frame->nonce);

    /*
     * On encode temp_centi sur 4 octets.
     * Exemple : 24.60 °C -> 2460 -> 00 00 09 9C.
     */
    write_u32_be(plaintext, (uint32_t)temp_centi);

    /*
     * Associated Data :
     * Authentifié par ASCON, mais pas chiffré.
     * Ici on authentifie le type de message, la session et le seq.
     */
    ad_len = build_associated_data(seq, g_session_id, ad);

    ret = crypto_aead_encrypt(
        output,
        &output_len,
        plaintext,
        ASCON_APP_TEMP_SIZE,
        ad,
        (unsigned long long)ad_len,
        NULL,
        frame->nonce,
        g_key_ascon
    );

    if (ret != 0)
    {
        secure_wipe(plaintext, sizeof(plaintext));
        secure_wipe(output, sizeof(output));
        secure_wipe(ad, sizeof(ad));
        return -3;
    }

    if (output_len != (ASCON_APP_CIPHERTEXT_SIZE + ASCON_APP_TAG_SIZE))
    {
        secure_wipe(plaintext, sizeof(plaintext));
        secure_wipe(output, sizeof(output));
        secure_wipe(ad, sizeof(ad));
        return -4;
    }

    memcpy(frame->ciphertext, output, ASCON_APP_CIPHERTEXT_SIZE);
    memcpy(frame->tag, output + ASCON_APP_CIPHERTEXT_SIZE, ASCON_APP_TAG_SIZE);

    secure_wipe(plaintext, sizeof(plaintext));
    secure_wipe(output, sizeof(output));
    secure_wipe(ad, sizeof(ad));

    return 0;
}

int ASCON_App_DecryptTemperature(const ASCON_App_TempFrame *frame, int32_t *temp_centi)
{
    uint8_t input[ASCON_APP_CIPHERTEXT_SIZE + ASCON_APP_TAG_SIZE];
    uint8_t plaintext[ASCON_APP_TEMP_SIZE];
    uint8_t ad[ASCON_APP_AD_MAX_SIZE];

    unsigned long long plaintext_len = 0;
    size_t ad_len;
    int ret;

    if (!g_ready)
    {
        return -1;
    }

    if (frame == NULL || temp_centi == NULL)
    {
        return -2;
    }

    memcpy(input, frame->ciphertext, ASCON_APP_CIPHERTEXT_SIZE);
    memcpy(input + ASCON_APP_CIPHERTEXT_SIZE, frame->tag, ASCON_APP_TAG_SIZE);

    ad_len = build_associated_data(frame->seq, frame->session_id, ad);

    ret = crypto_aead_decrypt(
        plaintext,
        &plaintext_len,
        NULL,
        input,
        ASCON_APP_CIPHERTEXT_SIZE + ASCON_APP_TAG_SIZE,
        ad,
        (unsigned long long)ad_len,
        frame->nonce,
        g_key_ascon
    );

    if (ret != 0)
    {
        secure_wipe(input, sizeof(input));
        secure_wipe(plaintext, sizeof(plaintext));
        secure_wipe(ad, sizeof(ad));
        return -3; /* tag invalide */
    }

    if (plaintext_len != ASCON_APP_TEMP_SIZE)
    {
        secure_wipe(input, sizeof(input));
        secure_wipe(plaintext, sizeof(plaintext));
        secure_wipe(ad, sizeof(ad));
        return -4;
    }

    *temp_centi = (int32_t)read_u32_be(plaintext);

    secure_wipe(input, sizeof(input));
    secure_wipe(plaintext, sizeof(plaintext));
    secure_wipe(ad, sizeof(ad));

    return 0;
}

int ASCON_App_SelfTest(void)
{
    ASCON_App_TempFrame frame;
    int32_t decrypted_temp = 0;
    uint32_t saved_seq = g_seq;
    int ret;

    if (!g_ready)
    {
        return -1;
    }

    ret = ASCON_App_EncryptTemperature(2460, &frame);
    if (ret != 0)
    {
        g_seq = saved_seq;
        return -2;
    }

    ret = ASCON_App_DecryptTemperature(&frame, &decrypted_temp);
    if (ret != 0)
    {
        g_seq = saved_seq;
        return -3;
    }

    g_seq = saved_seq;

    if (decrypted_temp != 2460)
    {
        return -4;
    }

    return 0;
}

void ASCON_App_PrintFrame(const ASCON_App_TempFrame *frame, int show_clear)
{
    if (frame == NULL)
    {
        return;
    }

    if (show_clear)
    {
        printf("DEMO|seq=%lu|sid=%08lX|clear=%ld|nonce=",
               (unsigned long)frame->seq,
               (unsigned long)frame->session_id,
               (long)frame->temp_centi_clear);
    }
    else
    {
        printf("DATA|seq=%lu|sid=%08lX|nonce=",
               (unsigned long)frame->seq,
               (unsigned long)frame->session_id);
    }

    print_hex_no_newline(frame->nonce, ASCON_APP_NONCE_SIZE);

    printf("|cipher=");
    print_hex_no_newline(frame->ciphertext, ASCON_APP_CIPHERTEXT_SIZE);

    printf("|tag=");
    print_hex_no_newline(frame->tag, ASCON_APP_TAG_SIZE);

    printf("\r\n");
}

uint32_t ASCON_App_GetSessionId(void)
{
    return g_session_id;
}

void ASCON_App_ResetSequence(void)
{
    g_seq = 0;
}
