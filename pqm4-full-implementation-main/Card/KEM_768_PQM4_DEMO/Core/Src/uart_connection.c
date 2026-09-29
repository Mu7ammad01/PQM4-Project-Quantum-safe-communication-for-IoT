#include "uart_connection.h"

#include "main.h"
#include "pqm4.h"
#include "ascon.h"
#include "temperature_sensor.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern UART_HandleTypeDef hlpuart1;

static char uart_rx_line[UARTCONNECTION_RX_LINE_SIZE];

static uint8_t mlkem_public_key[APP_MLKEM_PUBLICKEYBYTES];
static uint8_t mlkem_ciphertext[APP_MLKEM_CIPHERTEXTBYTES];
static uint8_t mlkem_shared_secret[APP_MLKEM_SHAREDSECRETBYTES];

static uint8_t session_ready = 0;

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }

    return -1;
}

static int uart_readline_blocking(char *buf, size_t max_len)
{
    size_t pos = 0;
    uint8_t ch = 0;

    if (buf == NULL || max_len < 2U)
    {
        return -1;
    }

    memset(buf, 0, max_len);

    while (1)
    {
        if (HAL_UART_Receive(&hlpuart1, &ch, 1, HAL_MAX_DELAY) != HAL_OK)
        {
            return -2;
        }

        if (ch == '\r')
        {
            continue;
        }

        if (ch == '\n')
        {
            buf[pos] = '\0';
            return (int)pos;
        }

        if (pos >= (max_len - 1U))
        {
            buf[max_len - 1U] = '\0';
            return -3;
        }

        buf[pos++] = (char)ch;
    }
}

static int hex_to_bytes_exact(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    size_t hex_len;

    if (hex == NULL || out == NULL)
    {
        return -1;
    }

    hex_len = strlen(hex);

    if (hex_len != (out_len * 2U))
    {
        return -2;
    }

    for (i = 0; i < out_len; i++)
    {
        int hi = hex_nibble(hex[2U * i]);
        int lo = hex_nibble(hex[2U * i + 1U]);

        if (hi < 0 || lo < 0)
        {
            return -3;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static void print_hex_bytes(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
}

static int parse_public_key_line(const char *line)
{
    const char *hex = NULL;
    const char *second_sep = NULL;

    if (line == NULL)
    {
        return -1;
    }

    /*
     * Formats acceptés :
     *
     * 1) PK|<public_key_hex>
     * 2) PK|2368|<public_key_hex>
     *
     * Pour ML-KEM-768 :
     * public key = 1184 octets = 2368 caractères HEX.
     */

    if (strncmp(line, "PK|", 3) != 0)
    {
        return -2;
    }

    hex = line + 3;

    /*
     * Si le PC envoie PK|2368|HEX,
     * on saute le champ longueur.
     */
    second_sep = strchr(hex, '|');
    if (second_sep != NULL)
    {
        hex = second_sep + 1;
    }

    return hex_to_bytes_exact(hex, mlkem_public_key, APP_MLKEM_PUBLICKEYBYTES);
}

static void send_mlkem_ciphertext(void)
{
    /*
     * Ciphertext ML-KEM-768 :
     * 1088 octets = 2176 caractères HEX.
     */
    printf("CT|%lu|", (unsigned long)(APP_MLKEM_CIPHERTEXTBYTES * 2U));
    print_hex_bytes(mlkem_ciphertext, APP_MLKEM_CIPHERTEXTBYTES);
    printf("\r\n");
}

uint8_t UARTConnection_IsSessionReady(void)
{
    return session_ready;
}

int UARTConnection_StartSession(void)
{
    int ret;

    session_ready = 0;

    printf("\r\nHELLO|STM32|MLKEM768|ASCONAEAD128\r\n");
    printf("WAIT_PK|bytes=%lu|hex_chars=%lu\r\n",
           (unsigned long)APP_MLKEM_PUBLICKEYBYTES,
           (unsigned long)(APP_MLKEM_PUBLICKEYBYTES * 2U));

    while (1)
    {
        int rx_len = uart_readline_blocking(uart_rx_line, sizeof(uart_rx_line));

        if (rx_len < 0)
        {
            printf("ERR|UART_RX|code=%d\r\n", rx_len);
            continue;
        }

        if (strcmp(uart_rx_line, "PING") == 0)
        {
            printf("PONG\r\n");
            continue;
        }

        ret = parse_public_key_line(uart_rx_line);

        if (ret == 0)
        {
            printf("PK_OK|bytes=%lu\r\n",
                   (unsigned long)APP_MLKEM_PUBLICKEYBYTES);
            break;
        }

        printf("ERR|PK_PARSE|code=%d|rx_len=%d\r\n", ret, rx_len);
        printf("WAIT_PK|bytes=%lu|hex_chars=%lu\r\n",
               (unsigned long)APP_MLKEM_PUBLICKEYBYTES,
               (unsigned long)(APP_MLKEM_PUBLICKEYBYTES * 2U));
    }

    printf("MLKEM|ENCAPS_START\r\n");

    ret = PQM4_MLKEM_EncapsulateFromPublicKey(
        mlkem_public_key,
        mlkem_ciphertext,
        mlkem_shared_secret
    );

    if (ret != 0)
    {
        printf("ERR|MLKEM_ENCAPS|code=%d\r\n", ret);
        return -10;
    }

    printf("MLKEM|ENCAPS_OK\r\n");

    /*
     * Remplace la clé fixe ASCON par une clé dérivée du shared_secret ML-KEM.
     */
    ret = ASCON_App_InitFromSharedSecret(
        mlkem_shared_secret,
        APP_MLKEM_SHAREDSECRETBYTES
    );

    if (ret != 0)
    {
        printf("ERR|ASCON_DERIVE|code=%d\r\n", ret);
        return -20;
    }

    printf("ASCON|KEY_DERIVED|sid=%08lX\r\n",
           (unsigned long)ASCON_App_GetSessionId());

    send_mlkem_ciphertext();

    printf("SESSION_OK|sid=%08lX\r\n",
           (unsigned long)ASCON_App_GetSessionId());

    session_ready = 1;

    return 0;
}

void UARTConnection_StreamTemperatureOnce(void)
{
    int32_t temp_centi = 0;
    ASCON_App_TempFrame frame;

    if (!session_ready)
    {
        printf("ERR|NO_SESSION\r\n");
        return;
    }

    if (bmp280_read_temperature_centi_deg(&temp_centi) != HAL_OK)
    {
        printf("ERR|TEMP_READ\r\n");
        return;
    }

    if (ASCON_App_EncryptTemperature(temp_centi, &frame) != 0)
    {
        printf("ERR|ASCON_ENCRYPT\r\n");
        return;
    }

    /*
     * Mode démo :
     * 1 = affiche clear=xxxx en plus du cipher/tag.
     *
     * Mode réel :
     * passer à 0 pour ne pas envoyer la température claire.
     */
    ASCON_App_PrintFrame(&frame, 1);
}
