#ifndef UARTCONNECTION_H
#define UARTCONNECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define UARTCONNECTION_RX_LINE_SIZE 3000U

/*
 * Lance la session :
 * 1. attend la public key ML-KEM du PC
 * 2. encapsule avec ML-KEM
 * 3. dérive la clé ASCON avec le shared_secret
 * 4. renvoie le ciphertext ML-KEM au PC
 */
int UARTConnection_StartSession(void);

/*
 * Lit une température, la chiffre avec ASCON,
 * puis l'envoie sur UART.
 */
void UARTConnection_StreamTemperatureOnce(void);

/*
 * Indique si une session ML-KEM + ASCON est prête.
 */
uint8_t UARTConnection_IsSessionReady(void);

#ifdef __cplusplus
}
#endif

#endif /* UARTCONNECTION_H */
