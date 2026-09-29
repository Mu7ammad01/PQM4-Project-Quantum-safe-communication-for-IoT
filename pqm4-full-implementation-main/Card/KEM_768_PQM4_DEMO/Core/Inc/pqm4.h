#ifndef PQM4_H
#define PQM4_H

#include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tailles ML-KEM-768.
 * Ces valeurs correspondent à PQM4 ML-KEM-768 :
 * pk = 1184, ct = 1088, ss = 32.
 */
#define APP_MLKEM_PUBLICKEYBYTES     1184U
#define APP_MLKEM_CIPHERTEXTBYTES    1088U
#define APP_MLKEM_SHAREDSECRETBYTES  32U

int PQM4_MLKEM_SelfTest(void);
int PQM4_MLKEM_BenchArticleLike(void);
void bench_systick_overflow_hook(void);
int PQM4_MLKEM_EncapsulateFromPublicKey(const uint8_t *public_key,
                                        uint8_t *ciphertext,
                                        uint8_t *shared_secret);
#ifdef __cplusplus
}
#endif

#endif /* PQM4_H */
