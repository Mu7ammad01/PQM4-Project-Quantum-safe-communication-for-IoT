#include "randombytes.h"
#include "main.h"

extern RNG_HandleTypeDef hrng;

void randombytes(uint8_t *out, size_t outlen)
{
    uint32_t rnd;
    size_t i = 0;

    while (i < outlen) {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK) {
            // En cas d'erreur RNG, on remplit avec 0 pour éviter un crash.
            // On pourra durcir cela ensuite.
            rnd = 0;
        }

        for (size_t j = 0; j < 4 && i < outlen; j++, i++) {
            out[i] = (uint8_t)((rnd >> (8U * j)) & 0xFF);
        }
    }
}
