#include "pqm4.h"
#include "putty.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../../PQC/m4fspeed/api.h"

#define STACK_BENCH_SIZE   65536U   /* ajuster si besoin */

extern RNG_HandleTypeDef hrng;

typedef int (*bench_fun_t)(void);

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];

static uint64_t cycles_keypair = 0;
static uint64_t cycles_encaps  = 0;
static uint64_t cycles_decaps  = 0;

static size_t stack_keypair = 0;
static size_t stack_encaps  = 0;
static size_t stack_decaps  = 0;

static uint8_t bench_stack[STACK_BENCH_SIZE] __attribute__((aligned(8)));

static volatile uint32_t bench_systick_overflows = 0;
static volatile uint8_t  bench_systick_running = 0;

static uint32_t bench_stack_canary_word = 0;

void bench_systick_overflow_hook(void)
{
    if (bench_systick_running)
    {
        bench_systick_overflows++;
    }
}

static void bench_systick_start(void)
{
    HAL_SuspendTick();

    bench_systick_overflows = 0;
    bench_systick_running = 1;

    SysTick->LOAD = 0xFFFFFFu;  /* 24 bits max */
    SysTick->VAL  = 0;
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk
                  | SysTick_CTRL_TICKINT_Msk
                  | SysTick_CTRL_ENABLE_Msk;
}

static uint64_t bench_systick_stop(void)
{
    uint32_t val = SysTick->VAL;
    uint32_t overflows = bench_systick_overflows;
    uint64_t total_cycles;

    bench_systick_running = 0;
    SysTick->CTRL = 0;

    total_cycles = ((uint64_t)overflows << 24)
                 + (uint64_t)(0xFFFFFFu - val);

    HAL_InitTick(TICK_INT_PRIORITY);
    HAL_ResumeTick();

    return total_cycles;
}

static void stack_canary_fill_random(void)
{
    size_t i;
    uint8_t *p = (uint8_t *)&bench_stack_canary_word;

    if (HAL_RNG_GenerateRandomNumber(&hrng, &bench_stack_canary_word) != HAL_OK)
    {
        bench_stack_canary_word = 0xA5A5A5A5u;
    }

    for (i = 0; i < sizeof(bench_stack); i++)
    {
        bench_stack[i] = p[i & 3u];
    }
}

static uint8_t *bench_get_stack_top(void)
{
    uintptr_t top = (uintptr_t)(bench_stack + sizeof(bench_stack));

    top &= ~((uintptr_t)0x7u);
    top -= 16u;

    return (uint8_t *)top;
}

static size_t stack_measure_used(void)
{
    size_t i;
    uint8_t *p = (uint8_t *)&bench_stack_canary_word;

    for (i = 0; i < sizeof(bench_stack); i++)
    {
        if (bench_stack[i] != p[i & 3u])
        {
            break;
        }
    }

    return sizeof(bench_stack) - i;
}

__attribute__((naked)) static int call_on_stack(bench_fun_t fn, uint8_t *stack_top)
{
    __asm volatile(
        "mov r2, sp            \n"
        "mov sp, r1            \n"
        "push {r2, lr}         \n"
        "blx r0                \n"
        "pop {r2, lr}          \n"
        "mov sp, r2            \n"
        "bx lr                 \n"
    );
}

static int measure_speed_systick(bench_fun_t fn, uint64_t *cycles)
{
    int ret;

    bench_systick_start();
    ret = fn();
    *cycles = bench_systick_stop();

    return ret;
}

static int measure_stack_canary(bench_fun_t fn, size_t *stack_used)
{
    int ret;

    stack_canary_fill_random();

    __disable_irq();
    ret = call_on_stack(fn, bench_get_stack_top());
    __enable_irq();

    *stack_used = stack_measure_used();

    return ret;
}

static __attribute__((noinline)) int do_keypair(void)
{
    return crypto_kem_keypair(pk, sk);
}

static __attribute__((noinline)) int do_encaps(void)
{
    return crypto_kem_enc(ct, ss_enc, pk);
}

static __attribute__((noinline)) int do_decaps(void)
{
    return crypto_kem_dec(ss_dec, ct, sk);
}

int PQM4_MLKEM_BenchArticleLike(void)
{
    printf("\r\n==== Article-like BENCH ML-KEM-768 m4fspeed / STM32 ====\r\n");
    printf("alg=%s\r\n", CRYPTO_ALGNAME);

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss_enc, 0, sizeof(ss_enc));
    memset(ss_dec, 0, sizeof(ss_dec));

    /* KEYPAIR */
    if (measure_speed_systick(do_keypair, &cycles_keypair) != 0)
    {
        printf("ERREUR speed keypair\r\n");
        return -1;
    }
    if (measure_stack_canary(do_keypair, &stack_keypair) != 0)
    {
        printf("ERREUR stack keypair\r\n");
        return -2;
    }

    /* ENCAPS */
    if (measure_speed_systick(do_encaps, &cycles_encaps) != 0)
    {
        printf("ERREUR speed encaps\r\n");
        return -3;
    }
    if (measure_stack_canary(do_encaps, &stack_encaps) != 0)
    {
        printf("ERREUR stack encaps\r\n");
        return -4;
    }

    /* DECAPS */
    if (measure_speed_systick(do_decaps, &cycles_decaps) != 0)
    {
        printf("ERREUR speed decaps\r\n");
        return -5;
    }
    if (measure_stack_canary(do_decaps, &stack_decaps) != 0)
    {
        printf("ERREUR stack decaps\r\n");
        return -6;
    }

    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) != 0)
    {
        printf("ERREUR: secret partage different\r\n");
        return -7;
    }

    printf("keypair : %lu cycles, stack = %u octets\r\n",
           (unsigned long)cycles_keypair, (unsigned)stack_keypair);

    printf("encaps  : %lu cycles, stack = %u octets\r\n",
           (unsigned long)cycles_encaps, (unsigned)stack_encaps);

    printf("decaps  : %lu cycles, stack = %u octets\r\n",
           (unsigned long)cycles_decaps, (unsigned)stack_decaps);

    return 0;
}

int PQM4_MLKEM_SelfTest(void)
{
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss_enc, 0, sizeof(ss_enc));
    memset(ss_dec, 0, sizeof(ss_dec));

    printf("\r\n==== PQM4 m4fspeed ML-KEM-768 / STM32 ====\r\n");
    printf("alg=%s\r\n", CRYPTO_ALGNAME);
    printf("pk=%d, sk=%d, ct=%d, ss=%d\r\n",
           CRYPTO_PUBLICKEYBYTES,
           CRYPTO_SECRETKEYBYTES,
           CRYPTO_CIPHERTEXTBYTES,
           CRYPTO_BYTES);

    printf("[1] keypair...\r\n");
    if (crypto_kem_keypair(pk, sk) != 0)
    {
        printf("ERREUR: keypair\r\n");
        return -1;
    }
    printf("OK\r\n");

    printf("[2] encaps...\r\n");
    if (crypto_kem_enc(ct, ss_enc, pk) != 0)
    {
        printf("ERREUR: encaps\r\n");
        return -2;
    }
    printf("OK\r\n");

    printf("[3] decaps...\r\n");
    if (crypto_kem_dec(ss_dec, ct, sk) != 0)
    {
        printf("ERREUR: decaps\r\n");
        return -3;
    }
    printf("OK\r\n");

    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) != 0)
    {
        printf("[4] shared secret match: NON\r\n");
        Putty_PrintHex("ss_enc = ", ss_enc, CRYPTO_BYTES);
        Putty_PrintHex("ss_dec = ", ss_dec, CRYPTO_BYTES);
        return -4;
    }

    printf("[4] shared secret match: OUI\r\n");
    Putty_PrintHex("pk[0..15] = ", pk, 16);
    Putty_PrintHex("ct[0..15] = ", ct, 16);
    Putty_PrintHex("ss = ", ss_enc, CRYPTO_BYTES);

    return 0;
}

int PQM4_MLKEM_EncapsulateFromPublicKey(const uint8_t *public_key,
                                        uint8_t *ciphertext,
                                        uint8_t *shared_secret)
{
    if (public_key == NULL || ciphertext == NULL || shared_secret == NULL)
    {
        return -1;
    }

    return crypto_kem_enc(ciphertext, shared_secret, public_key);
}
