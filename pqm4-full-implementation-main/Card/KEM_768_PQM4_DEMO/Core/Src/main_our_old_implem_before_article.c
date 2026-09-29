/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "api.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef hlpuart1;

RNG_HandleTypeDef hrng;

/* USER CODE BEGIN PV */
#define BENCH_ITERS 100

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss_enc[CRYPTO_BYTES];
static uint8_t ss_dec[CRYPTO_BYTES];

#define BENCH_ITERS       100
#define STACK_BENCH_SIZE  24576U
#define STACK_PATTERN     0xA5u

static uint32_t cycles_keypair = 0;
static uint32_t cycles_encaps  = 0;
static uint32_t cycles_decaps  = 0;

static size_t stack_keypair = 0;
static size_t stack_encaps  = 0;
static size_t stack_decaps  = 0;

/* pile temporaire dédiée au test stack */
static uint8_t bench_stack[STACK_BENCH_SIZE] __attribute__((aligned(8)));


/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_LPUART1_UART_Init(void);
static void MX_RNG_Init(void);
/* USER CODE BEGIN PFP */
static void print_hex(const char *label, const uint8_t *buf, size_t len);
static void dwt_init(void);
static inline uint32_t dwt_get_cycles(void);
static int mlkem_self_test(void);
static void benchmark_mlkem(void);

static void dwt_reset(void);
static void stack_pattern_fill(void);
static uint8_t *bench_get_stack_top(void);
static size_t stack_measure_used(void);

static int mlkem_bench_stack_test(void);

static int do_keypair(void);
static int do_encaps(void);
static int do_decaps(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
int __io_putchar(int ch)
{
    HAL_UART_Transmit(&hlpuart1, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
    return ch;
}

#ifdef __GNUC__
int _write(int file, char *ptr, int len)
{
    (void)file;
    HAL_UART_Transmit(&hlpuart1, (uint8_t *)ptr, len, HAL_MAX_DELAY);
    return len;
}
#endif

static void dwt_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

static inline uint32_t dwt_get_cycles(void)
{
    return DWT->CYCCNT;
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\r\n");
}


typedef int (*bench_fun_t)(void);

static void dwt_reset(void)
{
    DWT->CYCCNT = 0;
    __DSB();
    __ISB();
}

/* DEBUT Ajout Tests Stack */

static void stack_pattern_fill(void)
{
    memset(bench_stack, STACK_PATTERN, sizeof(bench_stack));
}

static uint8_t *bench_get_stack_top(void)
{
    uintptr_t top = (uintptr_t)(bench_stack + sizeof(bench_stack));

    /* alignement 8 octets */
    top &= ~((uintptr_t)0x7u);

    /* petite marge pour le prologue */
    top -= 16u;

    return (uint8_t *)top;
}

static size_t stack_measure_used(void)
{
    size_t i = 0;

    while (i < sizeof(bench_stack) && bench_stack[i] == STACK_PATTERN)
    {
        i++;
    }

    return sizeof(bench_stack) - i;
}

__attribute__((naked)) static int call_on_stack(bench_fun_t fn, uint8_t *stack_top)
{
    __asm volatile(
        "mov r2, sp            \n" /* sauvegarde ancien SP dans r2 */
        "mov sp, r1            \n" /* SP = nouvelle pile */
        "push {r2, lr}         \n" /* sauvegarde ancien SP et LR sur la nouvelle pile */
        "blx r0                \n" /* appelle fn() */
        "pop {r2, lr}          \n" /* restaure ancien SP et LR */
        "mov sp, r2            \n" /* restaure SP d'origine */
        "bx lr                 \n"
    );
}

static int measure_cycles_and_stack(bench_fun_t fn, uint32_t *cycles, size_t *stack_used)
{
    int ret;

    stack_pattern_fill();

    __disable_irq();
    dwt_reset();
    ret = call_on_stack(fn, bench_get_stack_top());
    *cycles = dwt_get_cycles();
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

static int mlkem_bench_stack_test(void)
{
    printf("\r\n==== BENCH STACK ML-KEM-768 m4fspeed / STM32 ====\r\n");

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss_enc, 0, sizeof(ss_enc));
    memset(ss_dec, 0, sizeof(ss_dec));

    /* KEYPAIR */
    if (measure_cycles_and_stack(do_keypair, &cycles_keypair, &stack_keypair) != 0)
    {
        printf("ERREUR bench keypair\r\n");
        return -1;
    }

    /* ENCAPS */
    if (measure_cycles_and_stack(do_encaps, &cycles_encaps, &stack_encaps) != 0)
    {
        printf("ERREUR bench encaps\r\n");
        return -2;
    }

    /* DECAPS */
    if (measure_cycles_and_stack(do_decaps, &cycles_decaps, &stack_decaps) != 0)
    {
        printf("ERREUR bench decaps\r\n");
        return -3;
    }

    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) != 0)
    {
        printf("ERREUR: secret partage different\r\n");
        return -4;
    }

    printf("KEYPAIR : %lu cycles, stack max = %u octets\r\n",
           (unsigned long)cycles_keypair, (unsigned)stack_keypair);

    printf("ENCAPS  : %lu cycles, stack max = %u octets\r\n",
           (unsigned long)cycles_encaps, (unsigned)stack_encaps);

    printf("DECAPS  : %lu cycles, stack max = %u octets\r\n",
           (unsigned long)cycles_decaps, (unsigned)stack_decaps);

    return 0;
}

/* FIN Ajout Tests Stack */

static int mlkem_self_test(void)
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
        print_hex("ss_enc = ", ss_enc, CRYPTO_BYTES);
        print_hex("ss_dec = ", ss_dec, CRYPTO_BYTES);
        return -4;
    }

    printf("[4] shared secret match: OUI\r\n");
    print_hex("pk[0..15] = ", pk, 16);
    print_hex("ct[0..15] = ", ct, 16);
    print_hex("ss = ", ss_enc, CRYPTO_BYTES);

    return 0;
}

static void benchmark_mlkem(void)
{
    uint32_t t0, t1;
    uint32_t key_cycles, enc_cycles, dec_cycles;
    uint32_t key_min = 0xFFFFFFFFu, enc_min = 0xFFFFFFFFu, dec_min = 0xFFFFFFFFu;
    uint32_t key_max = 0, enc_max = 0, dec_max = 0;
    uint64_t key_sum = 0, enc_sum = 0, dec_sum = 0;
    int i;

    printf("\r\n==== Benchmark PQM4-style (%d iterations) ====\r\n", BENCH_ITERS);

    for (i = 0; i < BENCH_ITERS; i++)
    {
        t0 = dwt_get_cycles();
        crypto_kem_keypair(pk, sk);
        t1 = dwt_get_cycles();
        key_cycles = t1 - t0;

        t0 = dwt_get_cycles();
        crypto_kem_enc(ct, ss_enc, pk);
        t1 = dwt_get_cycles();
        enc_cycles = t1 - t0;

        t0 = dwt_get_cycles();
        crypto_kem_dec(ss_dec, ct, sk);
        t1 = dwt_get_cycles();
        dec_cycles = t1 - t0;

        if (key_cycles < key_min) key_min = key_cycles;
        if (enc_cycles < enc_min) enc_min = enc_cycles;
        if (dec_cycles < dec_min) dec_min = dec_cycles;

        if (key_cycles > key_max) key_max = key_cycles;
        if (enc_cycles > enc_max) enc_max = enc_cycles;
        if (dec_cycles > dec_max) dec_max = dec_cycles;

        key_sum += key_cycles;
        enc_sum += enc_cycles;
        dec_sum += dec_cycles;

        printf("#%02d key=%lu enc=%lu dec=%lu cycles\r\n",
               i + 1,
               (unsigned long)key_cycles,
               (unsigned long)enc_cycles,
               (unsigned long)dec_cycles);
    }

    printf("\r\n");
    printf("keypair avg/min/max = %llu / %lu / %lu cycles\r\n",
           (unsigned long long)(key_sum / BENCH_ITERS),
           (unsigned long)key_min,
           (unsigned long)key_max);

    printf("encaps  avg/min/max = %llu / %lu / %lu cycles\r\n",
           (unsigned long long)(enc_sum / BENCH_ITERS),
           (unsigned long)enc_min,
           (unsigned long)enc_max);

    printf("decaps  avg/min/max = %llu / %lu / %lu cycles\r\n",
           (unsigned long long)(dec_sum / BENCH_ITERS),
           (unsigned long)dec_min,
           (unsigned long)dec_max);
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
  int test_status = -999;
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_LPUART1_UART_Init();
  MX_RNG_Init();
  /* USER CODE BEGIN 2 */
  dwt_init();

  test_status = mlkem_self_test();

  if (test_status == 0)
  {
      int bench_stack_status;
//      HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET);
//      HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_RESET);
      printf("PQM4 ML-KEM-768 m4fspeed: SUCCES\r\n");

      /* Moyenne des cycles */
      benchmark_mlkem();

      /* nouveau bench : cycles + stack sur pile dediee */
	  bench_stack_status = mlkem_bench_stack_test();
	  if (bench_stack_status == 0)
	  {
		  printf("Bench stack SUCCES\r\n");
	  }
	  else
	  {
		  printf("Bench stack ECHEC (%d)\r\n", bench_stack_status);
	  }
  }
  else
  {
//      HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);
//      HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_SET);
      printf("PQM4 ML-KEM-768 m4fspeed: ECHEC (%d)\r\n", test_status);
  }
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = 0;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_MSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief LPUART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_LPUART1_UART_Init(void)
{

  /* USER CODE BEGIN LPUART1_Init 0 */

  /* USER CODE END LPUART1_Init 0 */

  /* USER CODE BEGIN LPUART1_Init 1 */

  /* USER CODE END LPUART1_Init 1 */
  hlpuart1.Instance = LPUART1;
  hlpuart1.Init.BaudRate = 115200;
  hlpuart1.Init.WordLength = UART_WORDLENGTH_8B;
  hlpuart1.Init.StopBits = UART_STOPBITS_1;
  hlpuart1.Init.Parity = UART_PARITY_NONE;
  hlpuart1.Init.Mode = UART_MODE_TX_RX;
  hlpuart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  hlpuart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  hlpuart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&hlpuart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN LPUART1_Init 2 */

  /* USER CODE END LPUART1_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOG_CLK_ENABLE();
  HAL_PWREx_EnableVddIO2();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
