#include "putty.h"
#include <stdio.h>

extern UART_HandleTypeDef hlpuart1;

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

void Putty_PrintHex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;

    printf("%s", label);
    for (i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\r\n");
}
