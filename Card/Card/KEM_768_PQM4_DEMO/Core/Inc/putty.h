#ifndef PUTTY_H
#define PUTTY_H

#include "main.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void Putty_PrintHex(const char *label, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PUTTY_H */
