#ifndef TEMPERATURE_SENSOR_H
#define TEMPERATURE_SENSOR_H


#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"
#include <stdint.h>

HAL_StatusTypeDef bmp280_init_simple(void);
HAL_StatusTypeDef bmp280_read_temperature_centi_deg(int32_t *temp_centi);

#ifdef __cplusplus
}
#endif

#endif /* TEMPERATURE_SENSOR_H */
