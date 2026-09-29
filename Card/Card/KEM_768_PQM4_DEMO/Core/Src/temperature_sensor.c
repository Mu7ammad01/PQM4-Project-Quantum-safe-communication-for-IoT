#include "temperature_sensor.h"

typedef struct
{
  uint16_t dig_T1;
  int16_t  dig_T2;
  int16_t  dig_T3;
} BMP280_Calib_t;

static BMP280_Calib_t bmp_calib;
static uint8_t bmp_addr = 0;   // 0x76 ou 0x77
static int32_t t_fine = 0;

extern I2C_HandleTypeDef hi2c1;

static HAL_StatusTypeDef bmp280_read_reg(uint8_t reg, uint8_t *data, uint16_t len)
{
  return HAL_I2C_Mem_Read(&hi2c1, (uint16_t)(bmp_addr << 1), reg, I2C_MEMADD_SIZE_8BIT, data, len, HAL_MAX_DELAY);
}

static HAL_StatusTypeDef bmp280_write_reg(uint8_t reg, uint8_t value)
{
  return HAL_I2C_Mem_Write(&hi2c1, (uint16_t)(bmp_addr << 1), reg, I2C_MEMADD_SIZE_8BIT, &value, 1, HAL_MAX_DELAY);
}

static uint8_t i2c_scan_for_bmp(void)
{
  uint8_t id = 0;

  for (uint8_t addr = 1; addr < 127; addr++)
  {
    if (HAL_I2C_IsDeviceReady(&hi2c1, (uint16_t)(addr << 1), 2, 50) == HAL_OK)
    {
      if (HAL_I2C_Mem_Read(&hi2c1, (uint16_t)(addr << 1), 0xD0, I2C_MEMADD_SIZE_8BIT, &id, 1, 100) == HAL_OK)
      {
        if (id == 0x58 || id == 0x60)
        {
          return addr;
        }
      }
    }
  }

  return 0;
}

static HAL_StatusTypeDef bmp280_read_calibration(void)
{
  uint8_t calib[6];

  if (bmp280_read_reg(0x88, calib, 6) != HAL_OK)
    return HAL_ERROR;

  bmp_calib.dig_T1 = (uint16_t)(calib[1] << 8 | calib[0]);
  bmp_calib.dig_T2 = (int16_t)(calib[3] << 8 | calib[2]);
  bmp_calib.dig_T3 = (int16_t)(calib[5] << 8 | calib[4]);

  return HAL_OK;
}

HAL_StatusTypeDef bmp280_init_simple(void)
{
  uint8_t id = 0;

  bmp_addr = i2c_scan_for_bmp();
  if (bmp_addr == 0)
    return HAL_ERROR;

  if (bmp280_read_reg(0xD0, &id, 1) != HAL_OK)
    return HAL_ERROR;

  if (id != 0x58 && id != 0x60)
    return HAL_ERROR;

  if (bmp280_write_reg(0xE0, 0xB6) != HAL_OK)   // reset
    return HAL_ERROR;

  HAL_Delay(10);

  if (bmp280_write_reg(0xF4, 0x27) != HAL_OK)   // temp x1, press x1, normal mode
    return HAL_ERROR;

  if (bmp280_write_reg(0xF5, 0xA0) != HAL_OK)   // standby 1000 ms
    return HAL_ERROR;

  return bmp280_read_calibration();
}

HAL_StatusTypeDef bmp280_read_temperature_centi_deg(int32_t *temp_centi)
{
  uint8_t data[3];
  int32_t adc_T;
  int32_t var1, var2;

  if (bmp280_read_reg(0xFA, data, 3) != HAL_OK)
    return HAL_ERROR;

  adc_T = ((int32_t)data[0] << 12) |
          ((int32_t)data[1] << 4)  |
          ((int32_t)data[2] >> 4);

  var1 = ((((adc_T >> 3) - ((int32_t)bmp_calib.dig_T1 << 1))) * ((int32_t)bmp_calib.dig_T2)) >> 11;
  var2 = (((((adc_T >> 4) - ((int32_t)bmp_calib.dig_T1)) *
            ((adc_T >> 4) - ((int32_t)bmp_calib.dig_T1))) >> 12) *
            ((int32_t)bmp_calib.dig_T3)) >> 14;

  t_fine = var1 + var2;
  *temp_centi = (t_fine * 5 + 128) >> 8;

  return HAL_OK;
}
