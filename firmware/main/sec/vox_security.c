#include "sec/vox_security.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
static SemaphoreHandle_t s_lock;
esp_err_t vox_security_init(void)
{
    if (!s_lock) s_lock = xSemaphoreCreateRecursiveMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}
void vox_security_lock(void) { xSemaphoreTakeRecursive(s_lock, portMAX_DELAY); }
void vox_security_unlock(void) { xSemaphoreGiveRecursive(s_lock); }
