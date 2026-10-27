#pragma once
#include "esp_err.h"
/* Initialise before starting tasks. Borrowed session/group pointers may only
 * be used under this recursive task mutex. Never use it in Wi-Fi callbacks. */
esp_err_t vox_security_init(void);
void vox_security_lock(void);
void vox_security_unlock(void);
