#pragma once
#include <stddef.h>
#include <stdint.h>
void esp_fill_random(void *,size_t);
uint32_t esp_random(void);
