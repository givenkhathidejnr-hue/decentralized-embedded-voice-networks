#include "vox_ptt.h"
#include "sec/vox_security.h"
#include "vox_config.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "vox.ptt";

static volatile bool     s_active;
static volatile bool     s_start_edge;
static volatile bool     s_end_edge;
static uint16_t          s_stream_id;
static volatile bool     s_group_mode;

#if CONFIG_VOX_PTT_GPIO >= 0
#define PTT_DEBOUNCE_MS 30

static void ptt_task(void *arg)
{
    (void)arg;
    bool stable = false;
    int64_t last_change_us = 0;

    for (;;) {
        bool pressed = (gpio_get_level(CONFIG_VOX_PTT_GPIO) == 0);  /* active low */
        int64_t now = esp_timer_get_time();

        if (pressed != stable) {
            if (last_change_us == 0) {
                last_change_us = now;
            } else if ((now - last_change_us) > (PTT_DEBOUNCE_MS * 1000)) {
                stable = pressed;
                last_change_us = 0;
                vox_ptt_set(stable);
            }
        } else {
            last_change_us = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
#endif

esp_err_t vox_ptt_init(void)
{
#if CONFIG_VOX_PTT_GPIO >= 0
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << CONFIG_VOX_PTT_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&io));
    xTaskCreatePinnedToCore(ptt_task, "ptt", 2048, NULL, 4, NULL, 0);
    ESP_LOGI(TAG, "push-to-talk on GPIO%d (active low)", CONFIG_VOX_PTT_GPIO);
#else
    ESP_LOGI(TAG, "no PTT GPIO; drive talk bursts from the console");
#endif

#if CONFIG_VOX_TRACE_GPIO_TX >= 0
    gpio_config_t tx_io = {
        .pin_bit_mask = 1ULL << CONFIG_VOX_TRACE_GPIO_TX,
        .mode = GPIO_MODE_OUTPUT, .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE, .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&tx_io));
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_TX, 0);
#endif
#if CONFIG_VOX_TRACE_GPIO_RX >= 0
    gpio_config_t rx_io = {
        .pin_bit_mask = 1ULL << CONFIG_VOX_TRACE_GPIO_RX,
        .mode = GPIO_MODE_OUTPUT, .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE, .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&rx_io));
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_RX, 0);
#endif

    s_stream_id = (uint16_t)(esp_random() & 0xFFFF);
    return ESP_OK;
}

void vox_ptt_snapshot(bool *active,bool *group,uint16_t *stream)
{
    vox_security_lock(); *active=s_active; *group=s_group_mode; *stream=s_stream_id; vox_security_unlock();
}
bool vox_ptt_active(void) { vox_security_lock(); bool v=s_active; vox_security_unlock(); return v; }
bool vox_ptt_group(void) { vox_security_lock(); bool v=s_group_mode; vox_security_unlock(); return v; }
void vox_ptt_set_group(bool on) { vox_security_lock(); s_group_mode=on; vox_security_unlock(); }
void vox_ptt_set(bool on)
{
    vox_security_lock();
    if(on!=s_active) {
        s_active=on;
        if(on) { s_stream_id++; s_start_edge=true; } else s_end_edge=true;
        ESP_LOGI(TAG,"talk burst %u %s",s_stream_id,on?"start":"end");
    }
    vox_security_unlock();
}
uint16_t vox_ptt_stream_id(void) { vox_security_lock(); uint16_t v=s_stream_id; vox_security_unlock(); return v; }
bool vox_ptt_take_start_edge(void) {
    vox_security_lock(); bool e=s_start_edge; s_start_edge=false; vox_security_unlock(); return e;
}
bool vox_ptt_take_end_edge(void) {
    vox_security_lock(); bool e=s_end_edge; s_end_edge=false; vox_security_unlock(); return e;
}

/*
 * Short pulses, deliberately not blocking. Width is set by the two register
 * writes themselves, which is a few hundred nanoseconds: enough for a logic
 * analyser, and small enough that the trace does not perturb the timing it is
 * there to measure.
 */
void vox_trace_tx_pulse(void)
{
#if CONFIG_VOX_TRACE_GPIO_TX >= 0
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_TX, 1);
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_TX, 0);
#endif
}

void vox_trace_rx_pulse(void)
{
#if CONFIG_VOX_TRACE_GPIO_RX >= 0
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_RX, 1);
    gpio_set_level(CONFIG_VOX_TRACE_GPIO_RX, 0);
#endif
}
