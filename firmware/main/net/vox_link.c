#include <string.h>
#include "net/vox_link.h"
#include "vox_config.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_timer.h"

static const char *TAG = "vox.link";

const uint8_t VOX_BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define RX_QUEUE_DEPTH  16

static QueueHandle_t     s_rx_q;
static SemaphoreHandle_t s_tx_lock;     /* serialises send + callback wait */
static SemaphoreHandle_t s_tx_done;     /* signalled by the send callback  */
static volatile bool     s_tx_ok;
static bool              s_tx_inflight; /* owned by caller under s_tx_lock */
static uint8_t           s_tx_mac[6];
static uint8_t           s_self_mac[6];
static vox_link_stats_t  s_stats;
static portMUX_TYPE s_stats_mux=portMUX_INITIALIZER_UNLOCKED;
#define STAT_ADD(field,value) do { portENTER_CRITICAL(&s_stats_mux); s_stats.field+=(value); portEXIT_CRITICAL(&s_stats_mux); } while(0)

/* ------------------------------------------------------------- callbacks */

/*
 * Runs in the Wi-Fi task, NOT in an interrupt: ESP-NOW dispatches both
 * callbacks from task context. Using the FromISR primitives here would be a
 * latent fault, so this uses the ordinary ones.
 */
static void on_send(const uint8_t *mac, esp_now_send_status_t status)
{
    if (memcmp(mac,s_tx_mac,6)!=0) return;
    s_tx_ok = (status == ESP_NOW_SEND_SUCCESS);
    if (s_tx_ok) {
        STAT_ADD(tx_cb_ok,1);
    } else {
        STAT_ADD(tx_cb_fail,1);
    }
    xSemaphoreGive(s_tx_done);
}

/*
 * Runs in the Wi-Fi task context. Timestamp first, copy second, no parsing,
 * no crypto: anything expensive here inflates every latency figure in the
 * study and risks starving the Wi-Fi driver.
 */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    int64_t now = esp_timer_get_time();

    if (len <= 0 || len > VOX_FRAME_MAX_LEN) {
        return;
    }

    vox_rx_pkt_t pkt;
    pkt.t_rx_us = now;
    pkt.len     = (uint16_t)len;
    pkt.rssi    = (info->rx_ctrl != NULL) ? (int8_t)info->rx_ctrl->rssi : 0;
    memcpy(pkt.src_mac, info->src_addr, 6);
    memcpy(pkt.buf, data, (size_t)len);

    STAT_ADD(rx_frames,1);
    STAT_ADD(rx_payload_bytes,(uint64_t)len);

    if (xQueueSend(s_rx_q, &pkt, 0) != pdTRUE) {
        /* A drop here is a real result, not a nuisance: it says the receive
         * pipeline could not keep up with the offered load. Counted, never
         * silently absorbed. */
        STAT_ADD(rx_queue_drop,1);
    }
}

/* ------------------------------------------------------------------- api */

esp_err_t vox_link_init(void)
{
    s_rx_q    = xQueueCreate(RX_QUEUE_DEPTH, sizeof(vox_rx_pkt_t));
    s_tx_lock = xSemaphoreCreateMutex();
    s_tx_done = xSemaphoreCreateBinary();
    if (s_rx_q == NULL || s_tx_lock == NULL || s_tx_done == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Every node in one experiment must sit on the same channel, and power
     * save must be off: a sleeping receiver would silently add latency that
     * the measurements would wrongly attribute to the protocol. */
    ESP_ERROR_CHECK(esp_wifi_set_channel(VOX_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(on_send));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(on_recv));

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, s_self_mac));

    /* Broadcast pseudo-peer, needed for time sync and the group arm. */
    esp_now_peer_info_t bc = { 0 };
    memcpy(bc.peer_addr, VOX_BROADCAST_MAC, 6);
    bc.channel = VOX_WIFI_CHANNEL;
    bc.ifidx   = WIFI_IF_STA;
    bc.encrypt = false;
    esp_err_t err = esp_now_add_peer(&bc);
    if (err != ESP_OK && err != ESP_ERR_ESPNOW_EXIST) {
        return err;
    }

    ESP_LOGI(TAG, "ESP-NOW up on channel %d, mac " MACSTR, VOX_WIFI_CHANNEL,
             MAC2STR(s_self_mac));
    return ESP_OK;
}

const uint8_t *vox_link_self_mac(void)
{
    return s_self_mac;
}

esp_err_t vox_link_peer_add(const uint8_t mac[6], const uint8_t *lmk)
{
    esp_now_peer_info_t p = { 0 };
    memcpy(p.peer_addr, mac, 6);
    p.channel = VOX_WIFI_CHANNEL;
    p.ifidx   = WIFI_IF_STA;

    if (lmk != NULL) {
        p.encrypt = true;
        memcpy(p.lmk, lmk, ESP_NOW_KEY_LEN);
    } else {
        p.encrypt = false;
    }

    esp_err_t err = esp_now_add_peer(&p);
    if (err == ESP_ERR_ESPNOW_EXIST) {
        err = esp_now_mod_peer(&p);
    }
    return err;
}

esp_err_t vox_link_peer_del(const uint8_t mac[6])
{
    return esp_now_del_peer(mac);
}

esp_err_t vox_link_send(const uint8_t mac[6], const uint8_t *buf, size_t len,
                        uint32_t timeout_ms, int64_t *out_air_us)
{
    if (len > ESP_NOW_MAX_DATA_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    xSemaphoreTake(s_tx_lock, portMAX_DELAY);

    /* A timeout does not cancel the driver's send. Do not enqueue a new
     * operation until that exact outstanding callback has been consumed. */
    if(s_tx_inflight) {
        if(xSemaphoreTake(s_tx_done,pdMS_TO_TICKS(timeout_ms))!=pdTRUE) {
            STAT_ADD(tx_timeout,1); xSemaphoreGive(s_tx_lock); return ESP_ERR_TIMEOUT;
        }
        s_tx_inflight=false;
    }
    memcpy(s_tx_mac,mac,6);
    s_tx_inflight=true;

    int64_t t0 = esp_timer_get_time();
    STAT_ADD(tx_calls,1);

    esp_err_t err = esp_now_send(mac, buf, len);
    if (err != ESP_OK) {
        s_tx_inflight=false;
        STAT_ADD(tx_enqueue_err,1);
        xSemaphoreGive(s_tx_lock);
        return err;
    }

    esp_err_t result;
    if (xSemaphoreTake(s_tx_done, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        STAT_ADD(tx_timeout,1);
        result = ESP_ERR_TIMEOUT;
    } else {
        s_tx_inflight=false;
        result = s_tx_ok ? ESP_OK : ESP_FAIL;
    }

    int64_t t1 = esp_timer_get_time();
    if (out_air_us != NULL) {
        *out_air_us = t1 - t0;
    }
    STAT_ADD(tx_payload_bytes,(uint64_t)len);

    xSemaphoreGive(s_tx_lock);
    return result;
}

esp_err_t vox_link_broadcast(const uint8_t *buf, size_t len, int64_t *out_air_us)
{
    return vox_link_send(VOX_BROADCAST_MAC, buf, len, 50, out_air_us);
}

bool vox_link_recv(vox_rx_pkt_t *out, uint32_t timeout_ms)
{
    return xQueueReceive(s_rx_q, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void vox_link_stats(vox_link_stats_t *out)
{
    portENTER_CRITICAL(&s_stats_mux); *out=s_stats; portEXIT_CRITICAL(&s_stats_mux);
}

void vox_link_stats_reset(void)
{
    portENTER_CRITICAL(&s_stats_mux); memset(&s_stats,0,sizeof(s_stats)); portEXIT_CRITICAL(&s_stats_mux);
}
