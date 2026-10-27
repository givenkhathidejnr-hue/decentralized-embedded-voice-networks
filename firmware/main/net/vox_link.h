/*
 * vox_link.h - ESP-NOW transport.
 *
 * Deliberately thin. It owns Wi-Fi/ESP-NOW bring-up, the link-level peer
 * table, one transmit primitive and one receive queue. All framing,
 * protection and audio logic sits above it, so that the same transport can
 * carry the group arm of the study unchanged.
 *
 * Transmit is serialised against the ESP-NOW send callback. esp_now_send() is
 * asynchronous and the driver's queue is shallow; firing several sends
 * without waiting produces ESP_ERR_ESPNOW_NO_MEM and destroys the per-peer
 * timing attribution that the N-scaling measurement depends on. Waiting for
 * the callback costs a little throughput and buys a defensible per-peer
 * transmit-time figure.
 *
 * The receive callback runs in the Wi-Fi task. It does exactly two things:
 * take a timestamp and copy the frame into a queue. Taking the timestamp
 * there rather than in the worker task is what makes the one-way delay
 * measurement a measurement of the radio path plus the local pipeline,
 * rather than of scheduler jitter in our own code.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "vox_frame.h"

typedef struct {
    uint8_t  src_mac[6];
    int64_t  t_rx_us;                    /* esp_timer at the ESP-NOW callback */
    uint16_t len;
    int8_t   rssi;
    uint8_t  buf[VOX_FRAME_MAX_LEN];
} vox_rx_pkt_t;

esp_err_t vox_link_init(void);

/* Local station MAC, printed at boot so the other board can be told about it. */
const uint8_t *vox_link_self_mac(void);

/* Register a MAC with the ESP-NOW driver. `lmk` may be NULL for unencrypted
 * link-layer delivery, which is the baseline: protection is applied above.
 * Passing an LMK enables ESP-NOW's own CCMP on top, for the layered-cost
 * measurement only. */
esp_err_t vox_link_peer_add(const uint8_t mac[6], const uint8_t *lmk);
esp_err_t vox_link_peer_del(const uint8_t mac[6]);

/*
 * Blocking unicast send. Returns:
 *   ESP_OK              driver accepted and the callback reported success
 *   ESP_ERR_TIMEOUT     no send callback within `timeout_ms`
 *   ESP_FAIL            callback reported failure (no acknowledgement)
 * `out_air_us` receives the interval from esp_now_send() to the callback,
 * which is the closest proxy for occupied transmit time available without
 * external measurement equipment. It includes driver queueing and any MAC
 * retries, and must be reported as such rather than as pure airtime.
 */
esp_err_t vox_link_send(const uint8_t mac[6], const uint8_t *buf, size_t len,
                        uint32_t timeout_ms, int64_t *out_air_us);

/*
 * Broadcast, used by the group arm and by time sync. Shares vox_link_send()'s
 * blocking/completion-wait path, so `out_air_us` means exactly what it means
 * there -- except a broadcast has no MAC-level acknowledgement or retry, so
 * this isolates driver/queueing cost from the retry budget a unicast send to
 * an unresponsive peer can pay. Pass NULL to ignore it.
 */
esp_err_t vox_link_broadcast(const uint8_t *buf, size_t len, int64_t *out_air_us);

/* Blocking receive from the ingress queue. */
bool vox_link_recv(vox_rx_pkt_t *out, uint32_t timeout_ms);

/* Link-level counters. */
typedef struct {
    uint32_t tx_calls;
    uint32_t tx_cb_ok;
    uint32_t tx_cb_fail;
    uint32_t tx_enqueue_err;
    uint32_t tx_timeout;
    uint32_t rx_frames;
    uint32_t rx_queue_drop;
    uint64_t tx_payload_bytes;
    uint64_t rx_payload_bytes;
} vox_link_stats_t;

void vox_link_stats(vox_link_stats_t *out);
void vox_link_stats_reset(void);

extern const uint8_t VOX_BROADCAST_MAC[6];
