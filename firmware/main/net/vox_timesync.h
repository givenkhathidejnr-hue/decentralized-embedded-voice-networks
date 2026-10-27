/*
 * vox_timesync.h - clock offset estimation, so one-way delay is measurable.
 *
 * The two boards have independent, free-running microsecond clocks. A frame
 * carries the sender's timestamp; the receiver reads its own clock on arrival.
 * Subtracting those two directly measures nothing, because the difference
 * includes an arbitrary constant offset between the clocks.
 *
 * This module estimates that constant with the standard four-timestamp
 * exchange:
 *
 *     A --SYNC_REQ, t1------------------> B  (arrives t2)
 *     A <-----------------SYNC_RESP, t1,t2,t3-- B  (sent t3)
 *     arrives t4
 *
 *     offset(A - B) = ((t1 - t2) + (t4 - t3)) / 2
 *     rtt           =  (t4 - t1) - (t3 - t2)
 *
 * The estimator keeps a window of samples and reports the offset from the
 * sample with the SMALLEST round-trip time, not the mean. That is deliberate:
 * queueing delay is one-sided and additive, so the least-delayed exchange is
 * the least-biased one. Averaging offsets would fold transmission jitter into
 * the constant being estimated and put a slow drift into every latency figure
 * in the results.
 *
 * The residual error in one-way delay is bounded by roughly half the
 * path asymmetry of the best sample, so the summary reports the best RTT
 * alongside the offset and the write-up should quote it as the uncertainty.
 * For a ground-truth cross-check independent of software entirely, set
 * CONFIG_VOX_TRACE_GPIO_TX and CONFIG_VOX_TRACE_GPIO_RX and put both boards
 * on one oscilloscope or logic analyser.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "vox_frame.h"

esp_err_t vox_timesync_init(void);

/* Send a probe to `peer_mac`. Cheap; call it a few times a second. */
esp_err_t vox_timesync_probe(const uint8_t peer_mac[6], uint16_t peer_id);

/* Feed a received VOX_T_SYNC_REQ / VOX_T_SYNC_RESP frame. */
void vox_timesync_on_frame(const uint8_t src_mac[6], const vox_hdr_t *hdr,
                           const uint8_t *body, size_t body_len, int64_t t_rx_us);

/* our_clock - peer_clock, in microseconds. Valid only if _valid() is true. */
bool    vox_timesync_valid(uint16_t peer_id);
int64_t vox_timesync_offset_us(uint16_t peer_id);
int64_t vox_timesync_best_rtt_us(uint16_t peer_id);
uint32_t vox_timesync_samples(uint16_t peer_id);

/*
 * Convert a sender timestamp carried in a frame into a one-way delay against
 * our own arrival time, correcting the 32-bit microsecond wrap. Returns
 * INT64_MIN when no usable offset estimate exists yet, so the caller can
 * exclude the sample rather than record a fabricated zero.
 */
int64_t vox_timesync_owd(uint16_t peer_id, uint32_t t_tx_us32, int64_t t_rx_us);

/* Caller holds security lock, including during peer removal. */
void vox_timesync_forget(uint16_t peer_id);
