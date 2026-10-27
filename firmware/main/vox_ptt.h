/*
 * vox_ptt.h - talk-burst control and oscilloscope trace pins.
 *
 * Voice here is half duplex by design, matching the walkie-talkie case the
 * report describes. A talk burst is a bounded stream of frames sharing one
 * stream_id; the receiver treats a change of stream_id as a hard playout
 * restart rather than trying to bridge the silence between bursts.
 *
 * The trace pins exist because the software one-way delay figure rests on a
 * clock-offset estimate. Toggling a GPIO at the instant a frame is handed to
 * the radio, and another at the instant the decoded frame is handed to the
 * DAC, gives a latency measurement on an oscilloscope that depends on no
 * software assumption at all. Reporting the two together is what turns the
 * software figure from an estimate into a validated one.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

esp_err_t vox_ptt_init(void);

void vox_ptt_snapshot(bool *active, bool *group, uint16_t *stream);
bool     vox_ptt_active(void);
void     vox_ptt_set(bool on);
uint16_t vox_ptt_stream_id(void);

/*
 * Delivery mode for the current/next talk burst: unicast (default, every
 * established pairwise peer, RQ1's architecture) or group (one broadcast
 * under the shared group key, RQ2's architecture). Decoupled from
 * vox_ptt_active() the same way the two already are from each other --
 * tx_task() snapshots these fields under the security mutex -- so the Chapter 4 experiment
 * protocol's matched trials can hold everything else constant and vary only
 * this flag between a unicast run and a group run.
 */
bool     vox_ptt_group(void);
void     vox_ptt_set_group(bool on);

/* True exactly once, on the frame that opens a burst. */
bool vox_ptt_take_start_edge(void);
bool vox_ptt_take_end_edge(void);

void vox_trace_tx_pulse(void);
void vox_trace_rx_pulse(void);
