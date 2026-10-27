/*
 * vox_metrics.h - the measurement apparatus.
 *
 * Three design rules, each of which exists to stop the instrumentation from
 * corrupting the thing it measures:
 *
 * 1. NOTHING IS PRINTED DURING A RUN. Per-frame records go into a fixed RAM
 *    ring; aggregates and histograms are updated with a handful of integer
 *    operations. The CSV is emitted only after the run stops. Printing 50
 *    lines a second over UART would cost more CPU than the cryptography the
 *    study is trying to weigh, and would land in the same numbers.
 *
 * 2. AGGREGATES ARE UNBOUNDED, RAW RECORDS ARE NOT. Count, min, max, mean and
 *    standard deviation accumulate for the whole run in constant memory, and
 *    a fixed-width histogram supplies percentiles. The raw ring holds only
 *    the most recent VOX_TRACE_DEPTH frames, for inspecting a specific event.
 *    A run may therefore be as long as you like; only the detailed trace is
 *    bounded.
 *
 * 3. STAGES ARE TIMED SEPARATELY. encode, protect, transmit on the sender;
 *    verify, decode, playout on the receiver. The review is explicit that a
 *    single "encryption overhead" figure conceals the decision that actually
 *    matters, so protect/verify is never folded into anything else.
 *
 * The resource sampler covers the list the review requires to accompany any
 * ESP32 claim: free internal heap, largest free block, per-task stack
 * high-water marks, per-core CPU utilisation, queue depth and underruns, plus
 * the module and toolchain identification that makes the numbers transferable.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#define VOX_TRACE_DEPTH     1000    /* raw per-frame records retained, each direction */
#define VOX_HIST_BINS       64
#define VOX_HIST_BIN_US     2000    /* 2 ms per bin -> 0..128 ms, then overflow */

/* --------------------------------------------------------- running stats */

typedef struct {
    uint32_t n;
    int64_t  sum;
    int64_t  sumsq;
    int32_t  min;
    int32_t  max;
} vox_stat_t;

void   vox_stat_reset(vox_stat_t *s);
void   vox_stat_add(vox_stat_t *s, int32_t v);
double vox_stat_mean(const vox_stat_t *s);
double vox_stat_sd(const vox_stat_t *s);

/* ------------------------------------------------------------- run state */

typedef struct {
    /* sender */
    vox_stat_t encode_us;
    vox_stat_t protect_us;
    vox_stat_t send_us;          /* per frame, summed over all peers */
    vox_stat_t send_per_peer_us; /* per peer per frame, all peers */
    /*
     * The real/phantom split exists because a phantom peer never acknowledges,
     * so its unicast pays a full Wi-Fi MAC retry budget before the completion
     * callback fires -- measured at roughly 4x the cost of a send to a real
     * acking peer. Folding the two together makes the sender-scaling curve a
     * measurement of retry timeout rather than of per-listener cost. Keeping
     * them apart means a phantom-assisted run still yields a defensible
     * per-listener transmit figure, taken from the real peers in the same run.
     */
    vox_stat_t send_real_us;         /* per frame, summed over real peers */
    vox_stat_t send_real_per_peer_us;
    vox_stat_t send_phantom_per_peer_us;
    uint32_t   tx_frames;
    uint32_t   tx_unicasts;      /* frames x peers: the RQ1 replication count */
    uint32_t   tx_real_unicasts;
    uint32_t   tx_phantom_unicasts;
    uint64_t   tx_air_bytes;     /* payload + link encapsulation */
    uint32_t   tx_send_fail;
    uint32_t   tx_deadline_miss; /* frames that took longer than VOX_FRAME_MS */
    /*
     * First and last frame instants, so the achieved rate is measured rather
     * than inferred. Deriving the burst length from the frame count and then
     * dividing the frame count by it is circular -- it returns the nominal
     * rate identically, and reported 50.00 f/s even when a third of frames
     * overran their deadline.
     */
    int64_t    t_first_tx_us;
    int64_t    t_last_tx_us;

    /* receiver */
    vox_stat_t verify_us;
    vox_stat_t decode_us;
    vox_stat_t owd_us;           /* one-way delay, clock-offset corrected */
    vox_stat_t ipdv_us;          /* inter-packet delay variation (RFC 3550 jitter input) */
    double     rtp_jitter_us;    /* RFC 3550 smoothed jitter estimate */
    uint32_t   rx_frames;
    uint32_t   rx_auth_fail;
    uint32_t   rx_replay_drop;
    uint32_t   rx_epoch_unknown;
    uint32_t   rx_malformed;
    uint32_t   rx_late;          /* past its playout instant */
    uint32_t   owd_over_budget;  /* one-way delay above the 150 ms target */

    /* signal fidelity, only when the deterministic source is in use */
    vox_stat_t frame_rms_err;    /* per-frame RMS error against the reference */
    uint32_t   frames_compared;
    uint32_t   frames_bitexact;

    uint16_t   owd_hist[VOX_HIST_BINS + 1];

    int64_t    t_start_us;
    int64_t    t_stop_us;
    bool       running;
} vox_run_t;

/* -------------------------------------------------------- raw trace rows */

typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint16_t encode_us;
    uint16_t protect_us;
    uint32_t send_us;
    uint32_t air_us_max;
    uint8_t  npeer;
    uint8_t  nfail;
    uint8_t  nreal;      /* of npeer, how many were real acking peers */
} vox_tx_rec_t;

typedef struct __attribute__((packed)) {
    uint32_t seq;
    int32_t  owd_us;
    uint16_t verify_us;
    uint16_t decode_us;
    uint16_t rms_err;
    uint8_t  jb_depth;
    int8_t   rssi;
} vox_rx_rec_t;

/* ------------------------------------------------------------------- api */

esp_err_t vox_metrics_init(void);

void vox_metrics_run_start(const char *label);
void vox_metrics_run_stop(void);
bool vox_metrics_running(void);
const vox_run_t *vox_metrics_run(void);

/*
 * One frame's worth of sender-side measurement. Passed as a struct rather than
 * a positional argument list because the real/phantom split made the list long
 * enough that a transposed pair of arguments would have been silent.
 */
typedef struct {
    uint32_t seq;
    uint32_t encode_us;
    uint32_t protect_us;
    uint32_t send_us;        /* summed over every peer transmitted to */
    uint32_t send_real_us;   /* summed over real (acking) peers only */
    uint32_t air_us_max;
    uint8_t  npeer;          /* peers transmitted to this frame */
    uint8_t  nreal;          /* of which real */
    uint8_t  nfail;          /* real peers whose send did not succeed */
    size_t   on_air_bytes;   /* per unicast copy, incl. link encapsulation */
} vox_tx_sample_t;

void vox_metrics_tx(const vox_tx_sample_t *s);

void vox_metrics_rx(uint32_t seq, int64_t owd_us, uint32_t verify_us,
                    uint32_t decode_us, uint32_t rms_err,
                    uint8_t jb_depth, int8_t rssi);

void vox_metrics_tx_deadline_miss(void);

void vox_metrics_rx_reject(int kind);   /* see VOX_REJECT_* */
#define VOX_REJECT_AUTH         0
#define VOX_REJECT_REPLAY       1
#define VOX_REJECT_EPOCH        2
#define VOX_REJECT_MALFORMED    3
#define VOX_REJECT_LATE         4

/* ------------------------------------------------------------- resources */

typedef struct {
    uint32_t heap_free;
    uint32_t heap_min_ever;
    uint32_t heap_largest_block;
    /*
     * cpu*_pct is the most recent sampling window only. It is near zero in any
     * summary printed after a talk burst has ended, because the last window
     * lands on an idle board -- which is why cpu*_run_pct exists: the idle
     * counters are latched at run start and differenced at run stop, so the
     * figure covers the measured interval rather than the instant it was read.
     */
    float    cpu0_pct;
    float    cpu1_pct;
    float    cpu0_run_pct;
    float    cpu1_run_pct;
    bool     cpu_run_valid;
    uint32_t rx_queue_peak;
} vox_res_t;

void vox_metrics_sample_resources(void);
void vox_metrics_res(vox_res_t *out);

/* --------------------------------------------------------------- reports */

/* Configuration and platform identification: the header every run must carry
 * for its numbers to mean anything outside this board. */
void vox_metrics_print_header(const char *label);

/* Aggregate summary, human readable. */
void vox_metrics_print_summary(void);

/*
 * Machine-readable summary: every aggregate the study needs, as
 * "#SUMMARY,key=value,..." lines. This is the contract tools/parse_telemetry.py
 * reads. The human summary above it is for the operator; scraping prose for
 * numbers produced column names that changed with their own values, so the
 * numbers now have a format of their own.
 */
void vox_metrics_print_summary_kv(void);

/* Machine-readable dumps for tools/parse_telemetry.py. */
void vox_metrics_dump_csv(void);
void vox_metrics_dump_hist(void);
void vox_metrics_dump_tasks(void);
