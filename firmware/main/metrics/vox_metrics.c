#include <string.h>
#include <stdlib.h>          /* llabs */
#include <math.h>
#include <stdio.h>
#include "metrics/vox_metrics.h"
#include "net/vox_link.h"
#include "sec/vox_session.h"
#include "sec/vox_group.h"
#include "sec/vox_security.h"
#include "audio/vox_codec.h"
#include "audio/vox_audio.h"
#include "audio/vox_jitterbuf.h"
#include "vox_config.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_app_desc.h"
#include "esp_mac.h"

static const char *TAG = "vox.metrics";

static vox_run_t   s_run;
static vox_res_t   s_res;
static char        s_label[24];

static vox_tx_rec_t s_tx_ring[VOX_TRACE_DEPTH];
static vox_rx_rec_t s_rx_ring[VOX_TRACE_DEPTH];
static uint32_t     s_tx_head, s_tx_count;
static uint32_t     s_rx_head, s_rx_count;

/* Previous frame's transit time, for inter-packet delay variation. */
static int64_t s_prev_owd_us;
static bool    s_prev_owd_valid;

/*
 * CPU accounting works by differencing the idle tasks' run-time counters
 * between two instants. A latch is one such instant; the run-window figure is
 * the difference between the latch taken at `run start` and the one taken at
 * `run stop`. Declared here because run control needs them and the sampler
 * implements them further down.
 */
typedef struct {
    uint32_t idle[2];
    uint32_t total;
    bool     per_core;
    bool     valid;
} vox_cpu_latch_t;

static vox_cpu_latch_t s_cpu_run_base;

static void cpu_latch(vox_cpu_latch_t *out);
static void cpu_window(const vox_cpu_latch_t *a, const vox_cpu_latch_t *b,
                       float *cpu0_pct, float *cpu1_pct, bool *valid);

/* ------------------------------------------------------------ stats maths */

void vox_stat_reset(vox_stat_t *s)
{
    s->n = 0; s->sum = 0; s->sumsq = 0;
    s->min = INT32_MAX; s->max = INT32_MIN;
}

void vox_stat_add(vox_stat_t *s, int32_t v)
{
    s->n++;
    s->sum   += v;
    s->sumsq += (int64_t)v * (int64_t)v;
    if (v < s->min) s->min = v;
    if (v > s->max) s->max = v;
}

double vox_stat_mean(const vox_stat_t *s)
{
    return (s->n == 0) ? 0.0 : (double)s->sum / (double)s->n;
}

double vox_stat_sd(const vox_stat_t *s)
{
    if (s->n < 2) {
        return 0.0;
    }
    double m  = vox_stat_mean(s);
    double var = ((double)s->sumsq / (double)s->n) - (m * m);
    return (var > 0.0) ? sqrt(var) : 0.0;
}

/* ------------------------------------------------------------- run control */

esp_err_t vox_metrics_init(void)
{
    memset(&s_run, 0, sizeof(s_run));
    memset(&s_res, 0, sizeof(s_res));
    s_res.heap_min_ever = UINT32_MAX;
    return ESP_OK;
}

static void vox_metrics_run_start_impl(const char *label)
{
    memset(&s_run, 0, sizeof(s_run));
    vox_stat_reset(&s_run.encode_us);
    vox_stat_reset(&s_run.protect_us);
    vox_stat_reset(&s_run.send_us);
    vox_stat_reset(&s_run.send_per_peer_us);
    vox_stat_reset(&s_run.send_real_us);
    vox_stat_reset(&s_run.send_real_per_peer_us);
    vox_stat_reset(&s_run.send_phantom_per_peer_us);
    vox_stat_reset(&s_run.verify_us);
    vox_stat_reset(&s_run.decode_us);
    vox_stat_reset(&s_run.owd_us);
    vox_stat_reset(&s_run.ipdv_us);
    vox_stat_reset(&s_run.frame_rms_err);

    s_tx_head = s_tx_count = 0;
    s_rx_head = s_rx_count = 0;
    s_prev_owd_valid = false;
    s_res.heap_min_ever = UINT32_MAX;
    s_res.rx_queue_peak = 0;

    /*
     * Latch the idle-task run-time counters so CPU can be reported over the
     * whole run rather than over whichever 50 ms window happened to be the
     * last one sampled. Without this the figure is read on an idle board --
     * the burst has already ended by the time `run stop` is typed -- and every
     * run reports 0.0 %.
     */
    cpu_latch(&s_cpu_run_base);
    s_res.cpu_run_valid = false;
    s_res.cpu0_run_pct  = 0.0f;
    s_res.cpu1_run_pct  = 0.0f;

    snprintf(s_label, sizeof(s_label), "%s", (label != NULL) ? label : "run");

    vox_link_stats_reset();
    vox_jb_reset();

    s_run.t_start_us = esp_timer_get_time();
    s_run.running    = true;
}

static void vox_metrics_run_stop_impl(void)
{
    if (!s_run.running) {
        return;
    }
    s_run.t_stop_us = esp_timer_get_time();
    s_run.running   = false;

    /* Difference the latched idle counters: whatever idle did not consume over
     * the run, the application did. */
    vox_cpu_latch_t now;
    cpu_latch(&now);
    cpu_window(&s_cpu_run_base, &now,
               &s_res.cpu0_run_pct, &s_res.cpu1_run_pct, &s_res.cpu_run_valid);
}

bool vox_metrics_running(void) { vox_security_lock(); bool v=s_run.running; vox_security_unlock(); return v; }
const vox_run_t *vox_metrics_run(void)  { return &s_run; }

/* --------------------------------------------------------------- capture */

static void vox_metrics_tx_impl(const vox_tx_sample_t *s)
{
    if (!s_run.running || s == NULL) {
        return;
    }
    vox_stat_add(&s_run.encode_us,  (int32_t)s->encode_us);
    vox_stat_add(&s_run.protect_us, (int32_t)s->protect_us);
    vox_stat_add(&s_run.send_us,    (int32_t)s->send_us);
    if (s->npeer > 0) {
        vox_stat_add(&s_run.send_per_peer_us, (int32_t)(s->send_us / s->npeer));
    }

    /*
     * Real and phantom transmit cost are accumulated apart. A phantom send
     * waits out the MAC retry budget for an address nobody answers; a real
     * send completes on an acknowledgement. Averaged together they describe
     * neither, so the per-listener figure the study quotes comes from the real
     * peers only, even in a phantom-assisted run.
     */
    uint8_t nreal = (s->nreal > s->npeer) ? s->npeer : s->nreal;
    uint8_t nphantom = (uint8_t)(s->npeer - nreal);
    if (nreal > 0) {
        vox_stat_add(&s_run.send_real_us, (int32_t)s->send_real_us);
        vox_stat_add(&s_run.send_real_per_peer_us,
                     (int32_t)(s->send_real_us / nreal));
    }
    if (nphantom > 0) {
        uint32_t phantom_us = (s->send_us > s->send_real_us)
                            ? (s->send_us - s->send_real_us) : 0;
        vox_stat_add(&s_run.send_phantom_per_peer_us,
                     (int32_t)(phantom_us / nphantom));
    }

    int64_t now = esp_timer_get_time();
    if (s_run.tx_frames == 0) {
        s_run.t_first_tx_us = now;
    }
    s_run.t_last_tx_us = now;

    s_run.tx_frames++;
    s_run.tx_unicasts          += s->npeer;
    s_run.tx_real_unicasts     += nreal;
    s_run.tx_phantom_unicasts  += nphantom;
    s_run.tx_send_fail         += s->nfail;
    s_run.tx_air_bytes         += (uint64_t)s->on_air_bytes * (uint64_t)s->npeer;

    vox_tx_rec_t *r = &s_tx_ring[s_tx_head];
    r->seq        = s->seq;
    r->encode_us  = (uint16_t)(s->encode_us  > 65535 ? 65535 : s->encode_us);
    r->protect_us = (uint16_t)(s->protect_us > 65535 ? 65535 : s->protect_us);
    r->send_us    = s->send_us;
    r->air_us_max = s->air_us_max;
    r->npeer      = s->npeer;
    r->nfail      = s->nfail;
    r->nreal      = nreal;

    s_tx_head = (s_tx_head + 1) % VOX_TRACE_DEPTH;
    if (s_tx_count < VOX_TRACE_DEPTH) {
        s_tx_count++;
    }
}

static void vox_metrics_rx_impl(uint32_t seq, int64_t owd_us, uint32_t verify_us,
                    uint32_t decode_us, uint32_t rms_err,
                    uint8_t jb_depth, int8_t rssi)
{
    if (!s_run.running) {
        return;
    }
    vox_stat_add(&s_run.verify_us, (int32_t)verify_us);
    vox_stat_add(&s_run.decode_us, (int32_t)decode_us);
    s_run.rx_frames++;

    /*
     * A one-way delay is only meaningful once the clock offset estimator has
     * converged; before that owd_us arrives as INT64_MIN and is excluded
     * rather than silently recorded as zero.
     */
    if (owd_us != INT64_MIN) {
        int32_t owd = (int32_t)owd_us;
        vox_stat_add(&s_run.owd_us, owd);

        int bin = (int)(owd / VOX_HIST_BIN_US);
        if (bin < 0) bin = 0;
        if (bin > VOX_HIST_BINS) bin = VOX_HIST_BINS;
        if (s_run.owd_hist[bin] < UINT16_MAX) {
            s_run.owd_hist[bin]++;
        }

        if (owd > 150000) {
            s_run.owd_over_budget++;    /* above the G.114 one-way target */
        }

        if (s_prev_owd_valid) {
            int32_t d = (int32_t)llabs(owd_us - s_prev_owd_us);
            vox_stat_add(&s_run.ipdv_us, d);
            /* RFC 3550 smoothed jitter: J += (|D| - J) / 16 */
            s_run.rtp_jitter_us += ((double)d - s_run.rtp_jitter_us) / 16.0;
        }
        s_prev_owd_us    = owd_us;
        s_prev_owd_valid = true;
    }

    if (rms_err != UINT32_MAX) {
        vox_stat_add(&s_run.frame_rms_err, (int32_t)rms_err);
        s_run.frames_compared++;
        if (rms_err == 0) {
            s_run.frames_bitexact++;
        }
    }

    vox_rx_rec_t *r = &s_rx_ring[s_rx_head];
    r->seq       = seq;
    r->owd_us    = (owd_us == INT64_MIN) ? INT32_MIN : (int32_t)owd_us;
    r->verify_us = (uint16_t)(verify_us > 65535 ? 65535 : verify_us);
    r->decode_us = (uint16_t)(decode_us > 65535 ? 65535 : decode_us);
    r->rms_err   = (uint16_t)(rms_err > 65535 ? 65535 : rms_err);
    r->jb_depth  = jb_depth;
    r->rssi      = rssi;

    s_rx_head = (s_rx_head + 1) % VOX_TRACE_DEPTH;
    if (s_rx_count < VOX_TRACE_DEPTH) {
        s_rx_count++;
    }
}

static void vox_metrics_tx_deadline_miss_impl(void)
{
    if (s_run.running) {
        s_run.tx_deadline_miss++;
    }
}

static void vox_metrics_rx_reject_impl(int kind)
{
    if (!s_run.running) {
        return;
    }
    switch (kind) {
    case VOX_REJECT_AUTH:      s_run.rx_auth_fail++;      break;
    case VOX_REJECT_REPLAY:    s_run.rx_replay_drop++;    break;
    case VOX_REJECT_EPOCH:     s_run.rx_epoch_unknown++;  break;
    case VOX_REJECT_MALFORMED: s_run.rx_malformed++;      break;
    case VOX_REJECT_LATE:      s_run.rx_late++;           break;
    default: break;
    }
}

/* ------------------------------------------------------------- resources */

#define MAX_TASKS 24
static vox_cpu_latch_t s_cpu_prev;

/*
 * Which core a task ran on. ESP-IDF's own FreeRTOS exposes TaskStatus_t.xCoreID;
 * the upstream SMP scheduler (CONFIG_FREERTOS_SMP) replaces it with an affinity
 * mask and tasks are not pinned by default. Rather than fail to build on one of
 * them, resolve it here and let the caller handle "unknown" honestly. Returns
 * -1 when the core cannot be determined.
 */
static int task_core_of(const TaskStatus_t *t)
{
#if defined(CONFIG_FREERTOS_SMP)
    (void)t;
    return -1;
#else
    return (t->xCoreID >= 0 && t->xCoreID < 2) ? (int)t->xCoreID : -1;
#endif
}

/*
 * Take one reading of the idle tasks' run-time counters. Everything CPU-related
 * is a difference between two of these, so nothing here interprets the numbers.
 */
static void cpu_latch(vox_cpu_latch_t *out)
{
    memset(out, 0, sizeof(*out));
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    TaskStatus_t st[MAX_TASKS];
    uint32_t total = 0;
    UBaseType_t n = uxTaskGetSystemState(st, MAX_TASKS, &total);

    out->per_core = true;
    for (UBaseType_t i = 0; i < n; i++) {
        if (strncmp(st[i].pcTaskName, "IDLE", 4) != 0) {
            continue;
        }
        int core = task_core_of(&st[i]);
        if (core < 0) {
            out->per_core = false;
            out->idle[0] += st[i].ulRunTimeCounter;
        } else {
            out->idle[core] += st[i].ulRunTimeCounter;
        }
    }
    out->total = total;
    out->valid = true;
#endif
}

/*
 * Utilisation between two latches: whatever the idle task on a core did not
 * consume during the interval, the application did. When the core of an idle
 * task cannot be determined, both are pooled and the same aggregate figure is
 * reported for each, which is the honest reading rather than a fabricated
 * split.
 */
static void cpu_window(const vox_cpu_latch_t *a, const vox_cpu_latch_t *b,
                       float *cpu0_pct, float *cpu1_pct, bool *valid)
{
    *valid = false;
    *cpu0_pct = 0.0f;
    *cpu1_pct = 0.0f;

    if (!a->valid || !b->valid || b->total <= a->total) {
        return;
    }
    uint32_t dt = b->total - a->total;
    float d0 = (float)(b->idle[0] - a->idle[0]);
    float d1 = (float)(b->idle[1] - a->idle[1]);

    if (a->per_core && b->per_core) {
        /*
         * ulTotalRunTime is wall clock (esp_timer microseconds), NOT the sum
         * across cores, and each core's idle task accumulates against that
         * same wall clock. So a core's idle share is idle/dt, and dividing by
         * dt/2 instead reported 1 - 2*(idle/dt): a genuinely 30 %-busy core
         * came out negative and clamped to 0.0, which is why every run read
         * zero CPU.
         */
        *cpu0_pct = 100.0f * (1.0f - (d0 / (float)dt));
        *cpu1_pct = 100.0f * (1.0f - (d1 / (float)dt));
    } else {
        /* Core unknown, so both idle tasks were pooled into d0 and the total
         * available idle time across two cores is 2*dt. This is the branch
         * that needs the halving. */
        float pooled = 100.0f * (1.0f - (d0 / (2.0f * (float)dt)));
        *cpu0_pct = pooled;
        *cpu1_pct = pooled;
    }
    if (*cpu0_pct < 0.0f) *cpu0_pct = 0.0f;
    if (*cpu1_pct < 0.0f) *cpu1_pct = 0.0f;
    if (*cpu0_pct > 100.0f) *cpu0_pct = 100.0f;
    if (*cpu1_pct > 100.0f) *cpu1_pct = 100.0f;
    *valid = true;
}

static void vox_metrics_sample_resources_impl(void)
{
    s_res.heap_free          = (uint32_t)esp_get_free_heap_size();
    s_res.heap_largest_block = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

    uint32_t min_ever = (uint32_t)esp_get_minimum_free_heap_size();
    if (min_ever < s_res.heap_min_ever) {
        s_res.heap_min_ever = min_ever;
    }

    /*
     * The instantaneous figure, over one sampling period. Useful for a live
     * `stats` while a burst is running; useless in a summary printed after it,
     * which is what cpu*_run_pct is for.
     */
    vox_cpu_latch_t now;
    cpu_latch(&now);
    bool ok = false;
    cpu_window(&s_cpu_prev, &now, &s_res.cpu0_pct, &s_res.cpu1_pct, &ok);
    s_cpu_prev = now;

    /*
     * Keep the run-window figure current while the run is open, so `stats` can
     * show a meaningful number without stopping the run. run_stop takes its own
     * final latch.
     */
    if (s_run.running) {
        cpu_window(&s_cpu_run_base, &now,
                   &s_res.cpu0_run_pct, &s_res.cpu1_run_pct, &s_res.cpu_run_valid);
    }
}

static void vox_metrics_res_impl(vox_res_t *out)
{
    *out = s_res;
}

/* --------------------------------------------------------------- reports */

static void vox_metrics_print_header_impl(const char *label)
{
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();
    const uint8_t *mac = vox_link_self_mac();

    printf("#RUN,label=%s\n", (label != NULL) ? label : s_label);
    printf("#PLATFORM,chip=ESP32,cores=%d,rev=%d,idf=%s,app_ver=%s,built=%s %s\n",
           chip.cores, chip.revision, IDF_VER, app->version, app->date, app->time);
    /*
     * Build flags are resolved into ordinary variables first. Preprocessor
     * directives inside a function-call argument list are undefined behaviour
     * when the callee turns out to be a macro, which printf is permitted to be.
     */
#ifdef CONFIG_VOX_ROLE_TALKER
    const int role_tx = 1;
#else
    const int role_tx = 0;
#endif
#ifdef CONFIG_VOX_ROLE_LISTENER
    const int role_rx = 1;
#else
    const int role_rx = 0;
#endif
#ifdef CONFIG_VOX_CRYPTO_ENABLED
    const int crypto_on = 1;
#else
    const int crypto_on = 0;
#endif

    printf("#NODE,id=%u,mac=" MACSTR ",role_tx=%d,role_rx=%d\n",
           VOX_NODE_ID, MAC2STR(mac), role_tx, role_rx);
    printf("#AUDIO,src=%s,sink=%s,rate=%d,frame_ms=%d,samples=%d,codec=%s,"
           "encoded_bytes=%d,bitrate=%u\n",
           vox_audio_src_name(), vox_audio_sink_name(),
           VOX_SAMPLE_RATE_HZ, VOX_FRAME_MS, VOX_SAMPLES_PER_FRAME,
           vox_codec()->name, (int)vox_codec()->encoded_bytes,
           (unsigned)vox_codec()->bitrate_bps);
    printf("#FRAME,hdr=%d,plaintext=%d,tag=%d,on_air=%d,link_overhead=%d,total=%d\n",
           VOX_HDR_LEN, VOX_AUDIO_PLAINTEXT, VOX_TAG_LEN, VOX_ON_AIR_BYTES,
           VOX_LINK_OVERHEAD_BYTES, VOX_ON_AIR_BYTES + VOX_LINK_OVERHEAD_BYTES);
    printf("#SEC,crypto=%d,aead=%s,tag_len=%d,replay_window=%d,epoch_limit=%u\n",
           crypto_on, vox_aead_name(), VOX_TAG_LEN, VOX_REPLAY_WINDOW,
           (unsigned)VOX_EPOCH_MAX_FRAMES);
    printf("#JITTER,target=%d,capacity=%d,target_ms=%d,bytes=%d\n",
           CONFIG_VOX_JITTER_TARGET_FRAMES, CONFIG_VOX_JITTER_MAX_FRAMES,
           CONFIG_VOX_JITTER_TARGET_FRAMES * VOX_FRAME_MS, (int)vox_jb_bytes());
    printf("#PEERS,total=%d,real=%d,phantom=%d,state_bytes=%d,bytes_per_peer=%d\n",
           vox_peer_count(), vox_peer_count_real(),
           vox_peer_count() - vox_peer_count_real(),
           (int)vox_session_state_bytes(), (int)vox_session_bytes_per_peer());
    printf("#WIFI,channel=%d,ps=none\n", VOX_WIFI_CHANNEL);
}

/*
 * A vox_stat_t with no samples has min = INT32_MAX and max = INT32_MIN, which
 * printed straight out as "min 2147483647  max -2147483648" in every run where
 * one direction was idle. Those reached the parsed CSVs and read as data.
 */
static void print_stat_us(const char *label, const vox_stat_t *s, const char *note)
{
    if (s->n == 0) {
        printf("%-21s no samples%s\n", label, note);
        return;
    }
    printf("%-21s mean %.1f  sd %.1f  min %d  max %d  n=%u%s\n",
           label, vox_stat_mean(s), vox_stat_sd(s),
           (int)s->min, (int)s->max, (unsigned)s->n, note);
}

static void vox_metrics_print_summary_impl(void)
{
    const vox_run_t *r = &s_run;
    double dur_s = (double)((r->t_stop_us ? r->t_stop_us : esp_timer_get_time())
                            - r->t_start_us) / 1e6;
    if (dur_s <= 0.0) dur_s = 1e-9;

    vox_link_stats_t ls;
    vox_link_stats(&ls);
    vox_jb_stats_t jb;
    vox_jb_stats(&jb);

    printf("\n===== run summary: %s =====\n", s_label);
    printf("duration              %.2f s\n", dur_s);

    printf("\n-- sender --\n");
    /*
     * Two frame rates, because one of them was being misread. The run window
     * includes the setup and teardown either side of the burst, so dividing by
     * it understates the rate a 30 s burst inside a 34 s window reports as
     * 43.7 f/s when it actually ran at 50. The nominal rate is what the frame
     * interval demands; the achieved rate is frames divided by the time the
     * sender was actually talking.
     */
    double nominal_fps = 1000.0 / (double)VOX_FRAME_MS;
    double span_s = (r->tx_frames > 1)
        ? (double)(r->t_last_tx_us - r->t_first_tx_us) / 1e6 : 0.0;
    double achieved = (span_s > 0.0) ? (double)(r->tx_frames - 1) / span_s : 0.0;
    printf("frames                %u  (%.2f /s achieved vs %.2f /s nominal "
           "over a %.2f s burst; %.1f /s across the whole %.1f s window)\n",
           (unsigned)r->tx_frames, achieved, nominal_fps, span_s,
           (double)r->tx_frames / dur_s, dur_s);
    if (span_s > 0.0 && achieved < nominal_fps * 0.995) {
        printf("  SENDER BEHIND       produced %.0f fewer frames than the burst "
               "called for; it is no longer sustaining the frame rate\n",
               span_s * nominal_fps - (double)(r->tx_frames - 1));
    }
    printf("unicast transmissions %u  (%.2f per frame;  real %u  phantom %u)\n",
           (unsigned)r->tx_unicasts,
           r->tx_frames ? (double)r->tx_unicasts / (double)r->tx_frames : 0.0,
           (unsigned)r->tx_real_unicasts, (unsigned)r->tx_phantom_unicasts);
    print_stat_us("encode   us/frame", &r->encode_us, "");
    print_stat_us("protect  us/frame", &r->protect_us, "   (all peers)");
    print_stat_us("transmit us/frame", &r->send_us, "   (all peers)");
    printf("transmit us/peer      all %.1f   real %.1f   phantom %.1f\n",
           vox_stat_mean(&r->send_per_peer_us),
           vox_stat_mean(&r->send_real_per_peer_us),
           vox_stat_mean(&r->send_phantom_per_peer_us));
    if (r->tx_phantom_unicasts > 0) {
        printf("  NOTE: phantom peers never acknowledge, so their transmit cost\n"
               "        is a MAC retry timeout, not a per-listener cost. Quote\n"
               "        the 'real' column for per-listener transmit time.\n");
    }
    printf("send failures         %u\n", (unsigned)r->tx_send_fail);
    /*
     * The receiver count at which the sender can no longer fit N protects plus
     * N sends inside one frame interval is the direct answer to RQ1, so it is
     * printed here rather than left in a counter nothing reads.
     */
    printf("frame deadline misses %u of %u  (%.2f %%)   [budget %d ms/frame]\n",
           (unsigned)r->tx_deadline_miss, (unsigned)r->tx_frames,
           r->tx_frames ? 100.0 * (double)r->tx_deadline_miss / (double)r->tx_frames : 0.0,
           VOX_FRAME_MS);
    printf("offered air bytes     %llu  (%.1f kB/s incl. %d B link overhead)\n",
           (unsigned long long)r->tx_air_bytes,
           (double)r->tx_air_bytes / dur_s / 1024.0, VOX_LINK_OVERHEAD_BYTES);

    printf("\n-- receiver --\n");
    printf("frames accepted       %u  (%.1f /s over the window)\n",
           (unsigned)r->rx_frames, (double)r->rx_frames / dur_s);
    print_stat_us("verify  us/frame", &r->verify_us, "");
    print_stat_us("decode  us/frame", &r->decode_us, "");

    if (r->owd_us.n > 0) {
        printf("one-way delay ms      mean %.2f  sd %.2f  min %.2f  max %.2f  n=%u\n",
               vox_stat_mean(&r->owd_us) / 1000.0, vox_stat_sd(&r->owd_us) / 1000.0,
               (double)r->owd_us.min / 1000.0, (double)r->owd_us.max / 1000.0,
               (unsigned)r->owd_us.n);
        printf("  over 150 ms budget  %u  (%.2f %%)   [G.114 target]\n",
               (unsigned)r->owd_over_budget,
               100.0 * (double)r->owd_over_budget / (double)r->owd_us.n);
        printf("ipdv ms               mean %.2f  max %.2f\n",
               vox_stat_mean(&r->ipdv_us) / 1000.0, (double)r->ipdv_us.max / 1000.0);
        printf("rfc3550 jitter ms     %.2f   [NIST target < 40 ms]\n",
               r->rtp_jitter_us / 1000.0);
    } else {
        printf("one-way delay         no samples (clock offset not converged, or rx-only idle)\n");
    }

    printf("\n-- security events --\n");
    printf("auth failures         %u\n", (unsigned)r->rx_auth_fail);
    printf("replay rejects        %u\n", (unsigned)r->rx_replay_drop);
    printf("unknown epoch         %u\n", (unsigned)r->rx_epoch_unknown);
    printf("malformed             %u\n", (unsigned)r->rx_malformed);
    printf("late rejects          %u\n", (unsigned)r->rx_late);

    printf("\n-- delivery --\n");
    uint32_t expected = jb.media_expected;
    if (expected > 0) {
        printf("played / concealed    %u / %u  (media-index loss %.3f %%)\n",
               (unsigned)jb.popped, (unsigned)jb.concealed,
               100.0 * (double)(expected-jb.media_received) / (double)expected);
    } else {
        /*
         * A talker-only log has nothing to lose. Printing "loss 0.000 %" made
         * the analysis record a clean pass against the NIST target from no
         * evidence at all.
         */
        printf("played / concealed    0 / 0  (no delivery evidence in this run)\n");
    }
    printf("late / dup / overflow %u / %u / %u\n",
           (unsigned)jb.late, (unsigned)jb.duplicate, (unsigned)jb.overflow);
    printf("jb resyncs / max depth %u / %u\n",
           (unsigned)jb.resyncs, (unsigned)jb.max_depth);

    if (r->frames_compared > 0) {
        printf("\n-- fidelity vs deterministic reference --\n");
        printf("frames compared       %u\n", (unsigned)r->frames_compared);
        printf("bit-exact             %u  (%.1f %%)\n",
               (unsigned)r->frames_bitexact,
               100.0 * (double)r->frames_bitexact / (double)r->frames_compared);
        printf("rms error             mean %.1f  max %d  (of 32768 full scale)\n",
               vox_stat_mean(&r->frame_rms_err), (int)r->frame_rms_err.max);
    }

    printf("\n-- link --\n");
    printf("tx calls %u  cb ok %u  cb fail %u  enqueue err %u  timeout %u\n",
           (unsigned)ls.tx_calls, (unsigned)ls.tx_cb_ok, (unsigned)ls.tx_cb_fail,
           (unsigned)ls.tx_enqueue_err, (unsigned)ls.tx_timeout);
    printf("rx frames %u  queue drops %u\n",
           (unsigned)ls.rx_frames, (unsigned)ls.rx_queue_drop);

    printf("\n-- resources --\n");
    printf("heap free %u  min ever %u  largest block %u\n",
           (unsigned)s_res.heap_free, (unsigned)s_res.heap_min_ever,
           (unsigned)s_res.heap_largest_block);
    if (s_res.cpu_run_valid) {
        printf("cpu over run   core0 %.1f %%  core1 %.1f %%\n",
               s_res.cpu0_run_pct, s_res.cpu1_run_pct);
    } else {
        printf("cpu over run   unavailable (needs CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS)\n");
    }
    printf("cpu last sample core0 %.1f %%  core1 %.1f %%   (idle window, not the run)\n",
           s_res.cpu0_pct, s_res.cpu1_pct);
    printf("peer state %d B total, %d B per peer, %d peers (%d real, %d phantom)\n",
           (int)vox_session_state_bytes(), (int)vox_session_bytes_per_peer(),
           vox_peer_count(), vox_peer_count_real(),
           vox_peer_count() - vox_peer_count_real());
    printf("=====================================\n\n");

    vox_metrics_print_summary_kv();
}

/*
 * Machine-readable twin of the block above. Emitted as several "#SUMMARY,k=v"
 * lines so the existing "#SECTION,k=v" parser picks them up unchanged and
 * merges them into one namespace.
 *
 * This exists because the host used to recover these numbers by regex over the
 * human summary, which produced column names containing their own values
 * ("fw_tx_calls_1447") and silently dropped any line whose label was followed
 * by a single space -- which is how key state, the one RQ1 metric measured
 * exactly on chip, reached no table at all.
 *
 * Counts are authoritative: a mean whose *_n is 0 carries no information, and
 * the host must check the count rather than treat 0.0 as a measurement.
 */
static void vox_metrics_print_summary_kv_impl(void)
{
    const vox_run_t *r = &s_run;
    double dur_s = (double)((r->t_stop_us ? r->t_stop_us : esp_timer_get_time())
                            - r->t_start_us) / 1e6;
    if (dur_s <= 0.0) dur_s = 1e-9;

    vox_link_stats_t ls;
    vox_link_stats(&ls);
    vox_jb_stats_t jb;
    vox_jb_stats(&jb);

    double nominal_fps = 1000.0 / (double)VOX_FRAME_MS;
    double span_s = (r->tx_frames > 1)
        ? (double)(r->t_last_tx_us - r->t_first_tx_us) / 1e6 : 0.0;
    double achieved = (span_s > 0.0) ? (double)(r->tx_frames - 1) / span_s : 0.0;
    uint32_t expected = jb.media_expected;

    printf("#SUMMARY,protocol=%u,measurement_schema=2,owd_scope=capture_start_to_radio_rx,loss_complete=%d,media_expected=%u,media_received=%u,silence_ticks=%u\n",
        VOX_PROTO_VERSION,vox_jb_loss_complete(),(unsigned)jb.media_expected,
        (unsigned)jb.media_received,(unsigned)jb.silence_ticks);
    vox_security_lock();
    printf("#SUMMARY,peer_static_bytes=%u,group_static_bytes=%u,group_active_bytes=%u,group_members=%d,group_listeners=%d\n",
        (unsigned)vox_session_allocated_bytes(),(unsigned)vox_group_state_bytes(),
        (unsigned)vox_group_active_state_bytes(),vox_group_member_count(),
        vox_group_member_count()>0?vox_group_member_count()-1:0);
    vox_security_unlock();
    printf("#SUMMARY,label=%s,duration_s=%.3f,frame_ms=%d,nominal_fps=%.2f\n",
           s_label, dur_s, VOX_FRAME_MS, nominal_fps);

    printf("#SUMMARY,tx_frames=%u,tx_fps_achieved=%.3f,tx_burst_s=%.3f,"
           "tx_rate_deficit_pct=%.3f,tx_unicasts=%u,"
           "tx_real_unicasts=%u,tx_phantom_unicasts=%u,tx_send_fail=%u\n",
           (unsigned)r->tx_frames, achieved, span_s,
           (achieved > 0.0) ? 100.0 * (1.0 - achieved / nominal_fps) : 0.0,
           (unsigned)r->tx_unicasts, (unsigned)r->tx_real_unicasts,
           (unsigned)r->tx_phantom_unicasts, (unsigned)r->tx_send_fail);

    printf("#SUMMARY,encode_us_mean=%.2f,encode_us_sd=%.2f,encode_us_min=%d,"
           "encode_us_max=%d,encode_n=%u\n",
           vox_stat_mean(&r->encode_us), vox_stat_sd(&r->encode_us),
           r->encode_us.n ? (int)r->encode_us.min : 0,
           r->encode_us.n ? (int)r->encode_us.max : 0,
           (unsigned)r->encode_us.n);

    printf("#SUMMARY,protect_us_mean=%.2f,protect_us_sd=%.2f,protect_us_min=%d,"
           "protect_us_max=%d,protect_n=%u\n",
           vox_stat_mean(&r->protect_us), vox_stat_sd(&r->protect_us),
           r->protect_us.n ? (int)r->protect_us.min : 0,
           r->protect_us.n ? (int)r->protect_us.max : 0,
           (unsigned)r->protect_us.n);

    printf("#SUMMARY,send_us_mean=%.2f,send_us_sd=%.2f,send_us_max=%d,send_n=%u,"
           "send_us_per_peer=%.2f,send_real_us_per_peer=%.2f,"
           "send_phantom_us_per_peer=%.2f,send_real_n=%u,send_phantom_n=%u\n",
           vox_stat_mean(&r->send_us), vox_stat_sd(&r->send_us),
           r->send_us.n ? (int)r->send_us.max : 0, (unsigned)r->send_us.n,
           vox_stat_mean(&r->send_per_peer_us),
           vox_stat_mean(&r->send_real_per_peer_us),
           vox_stat_mean(&r->send_phantom_per_peer_us),
           (unsigned)r->send_real_per_peer_us.n,
           (unsigned)r->send_phantom_per_peer_us.n);

    printf("#SUMMARY,deadline_miss=%u,deadline_miss_pct=%.3f,air_bytes=%llu,"
           "air_bytes_per_s=%.1f,link_overhead_b=%d,on_air_b=%d\n",
           (unsigned)r->tx_deadline_miss,
           r->tx_frames ? 100.0 * (double)r->tx_deadline_miss / (double)r->tx_frames : 0.0,
           (unsigned long long)r->tx_air_bytes,
           (double)r->tx_air_bytes / dur_s,
           VOX_LINK_OVERHEAD_BYTES, VOX_ON_AIR_BYTES);

    printf("#SUMMARY,rx_frames=%u,verify_us_mean=%.2f,verify_us_sd=%.2f,"
           "verify_us_max=%d,verify_n=%u,decode_us_mean=%.2f,decode_us_sd=%.2f,"
           "decode_us_max=%d,decode_n=%u\n",
           (unsigned)r->rx_frames,
           vox_stat_mean(&r->verify_us), vox_stat_sd(&r->verify_us),
           r->verify_us.n ? (int)r->verify_us.max : 0, (unsigned)r->verify_us.n,
           vox_stat_mean(&r->decode_us), vox_stat_sd(&r->decode_us),
           r->decode_us.n ? (int)r->decode_us.max : 0, (unsigned)r->decode_us.n);

    printf("#SUMMARY,owd_n=%u,owd_mean_ms=%.3f,owd_sd_ms=%.3f,owd_min_ms=%.3f,"
           "owd_max_ms=%.3f,owd_over_budget=%u,ipdv_mean_ms=%.3f,ipdv_max_ms=%.3f,"
           "rfc3550_jitter_ms=%.3f\n",
           (unsigned)r->owd_us.n,
           r->owd_us.n ? vox_stat_mean(&r->owd_us) / 1000.0 : 0.0,
           r->owd_us.n ? vox_stat_sd(&r->owd_us) / 1000.0 : 0.0,
           r->owd_us.n ? (double)r->owd_us.min / 1000.0 : 0.0,
           r->owd_us.n ? (double)r->owd_us.max / 1000.0 : 0.0,
           (unsigned)r->owd_over_budget,
           r->ipdv_us.n ? vox_stat_mean(&r->ipdv_us) / 1000.0 : 0.0,
           r->ipdv_us.n ? (double)r->ipdv_us.max / 1000.0 : 0.0,
           r->rtp_jitter_us / 1000.0);

    printf("#SUMMARY,auth_fail=%u,replay_drop=%u,epoch_unknown=%u,malformed=%u,"
           "late_reject=%u\n",
           (unsigned)r->rx_auth_fail, (unsigned)r->rx_replay_drop,
           (unsigned)r->rx_epoch_unknown, (unsigned)r->rx_malformed,
           (unsigned)r->rx_late);

    /* delivery_n = 0 means "no delivery evidence"; loss_pct is then meaningless
     * and the host must print n/a rather than a passing 0.000. */
    printf("#SUMMARY,playout_loss_pct=%.4f,playout_loss_complete=%d\n",
           expected ? 100.0*(double)(expected-jb.popped)/(double)expected : 0.0,
           vox_jb_loss_complete());
    printf("#SUMMARY,delivery_n=%u,jb_played=%u,jb_concealed=%u,loss_pct=%.4f,"
           "jb_late=%u,jb_dup=%u,jb_overflow=%u,jb_resyncs=%u,jb_max_depth=%u\n",
           (unsigned)expected, (unsigned)jb.popped, (unsigned)jb.concealed,
           expected ? 100.0 * (double)(expected-jb.media_received) / (double)expected : 0.0,
           (unsigned)jb.late, (unsigned)jb.duplicate, (unsigned)jb.overflow,
           (unsigned)jb.resyncs, (unsigned)jb.max_depth);

    printf("#SUMMARY,tx_calls=%u,tx_cb_ok=%u,tx_cb_fail=%u,tx_enqueue_err=%u,"
           "tx_timeout=%u,link_rx_frames=%u,rx_queue_drop=%u\n",
           (unsigned)ls.tx_calls, (unsigned)ls.tx_cb_ok, (unsigned)ls.tx_cb_fail,
           (unsigned)ls.tx_enqueue_err, (unsigned)ls.tx_timeout,
           (unsigned)ls.rx_frames, (unsigned)ls.rx_queue_drop);

    printf("#SUMMARY,heap_free=%u,heap_min_ever=%u,heap_largest_block=%u,"
           "cpu0_run_pct=%.2f,cpu1_run_pct=%.2f,cpu_run_valid=%d,"
           "cpu0_last_pct=%.2f,cpu1_last_pct=%.2f\n",
           (unsigned)s_res.heap_free, (unsigned)s_res.heap_min_ever,
           (unsigned)s_res.heap_largest_block,
           s_res.cpu0_run_pct, s_res.cpu1_run_pct, s_res.cpu_run_valid ? 1 : 0,
           s_res.cpu0_pct, s_res.cpu1_pct);

    /* Peer census at the END of the run. The header's #PEERS line is taken at
     * `run start`, which misses any `phantom N` issued afterwards. */
    printf("#SUMMARY,peers=%d,peers_real=%d,peers_phantom=%d,peer_state_bytes=%d,"
           "peer_bytes_per_peer=%d\n",
           vox_peer_count(), vox_peer_count_real(),
           vox_peer_count() - vox_peer_count_real(),
           (int)vox_session_state_bytes(), (int)vox_session_bytes_per_peer());

    printf("#SUMMARY,frames_compared=%u,frames_bitexact=%u,rms_mean=%.2f,rms_max=%d\n",
           (unsigned)r->frames_compared, (unsigned)r->frames_bitexact,
           r->frame_rms_err.n ? vox_stat_mean(&r->frame_rms_err) : 0.0,
           r->frame_rms_err.n ? (int)r->frame_rms_err.max : 0);

    /* Trace coverage, so the host can tell a complete capture from a truncated
     * one instead of computing percentiles over whatever survived the UART. */
    printf("#SUMMARY,trace_depth=%d,tx_trace_rows=%u,rx_trace_rows=%u\n",
           VOX_TRACE_DEPTH, (unsigned)s_tx_count, (unsigned)s_rx_count);
}

static void vox_metrics_dump_csv_impl(void)
{
    /*
     * Row counts are announced before the rows so the host can tell a complete
     * capture from one the UART truncated. Without them a dump that lost 60 %
     * of its rows still parsed cleanly and its percentiles were computed over
     * whatever arrived.
     */
    printf("#CSV_BEGIN,tx_rows=%u,rx_rows=%u\n",
           (unsigned)s_tx_count, (unsigned)s_rx_count);
    printf("dir,seq,a,b,c,d,e,f,g\n");

    uint32_t start = (s_tx_count == VOX_TRACE_DEPTH) ? s_tx_head : 0;
    for (uint32_t i = 0; i < s_tx_count; i++) {
        const vox_tx_rec_t *r = &s_tx_ring[(start + i) % VOX_TRACE_DEPTH];
        /* dir,seq,encode_us,protect_us,send_us,air_us_max,npeer,nfail,nreal */
        printf("TX,%u,%u,%u,%u,%u,%u,%u,%u\n",
               (unsigned)r->seq, r->encode_us, r->protect_us,
               (unsigned)r->send_us, (unsigned)r->air_us_max,
               r->npeer, r->nfail, r->nreal);
    }

    start = (s_rx_count == VOX_TRACE_DEPTH) ? s_rx_head : 0;
    for (uint32_t i = 0; i < s_rx_count; i++) {
        const vox_rx_rec_t *r = &s_rx_ring[(start + i) % VOX_TRACE_DEPTH];
        /* dir,seq,owd_us,verify_us,decode_us,rms_err,jb_depth,rssi */
        printf("RX,%u,%d,%u,%u,%u,%u,%d\n",
               (unsigned)r->seq, (int)r->owd_us, r->verify_us, r->decode_us,
               r->rms_err, r->jb_depth, r->rssi);
    }
    printf("#CSV_END\n");
}

static void vox_metrics_dump_hist_impl(void)
{
    printf("#HIST_BEGIN,bin_us=%d,bins=%d\n", VOX_HIST_BIN_US, VOX_HIST_BINS);
    printf("bin_lo_us,bin_hi_us,count\n");
    for (int i = 0; i <= VOX_HIST_BINS; i++) {
        if (s_run.owd_hist[i] == 0) {
            continue;
        }
        if (i == VOX_HIST_BINS) {
            printf("%d,inf,%u\n", VOX_HIST_BINS * VOX_HIST_BIN_US, s_run.owd_hist[i]);
        } else {
            printf("%d,%d,%u\n", i * VOX_HIST_BIN_US, (i + 1) * VOX_HIST_BIN_US,
                   s_run.owd_hist[i]);
        }
    }
    printf("#HIST_END\n");
}

static void vox_metrics_dump_tasks_impl(void)
{
    TaskStatus_t st[MAX_TASKS];
    uint32_t total = 0;
    UBaseType_t n = uxTaskGetSystemState(st, MAX_TASKS, &total);

    printf("#TASKS_BEGIN\n");
    printf("name,prio,core,stack_hwm_bytes,runtime_ticks,runtime_pct\n");
    for (UBaseType_t i = 0; i < n; i++) {
        double pct = (total > 0) ? (100.0 * (double)st[i].ulRunTimeCounter / (double)total) : 0.0;
        int core = task_core_of(&st[i]);
        printf("%s,%u,%d,%u,%u,%.2f\n",
               st[i].pcTaskName, (unsigned)st[i].uxCurrentPriority, core,
               (unsigned)(st[i].usStackHighWaterMark * sizeof(StackType_t)),
               (unsigned)st[i].ulRunTimeCounter, pct);
    }
    printf("#TASKS_END\n");
    (void)TAG;
}

/* Serialize resets, cross-core writers and report readers. Callers stop
 * measurement before bulk UART dumps, which intentionally hold this lock. */
void vox_metrics_run_start(const char *label) { vox_security_lock(); vox_metrics_run_start_impl(label); vox_security_unlock(); }
void vox_metrics_run_stop(void) { vox_security_lock(); vox_metrics_run_stop_impl(); vox_security_unlock(); }
void vox_metrics_tx(const vox_tx_sample_t *s) { vox_security_lock(); vox_metrics_tx_impl(s); vox_security_unlock(); }
void vox_metrics_rx(uint32_t seq, int64_t owd_us, uint32_t verify_us, uint32_t decode_us, uint32_t rms_err, uint8_t jb_depth, int8_t rssi) { vox_security_lock(); vox_metrics_rx_impl(seq,owd_us,verify_us,decode_us,rms_err,jb_depth,rssi); vox_security_unlock(); }
void vox_metrics_tx_deadline_miss(void) { vox_security_lock(); vox_metrics_tx_deadline_miss_impl(); vox_security_unlock(); }
void vox_metrics_rx_reject(int kind) { vox_security_lock(); vox_metrics_rx_reject_impl(kind); vox_security_unlock(); }
void vox_metrics_sample_resources(void) { vox_security_lock(); vox_metrics_sample_resources_impl(); vox_security_unlock(); }
void vox_metrics_res(vox_res_t *out) { vox_security_lock(); vox_metrics_res_impl(out); vox_security_unlock(); }
void vox_metrics_print_header(const char *label) { vox_security_lock(); vox_metrics_print_header_impl(label); vox_security_unlock(); }
void vox_metrics_print_summary(void) { vox_security_lock(); vox_metrics_print_summary_impl(); vox_security_unlock(); }
void vox_metrics_print_summary_kv(void) { vox_security_lock(); vox_metrics_print_summary_kv_impl(); vox_security_unlock(); }
void vox_metrics_dump_csv(void) { vox_security_lock(); vox_metrics_dump_csv_impl(); vox_security_unlock(); }
void vox_metrics_dump_hist(void) { vox_security_lock(); vox_metrics_dump_hist_impl(); vox_security_unlock(); }
void vox_metrics_dump_tasks(void) { vox_security_lock(); vox_metrics_dump_tasks_impl(); vox_security_unlock(); }
