#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "vox_console.h"
#include "vox_config.h"
#include "vox_ptt.h"
#include "audio/vox_audio.h"
#include "audio/vox_jitterbuf.h"
#include "net/vox_link.h"
#include "net/vox_timesync.h"
#include "sec/vox_keys.h"
#include "sec/vox_security.h"
#include "mbedtls/platform_util.h"
#include "esp_app_desc.h"
#include "sec/vox_session.h"
#include "sec/vox_group.h"
#include "sec/vox_group_control.h"
#include "metrics/vox_metrics.h"

#include "esp_console.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_mac.h"

#include "ed25519.h"

static const char *TAG = "vox.cli";
static esp_timer_handle_t s_talk_timer;

/* ------------------------------------------------------------- utilities */

static bool parse_mac(const char *s, uint8_t out[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xFF) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

static void talk_timeout(void *arg)
{
    (void)arg;
    vox_ptt_set(false);
}

/* ------------------------------------------------------------- commands */

static int cmd_mac(int argc, char **argv)
{
    (void)argc; (void)argv;
    const uint8_t *m = vox_link_self_mac();
    printf("node %u  mac " MACSTR "\n", VOX_NODE_ID, MAC2STR(m));
    const esp_app_desc_t *app=esp_app_get_description();
    printf("#DEVICE,node=%u,protocol=%u,frame_ms=%d,codec=%s,sha=",VOX_NODE_ID,VOX_PROTO_VERSION,VOX_FRAME_MS,VOX_CODEC_NAME);
    for(int i=0;i<32;i++) printf("%02x",app->app_elf_sha256[i]);
    printf(",tag=%u,crypto=",VOX_TAG_LEN);
#ifndef CONFIG_VOX_CRYPTO_ENABLED
    printf("none\n");
#elif defined(CONFIG_VOX_AEAD_CCM)
    printf("ccm\n");
#else
    printf("gcm\n");
#endif
    printf("on the other board run:  peer add " MACSTR " %u\n",
           MAC2STR(m), VOX_NODE_ID);
    return 0;
}

static int cmd_peer(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "list") == 0) {
        printf("%-4s %-18s %-8s %-6s %-6s %-8s %-8s %-8s\n",
               "id", "mac", "state", "epoch", "txseq", "authfail", "replay", "phantom");
        for (int i = 0; i < VOX_MAX_PEERS; i++) {
            vox_peer_t *p = vox_peer_at(i);
            if (p == NULL) continue;
            const char *st = (p->state == VOX_SESS_ESTABLISHED) ? "up"
                           : (p->state == VOX_SESS_INIT_SENT)   ? "init" : "idle";
            printf("%-4u " MACSTR " %-8s %-6u %-6u %-8u %-8u %-8s\n",
                   p->peer_id, MAC2STR(p->mac), st, p->epoch,
                   (unsigned)p->tx_seq, (unsigned)p->n_auth_fail,
                   (unsigned)p->n_replay_drop, p->phantom ? "yes" : "no");
            printf("#SESSION,peer=%u,state=%s,isolated=%d,phantom=%d,epoch=%u,"
                   "epoch_unknown=%u,initiator=%d,hs_pending=%d,hs_have_response=%d\n",
                   p->peer_id,st,p->isolated,p->phantom,p->epoch,
                   (unsigned)p->n_epoch_unknown,p->initiator,p->hs_pending,p->hs_have_response);
        }
        printf("%d peers (%d real), %d B state, %d B/peer\n",
               vox_peer_count(), vox_peer_count_real(),
               (int)vox_session_state_bytes(), (int)vox_session_bytes_per_peer());
        return 0;
    }

    if (argc >= 4 && strcmp(argv[1], "add") == 0) {
        uint8_t mac[6];
        if (!parse_mac(argv[2], mac)) {
            printf("bad MAC: expected aa:bb:cc:dd:ee:ff\n");
            return 1;
        }
        uint16_t id = (uint16_t)strtoul(argv[3], NULL, 10);
        vox_peer_t *p = vox_peer_add(mac, id, false);
        if (p == NULL) {
            printf("could not add peer\n");
            return 1;
        }
        printf("peer %u added; run 'connect %u' to establish a session\n", id, id);
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "del") == 0) {
        uint16_t id = (uint16_t)strtoul(argv[2], NULL, 10);
        return (vox_peer_remove(id) == ESP_OK) ? 0 : 1;
    }

    printf("usage: peer add <aa:bb:cc:dd:ee:ff> <id> | peer del <id> | peer list\n");
    return 1;
}

static int cmd_phantom(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: phantom <count>   (adds synthetic sender-side peers)\n");
        return 1;
    }
    int n = atoi(argv[1]);
    if (n < 0) {
        n = 0;
    }
    if (n > VOX_MAX_PEERS - 1) {
        n = VOX_MAX_PEERS - 1;      /* leave room for the real receiver */
        printf("clamped to %d: ESP-NOW supports at most %d unicast peers\n",
               n, VOX_MAX_PEERS);
    }

    /*
     * Set the count exactly rather than only adding. A sweep that visits
     * receiver counts in descending order, or that repeats a point after a
     * larger one, would otherwise silently carry the previous run's peers
     * forward and label the result with the wrong N.
     */
    for (int i = n; i < VOX_MAX_PEERS; i++) {
        vox_peer_t *p = vox_peer_by_id((uint16_t)(1000 + i));
        if (p != NULL && p->phantom) {
            vox_peer_remove((uint16_t)(1000 + i));
        }
    }

    for (int i = 0; i < n; i++) {
        uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0xDE, (uint8_t)(0xA0 + i) };
        vox_peer_t *p = vox_peer_add(mac, (uint16_t)(1000 + i), true);
        if (p != NULL && p->state != VOX_SESS_ESTABLISHED) {
            vox_session_handshake(p);
        }
    }

    printf("%d phantom peers active, %d real, %d total\n",
           vox_peer_count() - vox_peer_count_real(),
           vox_peer_count_real(), vox_peer_count());
    printf("NOTE: phantoms never acknowledge. Sender CPU, memory, crypto and\n"
           "      transmit cost are valid; their delivery and retry figures are not.\n");
    return 0;
}

static int cmd_connect(int argc, char **argv)
{
    if (argc >= 2) {
        vox_peer_t *p = vox_peer_by_id((uint16_t)strtoul(argv[1], NULL, 10));
        if (p == NULL) {
            printf("no such peer\n");
            return 1;
        }
        return (vox_session_handshake(p) == ESP_OK) ? 0 : 1;
    }
    int n = 0;
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        vox_peer_t *p = vox_peer_at(i);
        if (p != NULL && !p->phantom) {
            if (vox_session_handshake(p) == ESP_OK) n++;
        }
    }
    printf("handshake started with %d peers\n", n);
    return 0;
}

static int cmd_discover(int argc,char **argv)
{
    uint32_t window=argc>=2?(uint32_t)strtoul(argv[1],NULL,10):3000;
    vox_security_lock(); esp_err_t err=vox_session_discover(window); vox_security_unlock();
    if(err!=ESP_OK) return 1;
    vTaskDelay(pdMS_TO_TICKS(window+400));
    vox_security_lock(); printf("%d peers after discovery\n",vox_peer_count()); vox_security_unlock();
    return 0;
}

static int cmd_rekey(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: rekey <peer id>    (cheap epoch rotation, keeps the session)\n");
        return 1;
    }
    vox_peer_t *p = vox_peer_by_id((uint16_t)strtoul(argv[1], NULL, 10));
    if (p == NULL) {
        printf("no such peer\n");
        return 1;
    }
    int64_t t0 = esp_timer_get_time();
    esp_err_t err = vox_session_rekey(p);
    printf("rekey requested in %lld us, epoch %u -> %u (%s)\n",
           (long long)(esp_timer_get_time() - t0), p->epoch, p->rekey_target_epoch,
           esp_err_to_name(err));
    return (err == ESP_OK) ? 0 : 1;
}

static int cmd_talk(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: talk on | talk off | talk <seconds>\n"
               "       talk group on | talk group <seconds>\n"
               "'group' delivers via the active group's broadcast path\n"
               "(vox_group_*) instead of per-peer unicast -- requires an\n"
               "active group ('group create'/'group join'). Every form\n"
               "below sets the delivery mode explicitly, so a plain 'talk\n"
               "<seconds>' always means unicast even after a previous\n"
               "'talk group' burst.\n");
        return 1;
    }

    bool group = false;
    int arg_i = 1;
    if (strcmp(argv[1], "group") == 0) {
        if (argc < 3) {
            printf("usage: talk group on | talk group <seconds>\n");
            return 1;
        }
        if (!vox_group_ready()) {
            printf("no active group -- 'group create' or 'group join' first\n");
            return 1;
        }
        group = true;
        arg_i = 2;
    }
    vox_ptt_set_group(group);

    if (strcmp(argv[arg_i], "on") == 0) {
        vox_ptt_set(true);
        return 0;
    }
    if (strcmp(argv[arg_i], "off") == 0) {
        vox_ptt_set(false);
        return 0;
    }

    int secs = atoi(argv[arg_i]);
    if (secs <= 0) {
        printf("bad duration\n");
        return 1;
    }
    if (s_talk_timer == NULL) {
        const esp_timer_create_args_t a = { .callback = talk_timeout, .name = "talk" };
        ESP_ERROR_CHECK(esp_timer_create(&a, &s_talk_timer));
    }
    esp_timer_stop(s_talk_timer);
    vox_ptt_set(true);
    ESP_ERROR_CHECK(esp_timer_start_once(s_talk_timer, (uint64_t)secs * 1000000ULL));
    printf("talking for %d s (%s)\n", secs, group ? "group" : "unicast");
    return 0;
}

static int cmd_run(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "start") == 0) {
        const char *label = (argc >= 3) ? argv[2] : "run";
        vox_metrics_print_header(label);
        vox_metrics_run_start(label);
        printf("run '%s' started\n", label);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "stop") == 0) {
        vox_metrics_run_stop();
        vox_metrics_print_summary();
        return 0;
    }
    printf("usage: run start [label] | run stop\n");
    return 1;
}

static int cmd_dump(int argc, char **argv)
{
    if(vox_metrics_running()) { printf("run stop before dumping telemetry\n"); return 1; }
    const char *what = (argc >= 2) ? argv[1] : "all";

    /*
     * The machine-readable summary leads every dump. `run stop` prints it too,
     * but a capture that only dumps -- reading back a window someone else
     * closed -- would otherwise carry trace rows with no aggregates to check
     * them against, and the host would be back to computing statistics from
     * whatever survived the UART.
     */
    if (strcmp(what, "csv") == 0 || strcmp(what, "all") == 0 ||
        strcmp(what, "summary") == 0) {
        vox_metrics_print_summary_kv();
    }
    if (strcmp(what, "summary") == 0) {
        return 0;
    }

    if (strcmp(what, "csv") == 0 || strcmp(what, "all") == 0) {
        vox_metrics_dump_csv();
    }
    if (strcmp(what, "hist") == 0 || strcmp(what, "all") == 0) {
        vox_metrics_dump_hist();
    }
    if (strcmp(what, "tasks") == 0 || strcmp(what, "all") == 0) {
        vox_metrics_dump_tasks();
    }
    return 0;
}

static int cmd_stats(int argc, char **argv)
{
    (void)argc; (void)argv;
    vox_metrics_sample_resources();
    vox_metrics_print_summary();
    return 0;
}

static int cmd_sync(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("%-6s %-10s %-14s %-12s\n", "peer", "samples", "offset_us", "best_rtt_us");
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        vox_peer_t *p = vox_peer_at(i);
        if (p == NULL || p->phantom) continue;
        printf("%-6u %-10u %-14lld %-12lld %s\n",
               p->peer_id,
               (unsigned)vox_timesync_samples(p->peer_id),
               (long long)vox_timesync_offset_us(p->peer_id),
               (long long)vox_timesync_best_rtt_us(p->peer_id),
               vox_timesync_valid(p->peer_id) ? "" : "(not converged)");
        printf("#SYNC,peer=%u,valid=%d,samples=%u,best_rtt_us=%lld\n",p->peer_id,
               vox_timesync_valid(p->peer_id),(unsigned)vox_timesync_samples(p->peer_id),
               (long long)vox_timesync_best_rtt_us(p->peer_id));
    }
    printf("\nOne-way delay uncertainty is bounded by roughly half the best RTT.\n"
           "Quote that alongside any latency figure taken from software alone.\n");
    return 0;
}

static int cmd_pmk(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "set") == 0) {
        const char *hex = argv[2];
        if (strlen(hex) != VOX_PMK_LEN * 2) {
            printf("PMK must be %d hex characters\n", VOX_PMK_LEN * 2);
            return 1;
        }
        uint8_t pmk[VOX_PMK_LEN];
        for (int i = 0; i < VOX_PMK_LEN; i++) {
            char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
            char *end = NULL;
            long v = strtol(b, &end, 16);
            if (end != b + 2) {
                printf("bad hex\n");
                return 1;
            }
            pmk[i] = (uint8_t)v;
        }
        if (vox_keys_store_pmk(pmk) != ESP_OK) {
            printf("could not store PMK\n");
            return 1;
        }
        printf("PMK stored in NVS. Flash the same key on every board, then reboot both.\n");
        return 0;
    }
    printf("usage: pmk set <64 hex chars>\n");
    return 1;
}

static int cmd_gain(int argc, char **argv)
{
    if (argc < 2) {
        printf("mic gain shift %d (higher = quieter)\n", vox_audio_src_gain_shift());
        return 0;
    }
    vox_audio_src_set_gain_shift(atoi(argv[1]));
    printf("mic gain shift %d\n", vox_audio_src_gain_shift());
    return 0;
}

static int bench_broadcast(int argc, char **argv)
{
    int count = (argc >= 3) ? atoi(argv[2]) : 100;
    if (count <= 0) {
        count = 100;
    }

    static uint8_t buf[VOX_ON_AIR_BYTES];
    memset(buf, 0xA5, sizeof(buf));   /* content is irrelevant; only size matters */

    vox_stat_t air;
    vox_stat_reset(&air);
    uint32_t fail = 0;

    int64_t t_wall0 = esp_timer_get_time();
    for (int i = 0; i < count; i++) {
        int64_t air_us = 0;
        if (vox_link_broadcast(buf, sizeof(buf), &air_us) != ESP_OK) {
            fail++;
            continue;
        }
        vox_stat_add(&air, (int32_t)air_us);
    }
    int64_t t_wall1 = esp_timer_get_time();

    printf("broadcast bench: %d sends, %u failed, %lld us wall, %u B on air\n",
           count, (unsigned)fail, (long long)(t_wall1 - t_wall0),
           (unsigned)sizeof(buf));
    if (air.n > 0) {
        printf("  air us   mean %.1f  sd %.1f  min %d  max %d  n=%u\n",
               vox_stat_mean(&air), vox_stat_sd(&air),
               (int)air.min, (int)air.max, (unsigned)air.n);
    } else {
        printf("  air us   no samples\n");
    }
    return 0;
}

/*
 * Test vector generated independently with Python's `cryptography` library
 * (OpenSSL-backed), not transcribed from a spec by hand -- if the vendored
 * orlp/ed25519 C implementation reproduces the same public key and the same
 * signature from the same seed and message, that is strong cross-
 * implementation evidence it is correct: Ed25519 signing is deterministic,
 * so any correct implementation given this input must produce this output
 * bit for bit. The fixed 52-byte message matches the historical protocol-1
 * Codec2/40ms packet size; protocol-2 media packets are four bytes larger.
 */
static const uint8_t k_seed[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t k_pub_expected[32] = {
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18,
    0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f,
    0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8
};
static const uint8_t k_sig_expected[64] = {
    0xeb, 0x89, 0xc0, 0x16, 0x46, 0xe6, 0xfa, 0x14, 0xe7, 0xaf, 0x82, 0x14,
    0x7f, 0x13, 0x3c, 0x19, 0x2b, 0xc4, 0x9c, 0x54, 0xbc, 0x54, 0x3a, 0x66,
    0x55, 0x0d, 0xc9, 0xa9, 0x9c, 0x5e, 0xae, 0x99, 0xd7, 0xc3, 0x4a, 0xd8,
    0x5c, 0x71, 0x81, 0x5d, 0x39, 0xf5, 0x98, 0x08, 0x3f, 0xb8, 0x3c, 0xd3,
    0x4b, 0x63, 0xd3, 0x3a, 0xd3, 0x88, 0xed, 0x92, 0xc4, 0x86, 0xad, 0xa7,
    0x64, 0x19, 0x93, 0x07
};

/* Returns NULL on success, else a short string naming what failed. */
static const char *ed25519_self_test(uint8_t pub[32], uint8_t priv[64])
{
    static uint8_t msg[52];
    memset(msg, 0xA5, sizeof(msg));
    ed25519_create_keypair(pub, priv, k_seed);
    if (memcmp(pub, k_pub_expected, 32) != 0) {
        return "derived public key does not match the independently "
               "generated vector -- keypair derivation is wrong";
    }

    uint8_t sig[64];
    ed25519_sign(sig, msg, sizeof(msg), pub, priv);
    if (memcmp(sig, k_sig_expected, 64) != 0) {
        return "signature does not match the independently generated "
               "vector -- sign() disagrees with a trusted implementation";
    }

    if (!ed25519_verify(sig, msg, sizeof(msg), pub)) {
        return "verify() rejected its own valid signature";
    }

    uint8_t bad_sig[64];
    memcpy(bad_sig, sig, 64);
    bad_sig[0] ^= 0x01;
    if (ed25519_verify(bad_sig, msg, sizeof(msg), pub)) {
        return "verify() accepted a tampered signature";
    }

    uint8_t bad_msg[52];
    memcpy(bad_msg, msg, sizeof(msg));
    bad_msg[0] ^= 0x01;
    if (ed25519_verify(sig, bad_msg, sizeof(bad_msg), pub)) {
        return "verify() accepted a signature over the wrong message";
    }

    uint8_t other_pub[32], other_priv[64];
    uint8_t other_seed[32];
    memcpy(other_seed, k_seed, 32);
    other_seed[0] ^= 0xFF;
    ed25519_create_keypair(other_pub, other_priv, other_seed);
    if (ed25519_verify(sig, msg, sizeof(msg), other_pub)) {
        return "verify() accepted a signature under the wrong public key";
    }

    return NULL;
}

static int bench_ed25519(int argc, char **argv)
{
    if (argc < 3 || (strcmp(argv[2], "sign") != 0 && strcmp(argv[2], "verify") != 0)) {
        printf("usage: bench ed25519 sign|verify <count>\n");
        return 1;
    }
    bool do_sign = (strcmp(argv[2], "sign") == 0);
    int count = (argc >= 4) ? atoi(argv[3]) : 100;
    if (count <= 0) {
        count = 100;
    }

    uint8_t pub[32], priv[64];
    const char *fail_reason = ed25519_self_test(pub, priv);
    if (fail_reason != NULL) {
        printf("ed25519 self-test FAILED: %s\n"
               "Refusing to report timing from an implementation that just "
               "failed correctness checks.\n", fail_reason);
        return 1;
    }
    printf("ed25519 self-test passed (keypair, sign, verify, and three "
           "rejection cases, all checked against an independently "
           "generated vector)\n");

    static uint8_t msg[52];
    memset(msg, 0xA5, sizeof(msg));
    uint8_t sig[64];
    ed25519_sign(sig, msg, sizeof(msg), pub, priv);   /* needed for the verify bench */

    vox_stat_t t;
    vox_stat_reset(&t);
    int64_t t_wall0 = esp_timer_get_time();
    for (int i = 0; i < count; i++) {
        int64_t t0 = esp_timer_get_time();
        if (do_sign) {
            ed25519_sign(sig, msg, sizeof(msg), pub, priv);
        } else {
            volatile int ok = ed25519_verify(sig, msg, sizeof(msg), pub);
            (void)ok;
        }
        int64_t t1 = esp_timer_get_time();
        vox_stat_add(&t, (int32_t)(t1 - t0));
    }
    int64_t t_wall1 = esp_timer_get_time();

    printf("ed25519 %s bench: %d calls, %lld us wall, %u B message\n",
           do_sign ? "sign" : "verify", count,
           (long long)(t_wall1 - t_wall0), (unsigned)sizeof(msg));
    printf("  us       mean %.1f  sd %.1f  min %d  max %d  n=%u\n",
           vox_stat_mean(&t), vox_stat_sd(&t), (int)t.min, (int)t.max,
           (unsigned)t.n);
    return 0;
}

static int cmd_bench(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "broadcast") == 0) {
        return bench_broadcast(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "ed25519") == 0) {
        return bench_ed25519(argc, argv);
    }
    printf("usage: bench broadcast <count>\n"
           "       bench ed25519 sign|verify <count>\n"
           "'broadcast' times vox_link_broadcast() in isolation, with no\n"
           "group-key logic involved -- measures ANALYTICAL_MODEL.md's xi_b.\n"
           "'ed25519' times the vendored orlp/ed25519 sign/verify after a\n"
           "self-test against an independently generated vector -- measures\n"
           "ANALYTICAL_MODEL.md's source-authentication cost s.\n"
           "Do not run either while a talk burst or measurement run is\n"
           "active: broadcast shares the unicast send lock, and both will\n"
           "contend with vox_tx for CPU time on core 0.\n");
    return 1;
}

static void print_group_status(void)
{
    if(!vox_group_active()) { printf("no active group\n#GROUP,active=0,busy=%d\n",vox_group_control_busy()); return; }
    vox_grp_grant_body_t b; vox_group_snapshot(&b);
    printf("group: epoch %u, coordinator %u%s, %d member(s), %u B state\n",
        vox_group_epoch(),vox_group_coordinator(),vox_group_is_coordinator()?" (this node)":"",
        vox_group_member_count(),(unsigned)vox_group_state_bytes());
    for(int i=0;i<b.member_count;i++) printf("  member %u\n",b.members[i]);
    printf("#GROUP,active=1,ready=%d,busy=%d,status=%s,generation=%lu,coordinator=%u,group_id=",
        vox_group_ready(),vox_group_control_busy(),vox_group_control_status(),
        (unsigned long)b.generation,b.coordinator_id);
    for(int i=0;i<VOX_GROUP_ID_LEN;i++) printf("%02x",b.group_id[i]);
    printf(",members="); for(int i=0;i<b.member_count;i++) printf("%s%u",i?";":"",b.members[i]);
    printf(",allowed="); for(int i=0;i<b.allowed_count;i++) printf("%s%u",i?";":"",b.allowed[i]);
    printf("\n");
    for(int i=0;i<b.member_count;i++) {
        vox_replay_t *w=vox_group_replay_for(b.members[i]);
        printf("#GROUP_REPLAY,member=%u,primed=%d,highest=%lu,bitmap=%016llx\n",
            b.members[i],w->primed,(unsigned long)w->highest,(unsigned long long)w->bitmap);
    }
    mbedtls_platform_zeroize(&b,sizeof(b));
}
static int cmd_group(int argc,char **argv)
{
#ifndef CONFIG_VOX_CRYPTO_ENABLED
    printf("group control requires a crypto-enabled build\n"); return 1;
#endif
    if(argc<2) goto usage;
    uint16_t id=argc>2?(uint16_t)strtoul(argv[2],NULL,10):0;
    esp_err_t err=ESP_ERR_INVALID_ARG;
    if(!strcmp(argv[1],"status")) { print_group_status(); return 0; }
    if(!strcmp(argv[1],"create")) { err=vox_group_create(); if(err==ESP_OK) vox_group_control_init(); }
    else if(!strcmp(argv[1],"join") && id) err=vox_group_control_join(id);
    else if(!strcmp(argv[1],"allow") && id) err=vox_group_control_allow(id);
    else if(!strcmp(argv[1],"expect") && id) err=vox_group_control_expect(id);
    else if(!strcmp(argv[1],"revoke") && id) err=vox_group_control_revoke(id);
    else if(!strcmp(argv[1],"leave")) err=vox_group_control_leave();
    else if(!strcmp(argv[1],"rekey")) err=vox_group_control_rekey();
    else if(!strcmp(argv[1],"claim")) err=vox_group_control_claim_coordinator();
    else goto usage;
    printf("group %s: %s%s\n",argv[1],esp_err_to_name(err),
        err==ESP_OK?" (accepted; check group status / GRPOP completion)":"");
    return err!=ESP_OK;
usage:
    printf("usage: group create|status|leave|rekey|claim\n"
           "       group join|allow|revoke|expect <node-id>\n"
           "Provision per-pair PSKs before connect. Coordinator must allow\n"
           "each applicant. On every survivor, expect <candidate> explicitly\n"
           "authorises an operator-driven transfer before candidate claims.\n");
    return 1;
}
static int cmd_psk(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"list")) {
        for(int i=0;i<VOX_MAX_PEERS;i++) {
            vox_peer_t *p=vox_peer_at(i);
            if(p) printf("psk peer=%u isolated=%d session_isolated=%d\n",p->peer_id,
                vox_keys_peer_isolated(p->peer_id),p->isolated);
        }
        return 0;
    }
    if(argc<3) goto usage;
    uint16_t id=(uint16_t)strtoul(argv[2],NULL,10);
    if(vox_group_active() && vox_group_is_member(id)) {
        printf("leave/revoke the member before replacing its control credential\n"); return 1;
    }
    esp_err_t err;
    if(argc==3 && !strcmp(argv[1],"del")) err=vox_keys_remove_peer(id);
    else if(argc==4 && !strcmp(argv[1],"set") && strlen(argv[3])==64) {
        uint8_t key[32];
        for(int i=0;i<32;i++) {
            char byte[3]={argv[3][2*i],argv[3][2*i+1],0}, *end=NULL;
            long value=strtol(byte,&end,16);
            if(end!=byte+2 || value<0 || value>255) { mbedtls_platform_zeroize(key,sizeof(key)); goto usage; }
            key[i]=(uint8_t)value;
        }
        err=vox_keys_store_peer(id,key); mbedtls_platform_zeroize(key,sizeof(key));
        memset(argv[3],0,64);
    } else goto usage;
    if(err==ESP_OK) vox_peer_remove(id); /* old session cannot outlive changed credential */
    printf("psk stored: %s; add/connect peer again\n",esp_err_to_name(err));
    return err!=ESP_OK;
usage:
    printf("usage: psk set <peer-id> <64 hex chars> | psk del <peer-id> | psk list\n"); return 1;
}

static int cmd_attack(int argc, char **argv)
{
    if(argc==2 && !strcmp(argv[1],"info")) { vox_attack_info(); return 0; }
    if (argc < 2) {
        printf("usage: attack replay|tamper|forge|flood [count]\n"
               "Simulates the radio-range attacker from the threat model.\n"
               "Run these on the SENDER while the receiver has a run active,\n"
               "then compare the receiver's rejection counters.\n");
        return 1;
    }
    int n = (argc >= 3) ? atoi(argv[2]) : 10;
    if (n <= 0) n = 1;

    int sent;
    if (strcmp(argv[1], "replay") == 0) {
        sent = vox_attack_replay(n);
        printf("replayed %d captured frames; expect rx_replay_drop +%d, rx_frames +0\n",
               sent, sent);
    } else if (strcmp(argv[1], "tamper") == 0) {
        sent = vox_attack_tamper(n);
        printf("sent %d bit-flipped frames; expect rx_auth_fail +%d, rx_frames +0\n",
               sent, sent);
    } else if (strcmp(argv[1], "forge") == 0) {
        sent = vox_attack_forge(n);
        printf("sent %d forged frames; expect rx_auth_fail +%d, rx_frames +0\n",
               sent, sent);
    } else if (strcmp(argv[1], "flood") == 0) {
        int64_t t0 = esp_timer_get_time();
        sent = vox_attack_flood(n);
        int64_t dt = esp_timer_get_time() - t0;
        printf("flooded %d forged frames in %lld us (%.0f frames/s); "
               "this measures AVAILABILITY - read the receiver's loss and "
               "one-way delay, not just its rejection count\n",
               sent, (long long)dt,
               dt > 0 ? (double)sent * 1e6 / (double)dt : 0.0);
    } else {
        printf("unknown attack '%s'\n", argv[1]);
        return 1;
    }
    printf("#ATTACK,kind=%s,sent=%d,requested=%d\n",argv[1],sent,n);
    return (sent > 0) ? 0 : 1;
}

#define LOCKED_CMD(name) \
static int name##_locked(int argc,char **argv) { \
    vox_security_lock(); int rc=name(argc,argv); vox_security_unlock(); return rc; }
LOCKED_CMD(cmd_peer)
LOCKED_CMD(cmd_connect)
LOCKED_CMD(cmd_phantom)
LOCKED_CMD(cmd_rekey)
LOCKED_CMD(cmd_group)
LOCKED_CMD(cmd_psk)
LOCKED_CMD(cmd_pmk)
LOCKED_CMD(cmd_sync)
LOCKED_CMD(cmd_talk)

/* --------------------------------------------------------------- wiring */

/* Copy arguments before nested esp_console_run, whose parser reuses its
 * scratch buffer. The host matches an exact token and checks the return code. */
static int cmd_host(int argc,char **argv)
{
    if(argc<3 || strlen(argv[1])>16 || !strcmp(argv[2],"host")) return 1;
    char token[17],line[128]={0}; snprintf(token,sizeof(token),"%s",argv[1]);
    size_t used=0;
    for(int i=2;i<argc;i++) {
        int n=snprintf(line+used,sizeof(line)-used,"%s%s",i==2?"":" ",argv[i]);
        if(n<0 || (size_t)n>=sizeof(line)-used) return 1;
        used+=(size_t)n;
    }
    int rc=1; esp_err_t err=esp_console_run(line,&rc);
    mbedtls_platform_zeroize(line,sizeof(line));
    printf("\n#HOST,token=%s,rc=%d\n",token,err==ESP_OK?rc:(int)err);
    return 0;
}

static void reg(const char *cmd, const char *help, esp_console_cmd_func_t fn)
{
    const esp_console_cmd_t c = { .command = cmd, .help = help, .hint = NULL, .func = fn };
    ESP_ERROR_CHECK(esp_console_cmd_register(&c));
}

esp_err_t vox_console_start(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t rc = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    rc.prompt = "vox>";
    rc.max_cmdline_length = 128;
    /* The 4096 B default crashed (LoadProhibited) partway through a repeated
     * `bench ed25519 sign` loop -- Ed25519's field-element structs plus
     * printf's float/long-long formatting left too little headroom. */
    rc.task_stack_size = 8192;

    esp_console_dev_uart_config_t uc = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uc, &rc, &repl));

    ESP_ERROR_CHECK(esp_console_register_help_command());
    reg("mac",     "show this node's MAC and the peer command for the other board", cmd_mac);
    reg("host",    "host <token> <command>: machine-framed command result", cmd_host);
    reg("peer",    "peer add <mac> <id> | peer del <id> | peer list", cmd_peer_locked);
    reg("phantom", "phantom <n> - add synthetic peers for sender-side N-scaling", cmd_phantom_locked);
    reg("connect", "connect [id] - run the pairwise handshake", cmd_connect_locked);
    reg("discover", "discover [ms] - broadcast an invite; every listener in "
                    "range that holds the same PMK answers with its MAC", cmd_discover);
    reg("rekey",   "rekey <id> - rotate the key epoch", cmd_rekey_locked);
    reg("talk",    "talk on|off|<seconds> | talk group on|<seconds>", cmd_talk_locked);
    reg("run",     "run start [label] | run stop", cmd_run);
    reg("dump",    "dump csv | hist | tasks | summary | all", cmd_dump);
    reg("stats",   "print the current summary without stopping the run", cmd_stats);
    reg("sync",    "clock offset estimator state", cmd_sync_locked);
    reg("psk", "provision an independent pairwise credential", cmd_psk_locked);
    reg("pmk",     "pmk set <64 hex chars>", cmd_pmk_locked);
    reg("gain",    "gain [shift] - microphone gain", cmd_gain);
    reg("bench",   "bench broadcast <count> | bench ed25519 sign|verify <count>", cmd_bench);
    reg("group",   "group create|join|leave|revoke|rekey|claim|status", cmd_group_locked);
    reg("attack",  "attack replay|tamper|forge|flood [count] - threat-model test cases", cmd_attack);

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    ESP_LOGI(TAG, "console ready, type 'help'");
    return ESP_OK;
}
