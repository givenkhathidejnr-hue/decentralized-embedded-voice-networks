#!/usr/bin/env python3
"""Reproduce the October 2026 review findings without hardware.

Runs current group/control/replay/jitter-buffer function bodies, not copied
implementations. Only includes and duplicate logging TAG declarations are
removed when composing a temporary translation unit. ESP-IDF, transport,
pairwise lookup and cryptography are test doubles. AEAD open models an
already-authenticated peer; these checks are NOT cryptographic/RF tests.
Exit zero means all listed defect reproductions still reproduce, not that
the firmware is correct. After fixes, replace these with invariant tests.
"""
# Protocol-1 function names/layouts were retired by the fixes. Keep this
# diagnostic source as historical review evidence; do not present it as a test
# of protocol 2. The replacement asserts secure invariants with real crypto.
raise SystemExit("Historical protocol-1 reproducer retired. Run: bash tools/test_protocol.sh")

from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "firmware/main"


def source(name):
    text = (MAIN / name).read_text()
    text = re.sub(r'^\s*#(?:include[^\n]*|pragma once)\s*$', '', text, flags=re.M)
    return re.sub(r'^static const char \*TAG = .*;\s*$', '', text, flags=re.M)


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE 1
#define ESP_ERR_INVALID_SIZE 2
#define ESP_ERR_NO_MEM 3
#define ESP_ERR_NOT_FOUND 4
#define VOX_NODE_ID 1
#define VOX_MAX_GROUP_MEMBERS 8
#define VOX_REPLAY_WINDOW 32
#define VOX_SESSION_LEN 32
#define VOX_HS_NONCE_LEN 16
#define VOX_HDR_LEN 12
#define VOX_AUDIO_SUBHDR_LEN 8
#define VOX_TAG_LEN 16
#define VOX_AEAD_NONCE_LEN 12
#define VOX_AEAD_SALT_LEN 4
#define CONFIG_VOX_CRYPTO_ENABLED 1
#define VOX_SAMPLES_PER_FRAME 320
#define CONFIG_VOX_JITTER_MAX_FRAMES 8
#define CONFIG_VOX_JITTER_TARGET_FRAMES 1
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
typedef void *SemaphoreHandle_t;
#define portMAX_DELAY 0
static void *xSemaphoreCreateMutex(void) { static int lock; return &lock; }
static void xSemaphoreTake(void *a, int b) { (void)a; (void)b; }
static void xSemaphoreGive(void *a) { (void)a; }
typedef struct { bool ready; uint8_t salt[4]; uint8_t key_identity[33]; } vox_aead_t;
static int64_t esp_timer_get_time(void) { static int64_t t; return ++t; }
static void esp_fill_random(void *p, size_t n) { static unsigned v; memset(p, ++v, n); }
static void mbedtls_platform_zeroize(void *p, size_t n) { memset(p, 0, n); }
static void vox_aead_clear(vox_aead_t *a) { memset(a, 0, sizeof(*a)); }
static int vox_keys_derive_group(const uint8_t *s, uint8_t e, vox_aead_t *a) {
    memcpy(a->key_identity, s, 32); a->key_identity[32] = e;
    memcpy(a->salt, s, 4); a->ready = true; return ESP_OK;
}
static int vox_aead_seal(vox_aead_t *a, const uint8_t *n, const uint8_t *ad,
    size_t al, const uint8_t *p, size_t pl, uint8_t *c, uint8_t *tag, size_t tl) {
    (void)a; (void)n; (void)ad; (void)al;
    memcpy(c, p, pl); memset(tag, 0, tl); return ESP_OK;
}
static int vox_aead_open(vox_aead_t *a, const uint8_t *n, const uint8_t *ad,
    size_t al, const uint8_t *c, size_t cl, const uint8_t *tag, size_t tl, uint8_t *p) {
    (void)a; (void)n; (void)ad; (void)al; (void)tag; (void)tl;
    memcpy(p, c, cl); return ESP_OK;
}
'''

STUBS = r'''
static vox_peer_t peers[9];
static uint8_t last_sent[256];
static int send_result;
vox_peer_t *vox_peer_by_id(uint16_t id) { return id < 9 ? &peers[id] : NULL; }
vox_peer_t *vox_peer_by_mac(const uint8_t mac[6]) { return vox_peer_by_id(mac[0]); }
vox_aead_t *vox_session_rx_ctx(vox_peer_t *p, uint8_t e, vox_replay_t **w) {
    (void)e; *w = &p->replay; return &p->rx;
}
static int vox_link_send(const uint8_t *m, const uint8_t *b, size_t n,
    uint32_t t, int64_t *air) {
    (void)m; (void)t; (void)air; memcpy(last_sent, b, n); return send_result;
}
'''

TESTS = r'''
static void setup(void) {
    vox_group_init(); memset(peers, 0, sizeof(peers));
    memset(&s_rekey_wait, 0, sizeof(s_rekey_wait)); send_result = ESP_OK;
    for (int i = 1; i < 9; ++i) {
        peers[i].peer_id = i; peers[i].mac[0] = i;
        peers[i].state = VOX_SESS_ESTABLISHED;
    }
}
static void observed(bool yes, const char *name) {
    printf("%s: %s\n", yes ? "REPRODUCED" : "NOT REPRODUCED", name); assert(yes);
}
int main(void) {
    uint8_t secret[32] = {42}, before[32], after[32], e0, e1;
    uint8_t n0[12], n1[12];
    setup(); vox_group_install(secret, 7, 2);
    vox_aead_nonce(vox_group_aead(), VOX_NODE_ID, 7, vox_group_next_tx_seq(), n0);
    vox_replay_commit(vox_group_replay_for(2), 55);
    vox_group_install(secret, 7, 2);
    vox_aead_nonce(vox_group_aead(), VOX_NODE_ID, 7, vox_group_next_tx_seq(), n1);
    observed(memcmp(n0, n1, 12) == 0 && vox_replay_is_fresh(vox_group_replay_for(2), 55),
             "same-key install repeats nonce and reopens accepted replay");

    setup(); vox_group_create(); vox_group_grant_current(before, &e0);
    on_join_req(&peers[2], 2); vox_group_grant_current(after, &e1);
    const vox_grp_grant_body_t *grant = (const void *)(last_sent + VOX_HDR_LEN);
    observed(e0 == e1 && memcmp(before, after, 32) == 0 &&
             memcmp(grant->secret, before, 32) == 0,
             "new join receives pre-join group secret");
    vox_group_control_revoke(2);
    observed(!vox_group_is_member(2), "revocation first removes member");
    on_join_req(&peers[2], 2);
    observed(vox_group_is_member(2), "revoked peer immediately readmitted without approval");

    setup(); vox_group_install(secret, 0, 2);
    observed(vox_group_member_count() == 2 && vox_group_replay_for(3) == NULL,
             "member has only self and coordinator; another member cannot talk to it");
    vox_group_control_claim_coordinator();
    observed(vox_group_control_revoke(3) == ESP_ERR_NOT_FOUND,
             "promoted coordinator cannot revoke absent roster entry");

    setup(); vox_group_install(secret, 0, 2);
    vox_hdr_t hdr = { .type=VOX_T_GRP_REKEY, .src_id=3, .dst_id=1, .seq=1 };
    uint8_t wire[sizeof(vox_grp_grant_body_t) + VOX_TAG_LEN] = {0};
    vox_grp_grant_body_t *body = (void *)wire;
    memset(body->secret, 99, 32); body->coordinator_id=3; body->epoch=9;
    vox_group_control_on_frame(peers[3].mac, &hdr, wire, sizeof(wire));
    observed(vox_group_coordinator() == 3 && vox_group_epoch() == 9,
             "authenticated non-coordinator can replace group key and coordinator");

    setup(); vox_group_create(); vox_group_add_member(2); vox_group_add_member(3);
    send_result = ESP_FAIL;
    observed(vox_group_control_rekey() == ESP_OK && vox_group_epoch() == 1,
             "rekey reports success when all network sends fail");
    on_rekey_ack(2, 1); on_rekey_ack(2, 1);
    observed(!s_rekey_wait.pending && s_rekey_wait.acked == 2,
             "one member counted twice completes two-member ACK quorum");

    vox_jb_reset(); vox_jb_frame_t f = {.seq=100, .stream_id=5, .nsamp=320}, out;
    assert(vox_jb_push(&f)); assert(vox_jb_pop(&out));
    f.seq = 0;
    observed(!vox_jb_push(&f), "rekey sequence reset rejected as late within same talk burst");

    vox_jb_reset(); f.seq=0;
    assert(vox_jb_push(&f)); assert(vox_jb_pop(&out));
    for (int i=0; i<100; ++i) vox_jb_pop(&out);
    vox_jb_stats_t stats; vox_jb_stats(&stats);
    observed(stats.concealed == 1,
             "100 empty playout ticks count only one concealment after buffer stops");

    setup(); vox_group_create();
    for (int i=2; i<=8; ++i) on_join_req(&peers[i], i);
    observed(vox_group_member_count() == 8,
             "control experiment: eight-member coordinator roster supported with stub transport");
    return 0;
}
'''


def main():
    crypto = source("sec/vox_crypto.c")
    nonce = crypto[crypto.index("void vox_aead_nonce("):crypto.index("esp_err_t vox_aead_seal(")]
    pieces = [PRELUDE, source("vox_frame.h"), source("sec/vox_replay.h"),
              source("sec/vox_group.h"), source("sec/vox_group_control.h"),
              source("sec/vox_session.h"), source("audio/vox_jitterbuf.h"),
              nonce, STUBS, source("sec/vox_replay.c"), source("sec/vox_group.c"),
              source("sec/vox_group_control.c"), source("audio/vox_jitterbuf.c"), TESTS]
    with tempfile.TemporaryDirectory(prefix="vox-audit-") as tmp:
        c = Path(tmp) / "repro.c"
        exe = Path(tmp) / "repro"
        c.write_text("\n".join(pieces))
        subprocess.run(["gcc", "-std=c11", "-O0", "-g", "-Wall", "-Wextra",
                        "-Wno-unused-parameter", "-Wno-unused-variable", "-fsanitize=undefined,address",
                        str(c), "-o", str(exe)], check=True)
        # LeakSanitizer cannot run under the desktop tool's ptrace wrapper.
        # The doubles allocate no heap; retain address/UB instrumentation.
        subprocess.run([str(exe)], check=True,
                       env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})


if __name__ == "__main__":
    main()
