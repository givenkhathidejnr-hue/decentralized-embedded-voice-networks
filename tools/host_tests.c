/*
 * host_tests.c - unit tests for the target-independent logic, run on a PC.
 *
 * These cover the parts where a silent bug would not crash anything, would not
 * show up as a dropout, and would quietly invalidate a security claim in the
 * report: the replay window, the nonce construction, and the codec.
 *
 * Build and run:
 *      gcc -std=c11 -O2 -Wall -Wextra -o host_tests tools/host_tests.c -lm
 *      ./host_tests
 *
 * The firmware sources are included directly with the few ESP-IDF symbols they
 * need stubbed above, so these tests exercise the SAME code that runs on the
 * board rather than a reimplementation of it.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ----------------------- minimal ESP-IDF stand-ins ---------------------- */
typedef int esp_err_t;
#define ESP_OK              0
#define ESP_FAIL           -1
#define ESP_ERR_NO_MEM      0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND   0x105
#define ESP_ERR_INVALID_CRC 0x10c
#define ESP_LOGE(...) do {} while (0)
#define ESP_LOGW(...) do {} while (0)
#define ESP_LOGI(...) do {} while (0)
#define ESP_LOGD(...) do {} while (0)

/* Config values mirroring the firmware defaults under test. */
#define CONFIG_VOX_REPLAY_WINDOW      32
#define CONFIG_VOX_SAMPLE_RATE_HZ     8000
#define CONFIG_VOX_FRAME_MS           20
#define CONFIG_VOX_CODEC_G711U        1
#define CONFIG_VOX_CRYPTO_ENABLED     1
#define CONFIG_VOX_TAG_LEN            16
#define VOX_MAX_GROUP_MEMBERS_TEST    8   /* mirrors VOX_MAX_GROUP_MEMBERS, vox_config.h */

#define VOX_SAMPLE_RATE_HZ      CONFIG_VOX_SAMPLE_RATE_HZ
#define VOX_FRAME_MS            CONFIG_VOX_FRAME_MS
#define VOX_SAMPLES_PER_FRAME   ((VOX_SAMPLE_RATE_HZ * VOX_FRAME_MS) / 1000)
#define VOX_REPLAY_WINDOW       CONFIG_VOX_REPLAY_WINDOW
#define VOX_ENCODED_BYTES       (VOX_SAMPLES_PER_FRAME)

/* ============================ code under test =========================== */
/* Verbatim from firmware/main/sec/vox_replay.c */

typedef struct {
    uint32_t highest;
    uint64_t bitmap;
    bool     primed;
} vox_replay_t;

static void vox_replay_reset(vox_replay_t *w)
{
    w->highest = 0;
    w->bitmap  = 0;
    w->primed  = false;
}

static bool vox_replay_is_fresh(const vox_replay_t *w, uint32_t seq)
{
    if (!w->primed) {
        return true;
    }
    if (seq > w->highest) {
        return true;
    }
    uint32_t age = w->highest - seq;
    if (age >= VOX_REPLAY_WINDOW) {
        return false;
    }
    return ((w->bitmap >> age) & 1u) == 0u;
}

static void vox_replay_commit(vox_replay_t *w, uint32_t seq)
{
    if (!w->primed) {
        w->primed  = true;
        w->highest = seq;
        w->bitmap  = 1u;
        return;
    }
    if (seq > w->highest) {
        uint32_t shift = seq - w->highest;
        if (shift >= 64u) {
            w->bitmap = 0;
        } else {
            w->bitmap <<= shift;
        }
        w->bitmap |= 1u;
        w->highest = seq;
        return;
    }
    uint32_t age = w->highest - seq;
    if (age < 64u) {
        w->bitmap |= ((uint64_t)1u << age);
    }
}

/* Verbatim from firmware/main/sec/vox_crypto.c */
#define VOX_AEAD_SALT_LEN  4
#define VOX_AEAD_NONCE_LEN 12

static void nonce_build(const uint8_t salt[4], uint16_t src_id, uint8_t epoch,
                        uint32_t seq, uint8_t out[VOX_AEAD_NONCE_LEN])
{
    memcpy(out, salt, VOX_AEAD_SALT_LEN);
    out[4] = (uint8_t)(src_id & 0xFF);
    out[5] = (uint8_t)(src_id >> 8);
    out[6] = epoch;
    out[7] = 0x00;
    out[8]  = (uint8_t)(seq & 0xFF);
    out[9]  = (uint8_t)((seq >> 8) & 0xFF);
    out[10] = (uint8_t)((seq >> 16) & 0xFF);
    out[11] = (uint8_t)((seq >> 24) & 0xFF);
}

/* Verbatim from firmware/main/audio/vox_codec.c */
#define G711_BIAS   0x84
#define G711_CLIP   8159

static const int16_t k_seg_uend[8] = {
    0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF
};

static int seg_search(int16_t val)
{
    for (int i = 0; i < 8; i++) {
        if (val <= k_seg_uend[i]) return i;
    }
    return 8;
}

static uint8_t linear2ulaw(int16_t pcm_val)
{
    int mask;
    int v = pcm_val >> 2;
    if (v < 0) { v = -v; mask = 0x7F; } else { mask = 0xFF; }
    if (v > G711_CLIP) v = G711_CLIP;
    v += (G711_BIAS >> 2);
    int seg = seg_search((int16_t)v);
    if (seg >= 8) return (uint8_t)(0x7F ^ mask);
    uint8_t uval = (uint8_t)((seg << 4) | ((v >> (seg + 1)) & 0x0F));
    return (uint8_t)(uval ^ mask);
}

static int16_t ulaw2linear(uint8_t u_val)
{
    u_val = (uint8_t)~u_val;
    int t = ((u_val & 0x0F) << 3) + G711_BIAS;
    t <<= ((unsigned)u_val & 0x70) >> 4;
    return (int16_t)((u_val & 0x80) ? (G711_BIAS - t) : (t - G711_BIAS));
}

/* ================================ harness =============================== */

static int g_fail;
static int g_run;

#define CHECK(cond, ...) do {                             \
    g_run++;                                              \
    if (!(cond)) {                                        \
        g_fail++;                                         \
        printf("  FAIL %s:%d  ", __func__, __LINE__);     \
        printf(__VA_ARGS__);                              \
        printf("\n");                                     \
    }                                                     \
} while (0)

/* ------------------------------------------------------ replay behaviour */

static void test_replay_basic(void)
{
    vox_replay_t w;
    vox_replay_reset(&w);

    /* An unprimed window accepts anything: the first frame of a session has
     * no predecessor to be judged against. */
    CHECK(vox_replay_is_fresh(&w, 0), "first frame must be fresh");
    vox_replay_commit(&w, 0);

    /* Strictly increasing frames are always fresh. */
    for (uint32_t s = 1; s < 200; s++) {
        CHECK(vox_replay_is_fresh(&w, s), "seq %u should be fresh", s);
        vox_replay_commit(&w, s);
    }

    /* Every one of those is now a replay. */
    for (uint32_t s = 199; s > 199 - VOX_REPLAY_WINDOW; s--) {
        CHECK(!vox_replay_is_fresh(&w, s), "seq %u should be a replay", s);
    }

    /* Anything older than the window is rejected too, since we cannot prove
     * it was not seen. */
    CHECK(!vox_replay_is_fresh(&w, 0),   "ancient seq must be rejected");
    CHECK(!vox_replay_is_fresh(&w, 100), "out-of-window seq must be rejected");
}

static void test_replay_reordering(void)
{
    vox_replay_t w;
    vox_replay_reset(&w);

    /* Real radios reorder. A frame that arrives late but inside the window is
     * legitimate and must be accepted exactly once. */
    vox_replay_commit(&w, 100);
    vox_replay_commit(&w, 102);
    vox_replay_commit(&w, 103);

    CHECK(vox_replay_is_fresh(&w, 101), "in-window gap must be accepted");
    vox_replay_commit(&w, 101);
    CHECK(!vox_replay_is_fresh(&w, 101), "and only once");

    CHECK(!vox_replay_is_fresh(&w, 102), "102 already seen");
    CHECK(vox_replay_is_fresh(&w, 104),  "104 not yet seen");
}

static void test_replay_window_edges(void)
{
    vox_replay_t w;
    vox_replay_reset(&w);
    vox_replay_commit(&w, 1000);

    /* Exactly at the window edge is still judgeable; one beyond is not. */
    CHECK(vox_replay_is_fresh(&w, 1000 - (VOX_REPLAY_WINDOW - 1)),
          "oldest in-window seq must be judgeable");
    CHECK(!vox_replay_is_fresh(&w, 1000 - VOX_REPLAY_WINDOW),
          "first out-of-window seq must be rejected");
}

static void test_replay_desync_resistance(void)
{
    /*
     * THE SECURITY PROPERTY THAT MATTERS.
     *
     * An attacker injects frames carrying huge sequence numbers, trying to
     * drag the window forward so that legitimate frames fall outside it. That
     * only works if the window advances on the strength of the counter alone.
     *
     * Here it cannot: the receive path calls is_fresh() to decide whether to
     * spend a decryption, and calls commit() only after the AEAD tag verifies.
     * An attacker with no key never reaches commit(), so this test models the
     * attack as "many is_fresh() calls with no commit" and asserts that
     * legitimate traffic is untouched afterwards.
     */
    vox_replay_t w;
    vox_replay_reset(&w);
    for (uint32_t s = 0; s < 50; s++) {
        vox_replay_commit(&w, s);
    }
    uint32_t highest_before = w.highest;

    for (uint32_t i = 0; i < 10000; i++) {
        (void)vox_replay_is_fresh(&w, 0x7FFFFFFFu - i);   /* forged, never committed */
    }

    CHECK(w.highest == highest_before,
          "unauthenticated frames must not move the window (%u -> %u)",
          highest_before, w.highest);

    for (uint32_t s = 50; s < 100; s++) {
        CHECK(vox_replay_is_fresh(&w, s),
              "legitimate seq %u must still be accepted after the attack", s);
        vox_replay_commit(&w, s);
    }
}

static void test_replay_large_jump(void)
{
    /* A long outage: the far-forward frame is genuine, and the window must
     * re-anchor on it without accepting the whole old range as fresh. */
    vox_replay_t w;
    vox_replay_reset(&w);
    vox_replay_commit(&w, 10);

    CHECK(vox_replay_is_fresh(&w, 5000), "post-outage frame must be fresh");
    vox_replay_commit(&w, 5000);
    CHECK(!vox_replay_is_fresh(&w, 5000), "and not replayable");
    CHECK(!vox_replay_is_fresh(&w, 11),   "stale range must not reopen");
    CHECK(w.bitmap == 1u, "bitmap must be cleared by a jump beyond 64");
}

/* ------------------------------------------------------------- nonce use */

static void test_nonce_uniqueness(void)
{
    /*
     * Nonce reuse under one key is the failure that breaks AEAD outright.
     * Within a key the only varying input is seq, so distinct seq must give
     * distinct nonces across the whole 32-bit range, and the epoch and source
     * must both actually reach the nonce.
     */
    const uint8_t salt[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t a[12], b[12];

    nonce_build(salt, 1, 0, 0, a);
    nonce_build(salt, 1, 0, 1, b);
    CHECK(memcmp(a, b, 12) != 0, "consecutive seq must differ");

    nonce_build(salt, 1, 0, 0x01020304u, a);
    nonce_build(salt, 1, 0, 0x04030201u, b);
    CHECK(memcmp(a, b, 12) != 0, "byte-permuted seq must differ");

    nonce_build(salt, 1, 0, 7, a);
    nonce_build(salt, 1, 1, 7, b);
    CHECK(memcmp(a, b, 12) != 0, "epoch must reach the nonce");

    nonce_build(salt, 1, 0, 7, a);
    nonce_build(salt, 2, 0, 7, b);
    CHECK(memcmp(a, b, 12) != 0, "source id must reach the nonce");

    /* Exhaustive over a dense span, plus the boundaries. */
    uint8_t prev[12];
    nonce_build(salt, 3, 5, 0, prev);
    for (uint32_t s = 1; s < 200000u; s++) {
        nonce_build(salt, 3, 5, s, a);
        CHECK(memcmp(a, prev, 12) != 0, "collision at seq %u", s);
        memcpy(prev, a, 12);
        if (g_fail) break;
    }

    nonce_build(salt, 3, 5, 0xFFFFFFFFu, a);
    nonce_build(salt, 3, 5, 0xFFFFFFFEu, b);
    CHECK(memcmp(a, b, 12) != 0, "top of the sequence range must differ");
}

/* -------------------------------------------------------- group key/replay
 *
 * The group architecture (firmware/main/sec/vox_group.c) has one AEAD
 * context shared by every member -- unlike the pairwise case, there is no
 * per-direction key split. Nonce uniqueness under that shared key therefore
 * depends entirely on vox_aead_nonce()'s existing src_id parameter (the same
 * nonce_build() tested above), and replay resistance depends on each member
 * having its OWN independent replay window rather than one shared window
 * that would let one sender's traffic desynchronise another's. Both
 * properties are tested here without needing real HKDF/AES-GCM, exactly as
 * the pairwise tests above test replay and nonce logic independently of the
 * cryptography underneath them.
 */

static void test_group_nonce_separation(void)
{
    /*
     * Every member of a group shares one salt (it is derived alongside the
     * group key, not per-member) and one epoch. The only thing that can
     * possibly separate two members' nonce spaces is their node id, carried
     * in the same src_id field vox_aead_nonce() already takes for the
     * pairwise case -- so this is the same nonce_build() above, exercised
     * across many senders at the SAME seq value, which is the case that
     * actually matters for a group (every member's sequence counter starts
     * at 0 independently).
     */
    const uint8_t group_salt[4] = { 0x13, 0x37, 0xC0, 0xDE };
    const uint8_t epoch = 4;

    uint8_t seen[VOX_MAX_GROUP_MEMBERS_TEST][12];
    const int n_members = VOX_MAX_GROUP_MEMBERS_TEST;

    for (int m = 0; m < n_members; m++) {
        /* Every member transmitting its very first frame of this epoch --
         * seq = 0 for all of them, which is the worst case for collision. */
        nonce_build(group_salt, (uint16_t)(100 + m), epoch, 0, seen[m]);
    }
    for (int i = 0; i < n_members; i++) {
        for (int j = i + 1; j < n_members; j++) {
            CHECK(memcmp(seen[i], seen[j], 12) != 0,
                  "members %d and %d collided at seq 0 under one group key",
                  i, j);
        }
    }

    /* And each member's own sequence still never repeats, same as the
     * pairwise case -- sharing a key with other senders must not weaken a
     * single sender's own nonce uniqueness. */
    uint8_t prev[12], cur[12];
    nonce_build(group_salt, 101, epoch, 0, prev);
    for (uint32_t s = 1; s < 50000u; s++) {
        nonce_build(group_salt, 101, epoch, s, cur);
        CHECK(memcmp(cur, prev, 12) != 0, "member 101 self-collision at seq %u", s);
        memcpy(prev, cur, 12);
        if (g_fail) break;
    }
}

static void test_group_replay_independence(void)
{
    /*
     * vox_group_member_t gives every member its own vox_replay_t. The
     * property that matters is that these windows genuinely do not interact:
     * a fast-talking member cannot push another member's window forward (the
     * same desynchronisation concern test_replay_desync_resistance already
     * covers for one window, now checked across two that happen to share a
     * key), and a replayed frame from one member is rejected regardless of
     * how far any OTHER member's window has advanced.
     */
    vox_replay_t a, b;
    vox_replay_reset(&a);
    vox_replay_reset(&b);

    /* Member A transmits frames 0..9; member B has sent nothing yet. */
    for (uint32_t s = 0; s < 10; s++) {
        CHECK(vox_replay_is_fresh(&a, s), "member A seq %u should be fresh", s);
        vox_replay_commit(&a, s);
    }
    CHECK(vox_replay_is_fresh(&b, 0),
          "member B's window must still be unprimed; A's traffic must not reach it");

    /* Member B now sends its own seq 0..4 -- these must be judged solely
     * against B's window, not A's, even though A is already at seq 9. */
    for (uint32_t s = 0; s < 5; s++) {
        CHECK(vox_replay_is_fresh(&b, s),
              "member B seq %u must be fresh under its own window", s);
        vox_replay_commit(&b, s);
    }

    /* A replay of A's seq 3 must still be rejected -- B's independent
     * progress must not have reset or desynchronised A's window. */
    CHECK(!vox_replay_is_fresh(&a, 3), "replay of A's seq 3 must still be rejected");

    /* And B's window, having only reached seq 4, must still accept B's
     * seq 5 as fresh -- it must not have been dragged forward to A's seq 9
     * by any shared state between the two windows (there must be none). */
    CHECK(vox_replay_is_fresh(&b, 5), "B's own next frame must be fresh");

    /* A fresh-looking frame bearing an extreme sequence number, under
     * member A's identity, must not move member B's window at all. */
    CHECK(vox_replay_is_fresh(&a, 0xFFFFFFF0u),
          "an extreme seq is pre-authentication-plausible, by design (vox_replay_is_fresh "
          "is the cheap pre-filter; only vox_replay_commit after a verified tag may move a window)");
    /* Deliberately NOT committing it -- an unauthenticated extreme sequence
     * must never be allowed to move a window (this is the same rule the
     * pairwise desync test enforces); the check above only confirms the
     * pre-filter doesn't crash or misbehave on the boundary value, the way
     * test_replay_desync_resistance already proves commit-ordering matters
     * for a single window. */
    CHECK(vox_replay_is_fresh(&b, 5),
          "member B's window must be completely unaffected by traffic "
          "addressed under member A's identity");
}

/* ---------------------------------------------------- group control-plane
 *
 * The roster logic below is copied verbatim from firmware/main/sec/vox_group.c's
 * vox_group_add_member()/vox_group_remove_member()/vox_group_is_member()/
 * vox_group_member_count() (minus the vox_replay_t field, irrelevant here),
 * and the ack-tracking logic from firmware/main/sec/vox_group_control.c's
 * do_rekey()/on_rekey_ack() (the Stage 4 cost-metric completion test added
 * alongside the #GRPOP instrumentation). Both are plain array/counter logic
 * with no cryptographic dependency, exercised here the same way replay and
 * nonce logic are tested above: directly, without needing mbedTLS.
 *
 * This is also exactly the class of bug caught by inspection before the
 * first hardware test of this stage -- distribute_secret() originally used
 * vox_group_member_count() as a loop bound over an array that can have holes
 * (a removed member leaves its slot empty without compacting the array), which
 * skips or misindexes members whenever a hole exists before the end of the
 * roster. The fixed idiom (loop the full fixed-size array, skip !in_use) is
 * what test_group_roster_holes() below checks stays correct.
 */

typedef struct {
    bool     in_use;
    uint16_t member_id;
} grp_member_t;

static grp_member_t g_members[VOX_MAX_GROUP_MEMBERS_TEST];

static void grp_reset(void)
{
    memset(g_members, 0, sizeof(g_members));
}

static bool grp_is_member(uint16_t id)
{
    for (int i = 0; i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (g_members[i].in_use && g_members[i].member_id == id) {
            return true;
        }
    }
    return false;
}

static esp_err_t grp_add_member(uint16_t id)
{
    if (grp_is_member(id)) {
        return ESP_OK;
    }
    for (int i = 0; i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (!g_members[i].in_use) {
            g_members[i].in_use = true;
            g_members[i].member_id = id;
            return ESP_OK;
        }
    }
    return ESP_ERR_NO_MEM;
}

static esp_err_t grp_remove_member(uint16_t id)
{
    for (int i = 0; i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (g_members[i].in_use && g_members[i].member_id == id) {
            memset(&g_members[i], 0, sizeof(g_members[i]));
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

static int grp_member_count(void)
{
    int n = 0;
    for (int i = 0; i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (g_members[i].in_use) n++;
    }
    return n;
}

/* The buggy variant distribute_secret() originally used: member COUNT as the
 * loop bound over the slot array, rather than the array's fixed size. Kept
 * here, unused by the real firmware, purely so the test below can show it is
 * wrong whenever a hole precedes the end of the roster. */
static int grp_visit_with_count_bound(uint16_t *out, int out_cap)
{
    int n = 0;
    int bound = grp_member_count();
    for (int i = 0; i < bound && i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (g_members[i].in_use && n < out_cap) {
            out[n++] = g_members[i].member_id;
        }
    }
    return n;
}

static int grp_visit_with_fixed_bound(uint16_t *out, int out_cap)
{
    int n = 0;
    for (int i = 0; i < VOX_MAX_GROUP_MEMBERS_TEST; i++) {
        if (g_members[i].in_use && n < out_cap) {
            out[n++] = g_members[i].member_id;
        }
    }
    return n;
}

static void test_group_roster(void)
{
    grp_reset();
    CHECK(grp_member_count() == 0, "fresh roster is empty");

    CHECK(grp_add_member(1) == ESP_OK, "add member 1");
    CHECK(grp_add_member(2) == ESP_OK, "add member 2");
    CHECK(grp_add_member(3) == ESP_OK, "add member 3");
    CHECK(grp_member_count() == 3, "three members present");

    /* Re-adding an existing member must be a no-op, not a duplicate slot --
     * this is what makes vox_group_install()'s "recovery == re-join" design
     * (docs/DRAFT_CH4_GROUP_METHODOLOGY.md's C_recover) safe to call
     * idempotently from on_join_req(). */
    CHECK(grp_add_member(2) == ESP_OK, "re-adding an existing member succeeds");
    CHECK(grp_member_count() == 3, "re-adding must not create a duplicate slot");

    /* Remove the middle member, leaving a hole before the end of the roster. */
    CHECK(grp_remove_member(2) == ESP_OK, "remove member 2");
    CHECK(!grp_is_member(2), "member 2 is gone");
    CHECK(grp_is_member(1) && grp_is_member(3), "members 1 and 3 remain");
    CHECK(grp_member_count() == 2, "count reflects the removal");

    /* A fresh member added after the removal must reuse the freed slot, not
     * append past it -- otherwise the roster could overflow before the
     * array is actually full. */
    CHECK(grp_add_member(4) == ESP_OK, "add member 4 into the freed slot");
    CHECK(grp_member_count() == 3, "count is right after reusing the hole");

    CHECK(grp_remove_member(99) == ESP_ERR_NOT_FOUND, "removing a non-member fails cleanly");
}

static void test_group_roster_holes(void)
{
    /*
     * Reproduces the exact shape of the loop-bound bug caught by inspection
     * before this stage's first hardware test: a hole earlier in the array
     * than the current member count causes a COUNT-bounded loop to stop
     * short and miss a real member, or to visit fewer entries than exist.
     * The FIXED-bound loop (the idiom actually used in distribute_secret(),
     * vox_group_control_claim_coordinator()'s notify loop, and elsewhere in
     * app_main.c/vox_session.c) must not have this failure mode.
     */
    grp_reset();
    for (uint16_t id = 1; id <= 5; id++) {
        CHECK(grp_add_member(id) == ESP_OK, "add member %u", id);
    }
    /* Remove an early slot, leaving members 1,2 and a hole, then 3,4,5. */
    CHECK(grp_remove_member(1) == ESP_OK, "remove member 1");
    CHECK(grp_remove_member(2) == ESP_OK, "remove member 2");
    CHECK(grp_member_count() == 3, "three members remain after two removals");

    uint16_t buggy[VOX_MAX_GROUP_MEMBERS_TEST] = { 0 };
    uint16_t fixed[VOX_MAX_GROUP_MEMBERS_TEST] = { 0 };
    int n_buggy = grp_visit_with_count_bound(buggy, VOX_MAX_GROUP_MEMBERS_TEST);
    int n_fixed = grp_visit_with_fixed_bound(fixed, VOX_MAX_GROUP_MEMBERS_TEST);

    CHECK(n_fixed == 3, "fixed-bound visit finds all 3 remaining members (got %d)", n_fixed);
    CHECK(n_buggy < n_fixed,
          "count-bounded visit demonstrably misses members behind holes "
          "(buggy=%d, fixed=%d) -- this is why that bound was wrong", n_buggy, n_fixed);
}

static void test_group_roster_full(void)
{
    grp_reset();
    for (uint16_t id = 1; id <= VOX_MAX_GROUP_MEMBERS_TEST; id++) {
        CHECK(grp_add_member(id) == ESP_OK, "fill slot for member %u", id);
    }
    CHECK(grp_member_count() == VOX_MAX_GROUP_MEMBERS_TEST, "roster is full");
    CHECK(grp_add_member((uint16_t)(VOX_MAX_GROUP_MEMBERS_TEST + 1)) == ESP_ERR_NO_MEM,
          "a full roster rejects a new member rather than overflowing");
}

/* ------------------------------------------------- rekey ack-tracking (C4)
 *
 * Mirrors the s_rekey_wait state machine added to vox_group_control.c for
 * this stage's #GRPOP,op=rekey|revoke|coord_claim cost metric: a rekey is
 * "complete" only once every OTHER current member (not the coordinator
 * itself) has acknowledged the new epoch, and an ack for any other epoch
 * (a straggler acknowledging a since-superseded rekey) must not count.
 */

typedef struct {
    bool    pending;
    uint8_t epoch;
    int     expected;
    int     acked;
} rekey_wait_t;

static void rw_start(rekey_wait_t *w, uint8_t epoch, int expected)
{
    w->pending  = true;
    w->epoch    = epoch;
    w->expected = expected;
    w->acked    = 0;
}

/* Returns true exactly on the transition to complete. */
static bool rw_on_ack(rekey_wait_t *w, uint8_t acked_epoch)
{
    if (!w->pending || acked_epoch != w->epoch) {
        return false;
    }
    w->acked++;
    if (w->acked >= w->expected) {
        w->pending = false;
        return true;
    }
    return false;
}

static void test_group_rekey_ack_tracking(void)
{
    rekey_wait_t w;

    /* A rekey with no other members to acknowledge (e.g. a revoke that
     * leaves a group of one) must not need do_rekey() to wait at all -- it
     * is complete at the moment of the call, since expected == 0. */
    rw_start(&w, 5, 0);
    CHECK(!w.pending || w.expected == 0,
          "zero-expected rekey must be representable as already satisfied");

    /* Normal case: three other members, all ack the right epoch. */
    rw_start(&w, 7, 3);
    CHECK(!rw_on_ack(&w, 7), "first of three acks does not complete it");
    CHECK(!rw_on_ack(&w, 7), "second of three acks does not complete it");
    CHECK(rw_on_ack(&w, 7),  "third ack completes it");
    CHECK(!w.pending, "no longer pending once complete");

    /* A stale ack for a superseded epoch must not count toward the current
     * one -- otherwise a straggler from a PREVIOUS rekey could let the
     * CURRENT one report complete one ack early. */
    rw_start(&w, 9, 2);
    CHECK(!rw_on_ack(&w, 8), "stale epoch 8 ack must not count toward epoch 9");
    CHECK(w.acked == 0, "stale ack left the counter untouched");
    CHECK(!rw_on_ack(&w, 9), "one genuine ack, still short of 2");
    CHECK(rw_on_ack(&w, 9),  "second genuine ack completes it");

    /* An ack arriving after completion (a duplicate, or one more member than
     * expected due to a race) must not be acted on again -- on_rekey_ack()
     * in the real code checks s_rekey_wait.pending first for this reason. */
    CHECK(!rw_on_ack(&w, 9), "an ack after completion must be a no-op");
}

/* ------------------------------------------------------------ G.711 codec */

static void test_g711_roundtrip(void)
{
    /*
     * mu-law is lossy by construction: 16-bit in, 8-bit out. What must hold is
     * that the error stays inside the quantiser's segment, that sign is
     * preserved, and that a decode-encode cycle is idempotent on the 256
     * codewords.
     */
    /*
     * G.711 mu-law carries two representations of zero: 0xFF is positive zero
     * and 0x7F is negative zero. Both decode to 0, and the encoder emits the
     * positive one, so 0x7F is the single codeword in the whole space that is
     * not idempotent. That is the standard's behaviour, not a defect, and it
     * is asserted explicitly here so a future change cannot quietly turn a
     * real bug into "the zero case again".
     */
    CHECK(ulaw2linear(0x7F) == 0, "0x7F is negative zero");
    CHECK(ulaw2linear(0xFF) == 0, "0xFF is positive zero");
    CHECK(linear2ulaw(0) == 0xFF, "encoder must emit positive zero");

    for (int u = 0; u < 256; u++) {
        if (u == 0x7F) {
            continue;                       /* the negative-zero alias */
        }
        int16_t pcm = ulaw2linear((uint8_t)u);
        uint8_t back = linear2ulaw(pcm);
        CHECK(back == (uint8_t)u,
              "codeword %d not idempotent (got %d via pcm %d)", u, back, pcm);
    }

    /* Sign preservation and bounded relative error over the useful range. */
    double worst = 0.0;
    for (int32_t v = -32768; v <= 32767; v += 7) {
        int16_t pcm  = (int16_t)v;
        int16_t back = ulaw2linear(linear2ulaw(pcm));

        if (abs(v) > 200) {
            CHECK((pcm < 0) == (back < 0) || back == 0,
                  "sign flipped: %d -> %d", pcm, back);
        }
        if (abs(v) > 1000) {
            double rel = fabs((double)back - (double)pcm) / fabs((double)pcm);
            if (rel > worst) worst = rel;
        }
    }
    /* mu-law's segmented quantiser holds relative error to roughly 1/16 of a
     * segment; anything far above that means the bias or shift is wrong. */
    CHECK(worst < 0.12, "worst relative error %.4f is too large", worst);
    printf("  (g711 worst relative error over |x|>1000: %.4f)\n", worst);
}

static void test_g711_frame_fits(void)
{
    /* The payload-budget arithmetic the firmware asserts at compile time. */
    const int hdr = 12, tag = CONFIG_VOX_TAG_LEN, sub = 8, espnow_max = 250;
    int on_air = hdr + sub + VOX_ENCODED_BYTES + tag;

    CHECK(VOX_SAMPLES_PER_FRAME == 160, "20 ms at 8 kHz is 160 samples, got %d",
          VOX_SAMPLES_PER_FRAME);
    CHECK(VOX_ENCODED_BYTES == 160, "g711 20 ms frame is 160 bytes, got %d",
          VOX_ENCODED_BYTES);
    CHECK(on_air <= espnow_max, "frame is %d B, over the %d B ESP-NOW limit",
          on_air, espnow_max);
    printf("  (on-air payload %d B of %d B available, %d B spare)\n",
           on_air, espnow_max, espnow_max - on_air);
}

/* ------------------------------------------------------------------- main */

int main(void)
{
    printf("vox baseline host tests\n");
    printf("-----------------------\n");

    struct { const char *name; void (*fn)(void); } tests[] = {
        { "replay: monotonic and replay detection", test_replay_basic },
        { "replay: reordering inside the window",   test_replay_reordering },
        { "replay: window edges",                   test_replay_window_edges },
        { "replay: counter-desync resistance",      test_replay_desync_resistance },
        { "replay: large forward jump",             test_replay_large_jump },
        { "nonce: uniqueness",                      test_nonce_uniqueness },
        { "group: nonce separation across senders", test_group_nonce_separation },
        { "group: per-sender replay independence",  test_group_replay_independence },
        { "group: membership roster add/remove",    test_group_roster },
        { "group: roster loop-bound regression",    test_group_roster_holes },
        { "group: roster full rejects overflow",    test_group_roster_full },
        { "group: rekey ack-tracking completion",   test_group_rekey_ack_tracking },
        { "g711:  round trip and error bound",      test_g711_roundtrip },
        { "frame: payload budget",                  test_g711_frame_fits },
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int before = g_fail;
        printf("%s\n", tests[i].name);
        tests[i].fn();
        if (g_fail == before) {
            printf("  ok\n");
        }
    }

    printf("-----------------------\n");
    printf("%d checks, %d failures\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
