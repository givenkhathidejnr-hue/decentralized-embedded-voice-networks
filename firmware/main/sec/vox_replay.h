/*
 * vox_replay.h - bounded sliding replay window.
 *
 * Sequential freshness: a frame is accepted only if its sequence number has
 * not been seen and is not older than the window. The window is a 64-bit
 * bitmap anchored at the highest accepted sequence number.
 *
 * THE IMPORTANT PART - check and commit are separate calls, and commit must
 * happen only after the AEAD tag has verified.
 *
 * The desynchronisation attack described in the 802.15.4 MAC-security
 * literature works by injecting frames carrying very large counters, dragging
 * the receiver's expected counter forward so that legitimate frames fall
 * outside the window and are discarded. That attack succeeds only if the
 * receiver advances its window on the strength of the counter alone. Here the
 * window is advanced exclusively by vox_replay_commit(), which the receive
 * path calls after authentication succeeds. An attacker without the current
 * direction key therefore cannot move the window at all; the worst it can do
 * is spend our CPU on failed verifications, which is a counted availability
 * event rather than a silent link failure.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "vox_config.h"

_Static_assert(VOX_REPLAY_WINDOW >= 16 && VOX_REPLAY_WINDOW <= 64,
               "replay window must fit the 64-bit bitmap");

typedef struct {
    uint32_t highest;    /* highest sequence number accepted so far */
    uint64_t bitmap;     /* bit i set => (highest - i) already accepted */
    bool     primed;     /* false until the first frame is accepted */
} vox_replay_t;

void vox_replay_reset(vox_replay_t *w);

/*
 * Pure test, no state change. Returns true if `seq` is plausibly fresh.
 * Safe to call on unauthenticated input: it is the cheap early reject that
 * saves a decryption on an obvious replay.
 */
bool vox_replay_is_fresh(const vox_replay_t *w, uint32_t seq);

/*
 * Record `seq` as accepted and slide the window. CALL ONLY AFTER THE AEAD
 * TAG HAS VERIFIED.
 */
void vox_replay_commit(vox_replay_t *w, uint32_t seq);
