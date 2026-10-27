#include <string.h>
#include "sec/vox_replay.h"

void vox_replay_reset(vox_replay_t *w)
{
    w->highest = 0;
    w->bitmap  = 0;
    w->primed  = false;
}

bool vox_replay_is_fresh(const vox_replay_t *w, uint32_t seq)
{
    if (!w->primed) {
        return true;
    }
    if (seq > w->highest) {
        return true;                       /* ahead of the window */
    }
    uint32_t age = w->highest - seq;
    if (age >= VOX_REPLAY_WINDOW) {
        return false;                      /* too old to judge, reject */
    }
    return ((w->bitmap >> age) & 1u) == 0u;
}

void vox_replay_commit(vox_replay_t *w, uint32_t seq)
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
            w->bitmap = 0;                 /* window moved entirely past */
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
