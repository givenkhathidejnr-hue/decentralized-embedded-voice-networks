/*
 * vox_jitterbuf.h - playout buffer.
 *
 * Sequence-indexed ring, so reordering is handled for free: a frame is
 * written at (seq % capacity) and read in strict sequence order. Playout
 * starts once the buffer reaches its target depth and then runs on the audio
 * clock, one frame every VOX_FRAME_MS, regardless of arrival pattern.
 *
 * The depth setting is the direct expression of the delay-against-loss
 * trade-off the review takes from the VoIP literature: every buffered frame
 * adds VOX_FRAME_MS to end-to-end delay and buys tolerance to that much
 * network jitter. At the default 3 frames of 20 ms the buffer contributes
 * 60 ms of the 150 ms one-way budget, which is why it is a configured
 * experimental variable and not a magic number.
 *
 * A frame that arrives after its playout instant is not late-but-useful; it
 * is counted as late and discarded for playout. Authenticated media reception
 * and actual playout are reported separately; late reception is not useful audio.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "vox_config.h"

typedef struct {
    uint32_t seq;
    uint16_t stream_id;
    uint16_t sender_id;
    int64_t  t_tx_us;        /* sender clock, wrap-corrected */
    int64_t  t_rx_us;        /* our clock, taken in the ESP-NOW callback */
    size_t   nsamp;
    int16_t  pcm[VOX_SAMPLES_PER_FRAME];
} vox_jb_frame_t;

typedef struct {
    uint32_t pushed;
    uint32_t popped;
    uint32_t concealed;      /* playout instants with no frame available */
    uint32_t late;           /* arrived after its playout instant */
    uint32_t duplicate;
    uint32_t overflow;       /* arrived too far ahead of the play cursor */
    uint32_t resyncs;        /* stream restarts / large discontinuities */
    uint32_t max_depth;
    uint32_t media_expected;     /* source indices, including leading/gap losses */
    uint32_t media_received;     /* unique authenticated media positions */
    uint32_t ended_streams;
    uint32_t incomplete_streams; /* replaced without an authenticated END */
    uint32_t silence_ticks;
} vox_jb_stats_t;

void   vox_jb_reset(void);

/* Returns true if the frame was stored. */
bool   vox_jb_push(const vox_jb_frame_t *f);

/*
 * Pop the next frame due for playout. Returns true with a frame, or false
 * when the buffer is still filling or the next frame is missing (the caller
 * should then emit concealment). `out` is untouched on false.
 */
bool   vox_jb_pop(vox_jb_frame_t *out);

size_t vox_jb_depth(void);
void   vox_jb_stats(vox_jb_stats_t *out);
size_t vox_jb_bytes(void);

void vox_jb_end(uint16_t sender, uint16_t stream, uint32_t exclusive_seq);
bool vox_jb_loss_complete(void);
