/*
 * vox_codec.h - pluggable speech codec.
 *
 * The codec is a swappable stage on purpose. The literature review defines a
 * selection procedure rather than a winner, spanning 3.2 kb/s Codec2 through
 * 8 kb/s G.729.2 to the uncompressed G.711 family, and notes that none of
 * those has been measured on ESP-NOW. Making the codec a build-time choice
 * behind one interface means that comparison is a rebuild rather than a
 * rewrite, and that codec cost can be isolated from protection cost by
 * holding everything else fixed.
 *
 * Default is G.711 u-law: it is in the measured field the review describes,
 * it needs no external dependency, its per-sample cost is a table-free
 * arithmetic operation, and at 20 ms it produces exactly 160 bytes, which
 * fits one ESP-NOW packet with room for the header and a full 16-byte tag.
 * Raw PCM16 is the no-compression control. Codec2 is the low-rate end and
 * needs the codec2 component dropped into components/.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "vox_config.h"

typedef struct {
    uint8_t     id;
    const char *name;
    uint32_t    bitrate_bps;
    size_t      encoded_bytes;   /* per VOX_FRAME_MS frame */

    esp_err_t (*init)(void);
    /* Returns bytes written to `out`, or 0 on failure. */
    size_t    (*encode)(const int16_t *pcm, size_t nsamp, uint8_t *out, size_t out_cap);
    /* Returns samples written to `pcm`, or 0 on failure. */
    size_t    (*decode)(const uint8_t *in, size_t in_len, int16_t *pcm, size_t pcm_cap);
} vox_codec_t;

const vox_codec_t *vox_codec(void);
esp_err_t          vox_codec_init(void);
