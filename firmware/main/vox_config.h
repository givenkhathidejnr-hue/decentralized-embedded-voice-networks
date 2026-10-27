/*
 * vox_config.h - derived compile-time constants and payload-budget arithmetic.
 *
 * Everything the experiment sweeps lives in Kconfig (idf.py menuconfig). This
 * header turns those knobs into the sizes the pipeline needs and refuses, at
 * compile time, any combination whose encoded frame will not fit in one
 * ESP-NOW packet. One audio frame is one packet, by design: it keeps the
 * airtime accounting honest and removes fragmentation as a confounding
 * variable in the receiver-count sweep.
 */
#pragma once

#include <stdint.h>
#include "sdkconfig.h"
#include "esp_now.h"

/* ------------------------------------------------------------------ audio */

#define VOX_SAMPLE_RATE_HZ      CONFIG_VOX_SAMPLE_RATE_HZ
#define VOX_FRAME_MS            CONFIG_VOX_FRAME_MS
#define VOX_SAMPLES_PER_FRAME   ((VOX_SAMPLE_RATE_HZ * VOX_FRAME_MS) / 1000)
#define VOX_FRAME_PCM_BYTES     (VOX_SAMPLES_PER_FRAME * 2)   /* int16 mono */

/* ------------------------------------------------------------------ codec */

#if defined(CONFIG_VOX_CODEC_G711U)
#  define VOX_CODEC_ID          1
#  define VOX_CODEC_NAME        "g711u"
#  define VOX_ENCODED_BYTES     (VOX_SAMPLES_PER_FRAME)        /* 1 byte/sample */
#elif defined(CONFIG_VOX_CODEC_PCM16)
#  define VOX_CODEC_ID          0
#  define VOX_CODEC_NAME        "pcm16"
#  define VOX_ENCODED_BYTES     (VOX_FRAME_PCM_BYTES)
#elif defined(CONFIG_VOX_CODEC_CODEC2)
#  define VOX_CODEC_ID          2
#  define VOX_CODEC_NAME        "codec2_3200"
/* Codec2 3200 consumes 160 samples (20 ms @ 8 kHz) and emits 64 bits. */
#  define VOX_ENCODED_BYTES     ((VOX_SAMPLES_PER_FRAME * 8) / 160)
#else
#  error "No codec selected"
#endif

/* ---------------------------------------------------------- payload budget */

/*
 * ESP-NOW carries at most ESP_NOW_MAX_DATA_LEN application bytes (250 for the
 * v1 frame format). Our own encapsulation costs a 12-byte cleartext header,
 * authenticated as associated data, plus the AEAD tag. The remainder is the
 * plaintext budget shared by the audio sub-header and the encoded speech.
 */
#define VOX_HDR_LEN             12

#ifdef CONFIG_VOX_CRYPTO_ENABLED
#  define VOX_TAG_LEN           CONFIG_VOX_TAG_LEN
#else
#  define VOX_TAG_LEN           0
#endif

#define VOX_MAX_PLAINTEXT       (ESP_NOW_MAX_DATA_LEN - VOX_HDR_LEN - VOX_TAG_LEN)
#define VOX_AUDIO_SUBHDR_LEN    12
#define VOX_AUDIO_PLAINTEXT     (VOX_AUDIO_SUBHDR_LEN + VOX_ENCODED_BYTES)
#define VOX_ON_AIR_BYTES        (VOX_HDR_LEN + VOX_AUDIO_PLAINTEXT + VOX_TAG_LEN)

_Static_assert(VOX_AUDIO_PLAINTEXT <= VOX_MAX_PLAINTEXT,
    "Encoded audio frame does not fit one ESP-NOW packet. Reduce "
    "CONFIG_VOX_FRAME_MS, choose a lower-rate codec, or shorten the tag.");

_Static_assert((VOX_SAMPLE_RATE_HZ * VOX_FRAME_MS) % 1000 == 0,
    "Frame duration must yield a whole number of samples.");

/*
 * Link-layer encapsulation that ESP-NOW adds beneath our payload, used by the
 * byte-count model: MAC header 24 + category 1 + OUI 3 + random 4 +
 * vendor element header 7 + FCS 4 = 43. Excludes PHY preamble, ACKs,
 * contention and retransmissions; this is not measured RF airtime.
 */
#define VOX_LINK_OVERHEAD_BYTES 43

/* --------------------------------------------------------------- identity */

#define VOX_NODE_ID             ((uint16_t)CONFIG_VOX_NODE_ID)
#define VOX_BROADCAST_ID        ((uint16_t)0xFFFF)

/* ------------------------------------------------------------------ limits */

#define VOX_MAX_PEERS           20      /* ESP-NOW acknowledged-unicast ceiling */
#define VOX_MAX_GROUP_MEMBERS   8       /* RQ2/RQ3 scope: "a small fixed membership
                                          * set" -- this study's own measured and
                                          * modelled audience ceilings are single
                                          * digits (RESULTS_RQ1.md), so 8 is a
                                          * generous bound, not a platform limit */
#define VOX_REPLAY_WINDOW       CONFIG_VOX_REPLAY_WINDOW
#define VOX_EPOCH_MAX_FRAMES    ((uint32_t)CONFIG_VOX_EPOCH_MAX_FRAMES)

/* Wi-Fi channel every node in an experiment must share. */
#define VOX_WIFI_CHANNEL        1
