#include <string.h>
#include "audio/vox_codec.h"
#include "esp_log.h"

static const char *TAG = "vox.codec";

/*
 * Each codec is compiled only when it is the selected one. Keeping the others
 * out of the image entirely avoids dead code in flash and, more usefully,
 * means a mistake in an unselected codec cannot silently affect the build the
 * measurements were taken with.
 */

/* =============================== G.711 u-law ============================= */
#if defined(CONFIG_VOX_CODEC_G711U)
/*
 * ITU-T G.711 mu-law, the classic Sun reference construction: 14-bit input,
 * bias, segment search, 8-bit sign/exponent/mantissa output. Exact and
 * branch-light; no lookup table, so it costs no data RAM, which matters on a
 * WROOM-32 without PSRAM.
 */

#define G711_BIAS   0x84
#define G711_CLIP   8159

static const int16_t k_seg_uend[8] = {
    0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF
};

static int seg_search(int16_t val)
{
    for (int i = 0; i < 8; i++) {
        if (val <= k_seg_uend[i]) {
            return i;
        }
    }
    return 8;
}

static uint8_t linear2ulaw(int16_t pcm_val)
{
    int mask;
    int v = pcm_val >> 2;              /* 16-bit -> 14-bit */

    if (v < 0) {
        v = -v;
        mask = 0x7F;
    } else {
        mask = 0xFF;
    }
    if (v > G711_CLIP) {
        v = G711_CLIP;
    }
    v += (G711_BIAS >> 2);

    int seg = seg_search((int16_t)v);
    if (seg >= 8) {
        return (uint8_t)(0x7F ^ mask);
    }
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

static esp_err_t codec_init_(void) { return ESP_OK; }

static size_t codec_encode_(const int16_t *pcm, size_t nsamp, uint8_t *out, size_t cap)
{
    if (cap < nsamp) {
        return 0;
    }
    for (size_t i = 0; i < nsamp; i++) {
        out[i] = linear2ulaw(pcm[i]);
    }
    return nsamp;
}

static size_t codec_decode_(const uint8_t *in, size_t in_len, int16_t *pcm, size_t cap)
{
    if (cap < in_len) {
        return 0;
    }
    for (size_t i = 0; i < in_len; i++) {
        pcm[i] = ulaw2linear(in[i]);
    }
    return in_len;
}

/* ================================ PCM16 ================================= */
#elif defined(CONFIG_VOX_CODEC_PCM16)

static esp_err_t codec_init_(void) { return ESP_OK; }

static size_t codec_encode_(const int16_t *pcm, size_t nsamp, uint8_t *out, size_t cap)
{
    size_t n = nsamp * 2;
    if (cap < n) {
        return 0;
    }
    memcpy(out, pcm, n);
    return n;
}

static size_t codec_decode_(const uint8_t *in, size_t in_len, int16_t *pcm, size_t cap)
{
    size_t n = in_len / 2;
    if (cap < n) {
        return 0;
    }
    memcpy(pcm, in, n * 2);
    return n;
}

/* ================================ Codec2 ================================ */
#elif defined(CONFIG_VOX_CODEC_CODEC2)
/*
 * Integration point. Drop the codec2 sources into firmware/components/codec2
 * with a CMakeLists.txt registering them, and add "codec2" to REQUIRES in
 * main/CMakeLists.txt.
 *
 * Mode 3200 consumes exactly 160 samples (20 ms) and emits 8 bytes. One
 * ESP-NOW packet may carry several such sub-frames back to back, so
 * CONFIG_VOX_FRAME_MS may be any whole multiple of 20. Aggregating amortises
 * the 103 B of per-packet overhead over more audio; see
 * docs/CODEC_COMPARISON.md section 5. With one sub-frame per packet this is
 * byte-for-byte the original single-frame path.
 */
#include "codec2.h"

static struct CODEC2 *s_c2;
static int s_sub;      /* codec2 sub-frames per ESP-NOW packet */
static int s_c2_nsamp; /* samples per codec2 sub-frame  (160 for 3200) */
static int s_c2_nbyte; /* bytes   per codec2 sub-frame  (8   for 3200) */

static esp_err_t codec_init_(void)
{
    s_c2 = codec2_create(CODEC2_MODE_3200);
    if (s_c2 == NULL) {
        ESP_LOGE(TAG, "codec2_create failed");
        return ESP_ERR_NO_MEM;
    }
    s_c2_nsamp = codec2_samples_per_frame(s_c2);
    s_c2_nbyte = (codec2_bits_per_frame(s_c2) + 7) / 8;

    if (s_c2_nsamp <= 0 || (VOX_SAMPLES_PER_FRAME % s_c2_nsamp) != 0) {
        ESP_LOGE(TAG, "codec2 frame is %d samples; build wants %d, which is not "
                      "a whole multiple", s_c2_nsamp, VOX_SAMPLES_PER_FRAME);
        return ESP_ERR_INVALID_STATE;
    }
    s_sub = VOX_SAMPLES_PER_FRAME / s_c2_nsamp;

    /* vox_config.h sizes the payload independently; if the two disagree the
     * packet layout is wrong and every frame would be silently truncated. */
    if (s_sub * s_c2_nbyte != VOX_ENCODED_BYTES) {
        ESP_LOGE(TAG, "codec2 would emit %d B/frame but the build reserves %d B",
                 s_sub * s_c2_nbyte, VOX_ENCODED_BYTES);
        return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGI(TAG, "codec2 3200: %d sub-frame(s)/packet, %d samples, %d B",
             s_sub, VOX_SAMPLES_PER_FRAME, s_sub * s_c2_nbyte);
    return ESP_OK;
}

static size_t codec_encode_(const int16_t *pcm, size_t nsamp, uint8_t *out, size_t cap)
{
    size_t need = (size_t)s_sub * (size_t)s_c2_nbyte;
    if (cap < need || nsamp != (size_t)VOX_SAMPLES_PER_FRAME) {
        return 0;
    }
    for (int i = 0; i < s_sub; i++) {
        codec2_encode(s_c2, out + (size_t)i * s_c2_nbyte,
                      (short *)pcm + (size_t)i * s_c2_nsamp);
    }
    return need;
}

static size_t codec_decode_(const uint8_t *in, size_t in_len, int16_t *pcm, size_t cap)
{
    size_t need = (size_t)s_sub * (size_t)s_c2_nbyte;
    if (cap < (size_t)VOX_SAMPLES_PER_FRAME || in_len < need) {
        return 0;
    }
    for (int i = 0; i < s_sub; i++) {
        codec2_decode(s_c2, (short *)pcm + (size_t)i * s_c2_nsamp,
                      (unsigned char *)in + (size_t)i * s_c2_nbyte);
    }
    return (size_t)VOX_SAMPLES_PER_FRAME;
}

#else
#error "No codec selected"
#endif

/* =============================== selection ============================== */

static const vox_codec_t s_codec = {
    .id            = VOX_CODEC_ID,
    .name          = VOX_CODEC_NAME,
#if defined(CONFIG_VOX_CODEC_G711U)
    .bitrate_bps   = VOX_SAMPLE_RATE_HZ * 8,
#elif defined(CONFIG_VOX_CODEC_PCM16)
    .bitrate_bps   = VOX_SAMPLE_RATE_HZ * 16,
#else
    .bitrate_bps   = 3200,
#endif
    .encoded_bytes = VOX_ENCODED_BYTES,
    /** Codec initialization and function pointers */
    .init          = codec_init_,
    .encode        = codec_encode_,
    .decode        = codec_decode_,
};

const vox_codec_t *vox_codec(void)
{
    return &s_codec;
}

esp_err_t vox_codec_init(void)
{
    esp_err_t err = s_codec.init();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "%s, %u bit/s, %u B/frame, %d samples/frame",
                 s_codec.name, (unsigned)s_codec.bitrate_bps,
                 (unsigned)s_codec.encoded_bytes, VOX_SAMPLES_PER_FRAME);
    }
    return err;
}
