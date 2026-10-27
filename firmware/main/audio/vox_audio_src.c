#include <math.h>
#include <string.h>
#include <stdlib.h>
#include "audio/vox_audio.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"

#if defined(CONFIG_VOX_SRC_I2S_INMP441)
#include "driver/i2s_std.h"
#endif

static const char *TAG = "vox.src";

static int s_gain_shift = 14;

/* ====================== deterministic synthetic source ================== */
#if defined(CONFIG_VOX_SRC_SYNTH)

/*
 * One period of the composite waveform is generated once, at start-up, into
 * a table. Playback is then a table read, a modulo and a multiply per sample,
 * so the generator costs almost nothing during a measurement run. Building it
 * with sinf() on every frame instead would burn a few percent of the CPU that
 * the study is trying to measure, and would show up as codec or crypto cost
 * in the profile.
 *
 * The table length is an exact number of samples, so indexing by
 * (sample_index % TABLE_LEN) makes the output a pure function of the absolute
 * sample position: deterministic, reproducible, and regenerable by the
 * receiver.
 */
#define SYNTH_TABLE_LEN   (VOX_SAMPLE_RATE_HZ / 2)      /* 0.5 s */
#define SYNTH_ENV_PERIOD  (VOX_SAMPLE_RATE_HZ / 4)      /* 250 ms syllable */

static int16_t *s_table;

static void build_table(void)
{
#if defined(CONFIG_VOX_SYNTH_TONE)
    for (int i = 0; i < SYNTH_TABLE_LEN; i++) {
        float t = (float)i / (float)VOX_SAMPLE_RATE_HZ;
        s_table[i] = (int16_t)(12000.0f * sinf(2.0f * (float)M_PI * 1000.0f * t));
    }
#elif defined(CONFIG_VOX_SYNTH_SWEEP)
    /* Ramp counter: any sample corruption anywhere in the pipeline is
     * immediately visible as a discontinuity, and a bit-exact end-to-end
     * check is possible when the codec is PCM16. */
    for (int i = 0; i < SYNTH_TABLE_LEN; i++) {
        s_table[i] = (int16_t)((i * 64) - 16384);
    }
#else
    /*
     * Speech-like: a 120 Hz glottal fundamental with harmonics shaped by
     * three formant resonances at 700 / 1220 / 2600 Hz. Not speech, but it
     * occupies the same band with a comparable spectral envelope and crest
     * factor, so codec and packetisation behave as they would on real voice.
     */
    static const float f0 = 120.0f;
    static const float formant[3] = { 700.0f, 1220.0f, 2600.0f };
    static const float fgain[3]   = { 1.0f, 0.55f, 0.28f };
    static const float bw         = 260.0f;

    for (int i = 0; i < SYNTH_TABLE_LEN; i++) {
        float t = (float)i / (float)VOX_SAMPLE_RATE_HZ;
        float acc = 0.0f;

        for (int h = 1; h <= 28; h++) {
            float fh = f0 * (float)h;
            if (fh > 3400.0f) {
                break;                      /* keep inside the 8 kHz band */
            }
            float amp = 0.0f;
            for (int k = 0; k < 3; k++) {
                float d = (fh - formant[k]) / bw;
                amp += fgain[k] / (1.0f + d * d);
            }
            amp /= (float)h;                /* glottal -12 dB/octave rolloff */
            acc += amp * sinf(2.0f * (float)M_PI * fh * t);
        }
        float v = acc * 4200.0f;
        if (v >  32000.0f) v =  32000.0f;
        if (v < -32000.0f) v = -32000.0f;
        s_table[i] = (int16_t)v;
    }
#endif
}

/* Raised-cosine syllable envelope, also a pure function of sample index. */
static float envelope(uint32_t sample_index)
{
#if defined(CONFIG_VOX_SYNTH_SWEEP)
    (void)sample_index;
    return 1.0f;
#else
    uint32_t phase = sample_index % (uint32_t)SYNTH_ENV_PERIOD;
    float x = (float)phase / (float)SYNTH_ENV_PERIOD;
    /* 70% of the syllable voiced, 30% near-silent, smoothly gated. */
    if (x > 0.70f) {
        return 0.04f;
    }
    return 0.5f * (1.0f - cosf(2.0f * (float)M_PI * (x / 0.70f)));
#endif
}

static void synth_fill(uint32_t sample_index, int16_t *pcm, size_t nsamp)
{
    for (size_t i = 0; i < nsamp; i++) {
        uint32_t idx = sample_index + (uint32_t)i;
        float e = envelope(idx);
        int32_t v = (int32_t)((float)s_table[idx % (uint32_t)SYNTH_TABLE_LEN] * e);
        if (v >  32767) v =  32767;
        if (v < -32768) v = -32768;
        pcm[i] = (int16_t)v;
    }
}

esp_err_t vox_audio_src_init(void)
{
    s_table = heap_caps_malloc(SYNTH_TABLE_LEN * sizeof(int16_t), MALLOC_CAP_8BIT);
    if (s_table == NULL) {
        return ESP_ERR_NO_MEM;
    }
    build_table();
    ESP_LOGI(TAG, "synthetic source ready (%s), table %d B",
             vox_audio_src_name(), (int)(SYNTH_TABLE_LEN * sizeof(int16_t)));
    return ESP_OK;
}

bool vox_audio_src_read(uint32_t sample_index, int16_t *pcm, size_t nsamp, uint32_t timeout_ms)
{
    (void)timeout_ms;
    synth_fill(sample_index, pcm, nsamp);
    return true;
}

bool vox_audio_reference(uint32_t sample_index, int16_t *pcm, size_t nsamp)
{
    if (s_table == NULL) {
        return false;
    }
    synth_fill(sample_index, pcm, nsamp);
    return true;
}

size_t vox_audio_src_bytes(void)
{
    return SYNTH_TABLE_LEN * sizeof(int16_t);
}

const char *vox_audio_src_name(void)
{
#if defined(CONFIG_VOX_SYNTH_TONE)
    return "synth-tone1k";
#elif defined(CONFIG_VOX_SYNTH_SWEEP)
    return "synth-ramp";
#else
    return "synth-speechlike";
#endif
}

/* ============================ INMP441 over I2S ========================== */
#elif defined(CONFIG_VOX_SRC_I2S_INMP441)

static i2s_chan_handle_t s_rx;
static int32_t          *s_raw;

esp_err_t vox_audio_src_init(void)
{
    s_raw = heap_caps_malloc(VOX_SAMPLES_PER_FRAME * sizeof(int32_t), MALLOC_CAP_8BIT);
    if (s_raw == NULL) {
        return ESP_ERR_NO_MEM;
    }

    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_1, I2S_ROLE_MASTER);
    chan_cfg.dma_desc_num  = 4;
    chan_cfg.dma_frame_num = VOX_SAMPLES_PER_FRAME;
    ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, NULL, &s_rx));

    i2s_std_config_t std = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(VOX_SAMPLE_RATE_HZ),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT,
                                                        I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_VOX_I2S_IN_BCLK,
            .ws   = CONFIG_VOX_I2S_IN_LRCLK,
            .dout = I2S_GPIO_UNUSED,
            .din  = CONFIG_VOX_I2S_IN_SD,
            .invert_flags = { false, false, false },
        },
    };
    /* INMP441 with L/R tied low drives the left slot. */
    std.slot_cfg.slot_mask = I2S_STD_SLOT_LEFT;

    ESP_ERROR_CHECK(i2s_channel_init_std_mode(s_rx, &std));
    ESP_ERROR_CHECK(i2s_channel_enable(s_rx));
    ESP_LOGI(TAG, "INMP441 on bclk=%d ws=%d sd=%d, gain shift %d",
             CONFIG_VOX_I2S_IN_BCLK, CONFIG_VOX_I2S_IN_LRCLK,
             CONFIG_VOX_I2S_IN_SD, s_gain_shift);
    return ESP_OK;
}

bool vox_audio_src_read(uint32_t sample_index, int16_t *pcm, size_t nsamp, uint32_t timeout_ms)
{
    (void)sample_index;
    size_t got = 0;
    if (i2s_channel_read(s_rx, s_raw, nsamp * sizeof(int32_t), &got,
                         pdMS_TO_TICKS(timeout_ms)) != ESP_OK) {
        return false;
    }
    size_t n = got / sizeof(int32_t);
    if (n < nsamp) {
        memset(pcm + n, 0, (nsamp - n) * sizeof(int16_t));
    }
    for (size_t i = 0; i < n; i++) {
        int32_t v = s_raw[i] >> s_gain_shift;
        if (v >  32767) v =  32767;
        if (v < -32768) v = -32768;
        pcm[i] = (int16_t)v;
    }
    return true;
}

bool vox_audio_reference(uint32_t sample_index, int16_t *pcm, size_t nsamp)
{
    (void)sample_index; (void)pcm; (void)nsamp;
    return false;      /* live audio has no reference signal */
}

size_t vox_audio_src_bytes(void)
{
    return VOX_SAMPLES_PER_FRAME * sizeof(int32_t);
}

const char *vox_audio_src_name(void) { return "inmp441"; }

/* ================================== none ================================ */
#else

esp_err_t vox_audio_src_init(void) { return ESP_OK; }

bool vox_audio_src_read(uint32_t sample_index, int16_t *pcm, size_t nsamp, uint32_t timeout_ms)
{
    (void)sample_index; (void)pcm; (void)nsamp; (void)timeout_ms;
    return false;
}

bool vox_audio_reference(uint32_t si, int16_t *pcm, size_t n)
{
    (void)si; (void)pcm; (void)n;
    return false;
}

size_t vox_audio_src_bytes(void) { return 0; }
const char *vox_audio_src_name(void) { return "none"; }

#endif

void vox_audio_src_set_gain_shift(int shift)
{
    if (shift >= 0 && shift <= 24) {
        s_gain_shift = shift;
    }
}

int vox_audio_src_gain_shift(void)
{
    return s_gain_shift;
}
