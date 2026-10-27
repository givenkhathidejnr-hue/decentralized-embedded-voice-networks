#include <string.h>
#include "audio/vox_audio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

#if defined(CONFIG_VOX_SINK_I2S_MAX98357A)
#include "driver/i2s_std.h"
#endif

static const char *TAG = "vox.sink";

#if defined(CONFIG_VOX_SINK_I2S_MAX98357A)

static i2s_chan_handle_t s_tx;

esp_err_t vox_audio_sink_init(void)
{
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    /*
     * Four descriptors of one frame each. The DMA ring is deliberately shallow:
     * every buffered frame is latency that lands in the end-to-end delay
     * figure, and the jitter buffer above already absorbs network variation.
     * Deepening this to hide underruns would hide them from the measurement
     * too.
     */
    chan_cfg.dma_desc_num  = 4;
    chan_cfg.dma_frame_num = VOX_SAMPLES_PER_FRAME;
    /* Deliberately not setting auto_clear: the field was renamed across the
     * IDF 5.x series, and the playout task already writes explicit silence on
     * underrun. Doing it in software is version-proof and, more importantly,
     * keeps the concealment visible in the counter instead of being papered
     * over by the driver. */

    ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, &s_tx, NULL));

    i2s_std_config_t std = {
        .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(VOX_SAMPLE_RATE_HZ),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT,
                                                        I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = CONFIG_VOX_I2S_OUT_BCLK,
            .ws   = CONFIG_VOX_I2S_OUT_LRCLK,
            .dout = CONFIG_VOX_I2S_OUT_DIN,
            .din  = I2S_GPIO_UNUSED,
            .invert_flags = { false, false, false },
        },
    };

    ESP_ERROR_CHECK(i2s_channel_init_std_mode(s_tx, &std));
    ESP_ERROR_CHECK(i2s_channel_enable(s_tx));

    ESP_LOGI(TAG, "MAX98357A on bclk=%d lrc=%d din=%d, %d Hz mono",
             CONFIG_VOX_I2S_OUT_BCLK, CONFIG_VOX_I2S_OUT_LRCLK,
             CONFIG_VOX_I2S_OUT_DIN, VOX_SAMPLE_RATE_HZ);
    return ESP_OK;
}

esp_err_t vox_audio_sink_write(const int16_t *pcm, size_t nsamp, uint32_t timeout_ms)
{
    size_t written = 0;
    esp_err_t err = i2s_channel_write(s_tx, pcm, nsamp * sizeof(int16_t), &written,
                                      pdMS_TO_TICKS(timeout_ms));
    if (err == ESP_OK && written != nsamp * sizeof(int16_t)) {
        return ESP_ERR_TIMEOUT;
    }
    return err;
}

const char *vox_audio_sink_name(void) { return "max98357a"; }

#else

/*
 * Null sink. Useful as a control: it measures the whole receive pipeline
 * without the I2S DMA stage, so the cost of playout itself can be isolated
 * by differencing the two builds.
 */
esp_err_t vox_audio_sink_init(void)
{
    ESP_LOGI(TAG, "null sink: frames are decoded then discarded");
    return ESP_OK;
}

esp_err_t vox_audio_sink_write(const int16_t *pcm, size_t nsamp, uint32_t timeout_ms)
{
    (void)pcm; (void)nsamp; (void)timeout_ms;
    return ESP_OK;
}

const char *vox_audio_sink_name(void) { return "none"; }

#endif
