/*
 * vox_audio.h - capture and playout.
 *
 * Capture has two implementations and the choice is deliberate, not a
 * placeholder.
 *
 * The SYNTHETIC source is the default and is the right source for the
 * measurement runs. It is a pure function of the sample index: frame n
 * contains exactly the same samples on every run, on every board, forever.
 * That matters because the study compares independently protected unicast
 * against a group architecture across a receiver-count sweep, and any
 * difference in the input signal between runs would appear in the results as
 * a difference between the architectures. A live microphone cannot be held
 * constant across runs; a deterministic generator can.
 *
 * It also gives the receiver a reference. Because the generator is a known
 * function of the sequence number, the receiving node can regenerate exactly
 * what the sender should have produced and compute a true per-frame error,
 * rather than inferring quality from loss counts alone. vox_audio_reference()
 * exposes that.
 *
 * The INMP441 source is for the validation runs that show the pipeline
 * carries real speech, and for any listening test. Those are a separate,
 * later exercise from the scaling measurements.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "vox_config.h"

/* ---------------------------------------------------------------- source */

esp_err_t vox_audio_src_init(void);

/*
 * Fill one frame. `sample_index` is the absolute sample position of the
 * frame, used by the synthetic generator to stay deterministic; the I2S
 * source ignores it. Returns false if no data was available.
 */
bool vox_audio_src_read(uint32_t sample_index, int16_t *pcm, size_t nsamp,
                        uint32_t timeout_ms);

/*
 * Regenerate what the synthetic source produced at `sample_index`. Returns
 * false when the build uses a live microphone, in which case no reference
 * exists and error metrics must come from a listening test instead.
 */
bool vox_audio_reference(uint32_t sample_index, int16_t *pcm, size_t nsamp);

const char *vox_audio_src_name(void);

/* Bytes of RAM the source holds, reported separately in the run header so it
 * is not mistaken for pipeline memory. */
size_t vox_audio_src_bytes(void);

/* Microphone gain, as a right-shift applied to the 32-bit I2S word. Needs
 * tuning per board and per acoustic setup; no effect on the synthetic source. */
void vox_audio_src_set_gain_shift(int shift);
int  vox_audio_src_gain_shift(void);

/* ------------------------------------------------------------------ sink */

esp_err_t vox_audio_sink_init(void);
esp_err_t vox_audio_sink_write(const int16_t *pcm, size_t nsamp, uint32_t timeout_ms);
const char *vox_audio_sink_name(void);
