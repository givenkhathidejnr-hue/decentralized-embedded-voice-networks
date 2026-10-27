/*
 * vox_crypto.h - authenticated encryption for one direction of one link.
 *
 * The baseline deliberately protects frames at the application layer rather
 * than relying on ESP-NOW's own CCMP/LMK pairwise encryption. Two reasons,
 * both of which come straight out of the literature review:
 *
 *   1. ESP-NOW does not support encrypted multicast action frames, so the
 *      group arm of this study cannot use link-layer protection at all. If
 *      the unicast baseline used CCMP and the group arm used application
 *      crypto, the comparison would be measuring two different software
 *      stacks, not two delivery models. Using the same AEAD in both arms
 *      keeps the pairwise baseline a fair control.
 *
 *   2. The per-frame cryptographic cost has to be attributable. Work done
 *      inside the Wi-Fi driver is not visible to the instrumentation; work
 *      done here can be timed, per frame, on both sender and receiver.
 *
 * ESP-NOW's own LMK encryption may additionally be enabled on top of this
 * (see vox_link.c) when the experiment wants to measure the cost of the
 * layered arrangement, but the measurements reported for the baseline use
 * application-layer protection only.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "sdkconfig.h"

#if defined(CONFIG_VOX_AEAD_CCM)
#  include "mbedtls/ccm.h"
#else
#  include "mbedtls/gcm.h"
#endif

#define VOX_AEAD_KEY_LEN    16      /* AES-128 */
#define VOX_AEAD_SALT_LEN   4
#define VOX_AEAD_NONCE_LEN  12

typedef struct {
#if defined(CONFIG_VOX_AEAD_CCM)
    mbedtls_ccm_context ctx;
#else
    mbedtls_gcm_context ctx;
#endif
    uint8_t salt[VOX_AEAD_SALT_LEN];
    bool    ready;
} vox_aead_t;

/* Human-readable name of the selected construction, for the run header. */
const char *vox_aead_name(void);

esp_err_t vox_aead_set_key(vox_aead_t *a,
                           const uint8_t key[VOX_AEAD_KEY_LEN],
                           const uint8_t salt[VOX_AEAD_SALT_LEN]);
void      vox_aead_clear(vox_aead_t *a);

/*
 * Deterministic nonce: salt(4) || src_id(2,LE) || epoch(1) || 0x00 || seq(4,LE)
 *
 * Uniqueness argument: the key is derived per (session, direction, epoch), so
 * within one key the only varying inputs are src_id (fixed for that key) and
 * seq. seq is monotonic and never rewound within an epoch; an epoch change
 * derives a new key. Therefore no (key, nonce) pair repeats.
 */
void vox_aead_nonce(const vox_aead_t *a, uint16_t src_id, uint8_t epoch,
                    uint32_t seq, uint8_t out[VOX_AEAD_NONCE_LEN]);

/*
 * Encrypt-and-authenticate. `aad` is the cleartext frame header. `ct` may
 * alias `pt` for in-place operation. `tag_len` must match CONFIG_VOX_TAG_LEN.
 */
esp_err_t vox_aead_seal(vox_aead_t *a, const uint8_t nonce[VOX_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct, uint8_t *tag, size_t tag_len);

/*
 * Verify-and-decrypt. Returns ESP_ERR_INVALID_CRC when the tag does not
 * verify; the caller must treat that as a security event, count it, and
 * discard the frame without touching replay state.
 */
esp_err_t vox_aead_open(vox_aead_t *a, const uint8_t nonce[VOX_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *pt);
