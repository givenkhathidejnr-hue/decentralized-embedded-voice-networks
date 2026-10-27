#include <string.h>
#include "sec/vox_crypto.h"
#include "esp_log.h"

static const char *TAG = "vox.aead";

const char *vox_aead_name(void)
{
#if !defined(CONFIG_VOX_CRYPTO_ENABLED)
    return "none";
#elif defined(CONFIG_VOX_AEAD_CCM)
    return "aes128-ccm";
#else
    return "aes128-gcm";
#endif
}

esp_err_t vox_aead_set_key(vox_aead_t *a,
                           const uint8_t key[VOX_AEAD_KEY_LEN],
                           const uint8_t salt[VOX_AEAD_SALT_LEN])
{
    if (a == NULL || key == NULL || salt == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    vox_aead_clear(a);

    int rc;
#if defined(CONFIG_VOX_AEAD_CCM)
    mbedtls_ccm_init(&a->ctx);
    rc = mbedtls_ccm_setkey(&a->ctx, MBEDTLS_CIPHER_ID_AES, key, VOX_AEAD_KEY_LEN * 8);
#else
    mbedtls_gcm_init(&a->ctx);
    rc = mbedtls_gcm_setkey(&a->ctx, MBEDTLS_CIPHER_ID_AES, key, VOX_AEAD_KEY_LEN * 8);
#endif
    if (rc != 0) {
        ESP_LOGE(TAG, "setkey failed: -0x%04x", -rc);
        return ESP_FAIL;
    }
    memcpy(a->salt, salt, VOX_AEAD_SALT_LEN);
    a->ready = true;
    return ESP_OK;
}

void vox_aead_clear(vox_aead_t *a)
{
    if (a == NULL || !a->ready) {
        return;
    }
#if defined(CONFIG_VOX_AEAD_CCM)
    mbedtls_ccm_free(&a->ctx);
#else
    mbedtls_gcm_free(&a->ctx);
#endif
    memset(a->salt, 0, sizeof(a->salt));
    a->ready = false;
}

void vox_aead_nonce(const vox_aead_t *a, uint16_t src_id, uint8_t epoch,
                    uint32_t seq, uint8_t out[VOX_AEAD_NONCE_LEN])
{
    memcpy(out, a->salt, VOX_AEAD_SALT_LEN);
    out[4] = (uint8_t)(src_id & 0xFF);
    out[5] = (uint8_t)(src_id >> 8);
    out[6] = epoch;
    out[7] = 0x00;
    out[8]  = (uint8_t)(seq & 0xFF);
    out[9]  = (uint8_t)((seq >> 8) & 0xFF);
    out[10] = (uint8_t)((seq >> 16) & 0xFF);
    out[11] = (uint8_t)((seq >> 24) & 0xFF);
}

esp_err_t vox_aead_seal(vox_aead_t *a, const uint8_t nonce[VOX_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct, uint8_t *tag, size_t tag_len)
{
    if (a == NULL || !a->ready) {
        return ESP_ERR_INVALID_STATE;
    }
    /* mbedtls's GCM/CCM backends reject a NULL input pointer even when the
     * length is 0 (e.g. READY's empty body), so a literal NULL plaintext
     * must never reach them -- substitute any non-NULL pointer; it is never
     * dereferenced for a zero-length operation. */
    static const uint8_t empty[1] = {0};
    if (pt == NULL) pt = empty;
    if (ct == NULL) ct = (uint8_t *)empty;
    int rc;
#if defined(CONFIG_VOX_AEAD_CCM)
    rc = mbedtls_ccm_encrypt_and_tag(&a->ctx, pt_len,
                                     nonce, VOX_AEAD_NONCE_LEN,
                                     aad, aad_len,
                                     pt, ct,
                                     tag, tag_len);
#else
    rc = mbedtls_gcm_crypt_and_tag(&a->ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
                                   nonce, VOX_AEAD_NONCE_LEN,
                                   aad, aad_len,
                                   pt, ct,
                                   tag_len, tag);
#endif
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t vox_aead_open(vox_aead_t *a, const uint8_t nonce[VOX_AEAD_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *pt)
{
    if (a == NULL || !a->ready) {
        return ESP_ERR_INVALID_STATE;
    }
    static const uint8_t empty[1] = {0};
    if (ct == NULL) ct = empty;
    if (pt == NULL) pt = (uint8_t *)empty;
    int rc;
#if defined(CONFIG_VOX_AEAD_CCM)
    rc = mbedtls_ccm_auth_decrypt(&a->ctx, ct_len,
                                  nonce, VOX_AEAD_NONCE_LEN,
                                  aad, aad_len,
                                  ct, pt,
                                  tag, tag_len);
#else
    rc = mbedtls_gcm_auth_decrypt(&a->ctx, ct_len,
                                  nonce, VOX_AEAD_NONCE_LEN,
                                  aad, aad_len,
                                  tag, tag_len,
                                  ct, pt);
#endif
    if (rc != 0) {
        /* Authentication failure. Do not distinguish causes to the caller and
         * do not leak timing beyond what mbedTLS already guarantees. */
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}
