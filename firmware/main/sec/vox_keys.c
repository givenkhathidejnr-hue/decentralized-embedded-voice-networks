#include <string.h>
#include "sec/vox_keys.h"
#include "vox_config.h"
#include "vox_frame.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"      /* mbedtls_platform_zeroize */

static const char *TAG = "vox.keys";

static uint8_t s_pmk[VOX_PMK_LEN];
static uint8_t s_boot_key[32];
typedef struct { uint16_t id; uint8_t key[VOX_PMK_LEN]; } pair_key_t;
static pair_key_t s_pairs[VOX_MAX_PEERS];

static const uint8_t *peer_key(uint16_t id)
{
    for (int i=0; i<VOX_MAX_PEERS; ++i)
        if (s_pairs[i].id == id && id != 0) return s_pairs[i].key;
    return NULL;
}
bool vox_keys_peer_isolated(uint16_t id) { return peer_key(id) != NULL; }
static esp_err_t store_pairs(void)
{
    nvs_handle_t h;
    esp_err_t err=nvs_open("vox", NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err=nvs_set_blob(h, "pairs_v2", s_pairs, sizeof(s_pairs));
    if (err == ESP_OK) err=nvs_commit(h);
    nvs_close(h); return err;
}
esp_err_t vox_keys_store_peer(uint16_t id, const uint8_t key[VOX_PMK_LEN])
{
    if (!id || id==VOX_NODE_ID || id==VOX_BROADCAST_ID || !key) return ESP_ERR_INVALID_ARG;
    int slot=-1;
    for (int i=0; i<VOX_MAX_PEERS; ++i) {
        if (s_pairs[i].id==id) { slot=i; break; }
        if (!s_pairs[i].id && slot<0) slot=i;
    }
    if (slot<0) return ESP_ERR_NO_MEM;
    pair_key_t prev=s_pairs[slot];
    s_pairs[slot].id=id; memcpy(s_pairs[slot].key,key,VOX_PMK_LEN);
    esp_err_t err=store_pairs();
    if (err!=ESP_OK) s_pairs[slot]=prev;
    mbedtls_platform_zeroize(&prev,sizeof(prev));
    return err;
}
esp_err_t vox_keys_remove_peer(uint16_t id)
{
    for (int i=0; i<VOX_MAX_PEERS; ++i) if (s_pairs[i].id==id && id) {
        pair_key_t prev=s_pairs[i];
        mbedtls_platform_zeroize(&s_pairs[i],sizeof(s_pairs[i]));
        esp_err_t err=store_pairs(); if (err!=ESP_OK) s_pairs[i]=prev;
        mbedtls_platform_zeroize(&prev,sizeof(prev)); return err;
    }
    return ESP_ERR_NOT_FOUND;
}

static const char INFO_SESSION[] = "vox/v2/session";
static const char INFO_DIR[]     = "vox/v2/dir";
static const char INFO_BOOT[]    = "vox/v2/bootstrap";
static const char INFO_GROUP[]   = "vox/v2/group";

static int hex2nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static esp_err_t hex_to_bin(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) {
        return ESP_ERR_INVALID_SIZE;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex2nib(hex[2 * i]);
        int lo = hex2nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return ESP_ERR_INVALID_ARG;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return ESP_OK;
}

static void derive_bootstrap_key(void)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    /* Domain separation only; no per-session salt, the bootstrap key is
     * long-term by construction and is used for authentication, never for
     * encryption, so it carries no nonce-reuse hazard. */
    mbedtls_hkdf(md, NULL, 0,
                 s_pmk, sizeof(s_pmk),
                 (const unsigned char *)INFO_BOOT, sizeof(INFO_BOOT) - 1,
                 s_boot_key, sizeof(s_boot_key));
}

esp_err_t vox_keys_init(bool *used_default_pmk)
{
    bool used_default = true;
    memset(s_pairs, 0, sizeof(s_pairs));

    nvs_handle_t h;
    if (nvs_open("vox", NVS_READONLY, &h) == ESP_OK) {
        size_t len = VOX_PMK_LEN;
        if (nvs_get_blob(h, "pmk", s_pmk, &len) == ESP_OK && len == VOX_PMK_LEN) {
            used_default = false;
        }
        size_t pairs_len=sizeof(s_pairs);
        if (nvs_get_blob(h,"pairs_v2",s_pairs,&pairs_len)!=ESP_OK || pairs_len!=sizeof(s_pairs))
            memset(s_pairs,0,sizeof(s_pairs));
        nvs_close(h);
    }

    if (used_default) {
        esp_err_t err = hex_to_bin(CONFIG_VOX_PMK_HEX, s_pmk, VOX_PMK_LEN);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "CONFIG_VOX_PMK_HEX must be exactly %d hex characters",
                     VOX_PMK_LEN * 2);
            return err;
        }
        ESP_LOGW(TAG, "using the development default PMK - not a deployment key");
    }

    derive_bootstrap_key();
    if (used_default_pmk) {
        *used_default_pmk = used_default;
    }
    return ESP_OK;
}

const uint8_t *vox_keys_pmk(void)
{
    return s_pmk;
}

esp_err_t vox_keys_store_pmk(const uint8_t pmk[VOX_PMK_LEN])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open("vox", NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(h, "pmk", pmk, VOX_PMK_LEN);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);

    if (err == ESP_OK) {
        memcpy(s_pmk, pmk, VOX_PMK_LEN);
        derive_bootstrap_key();
    }
    return err;
}

esp_err_t vox_keys_derive_session(const uint8_t nonce_init[VOX_HS_NONCE_LEN],
                                  const uint8_t nonce_resp[VOX_HS_NONCE_LEN],
                                  uint16_t id_init, uint16_t id_resp,
                                  uint8_t out_secret[VOX_SESSION_LEN])
{
    uint8_t salt[VOX_HS_NONCE_LEN * 2];
    memcpy(salt, nonce_init, VOX_HS_NONCE_LEN);
    memcpy(salt + VOX_HS_NONCE_LEN, nonce_resp, VOX_HS_NONCE_LEN);

    uint8_t info[sizeof(INFO_SESSION) - 1 + 4];
    size_t  n = sizeof(INFO_SESSION) - 1;
    memcpy(info, INFO_SESSION, n);
    info[n++] = (uint8_t)(id_init & 0xFF);
    info[n++] = (uint8_t)(id_init >> 8);
    info[n++] = (uint8_t)(id_resp & 0xFF);
    info[n++] = (uint8_t)(id_resp >> 8);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const uint8_t *psk=peer_key(id_init==VOX_NODE_ID ? id_resp : id_init);
    if (!psk) psk=s_pmk; /* explicitly labelled legacy unicast arm */
    int rc = mbedtls_hkdf(md, salt, sizeof(salt),
                          psk, VOX_PMK_LEN,
                          info, n,
                          out_secret, VOX_SESSION_LEN);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t vox_keys_derive_dir(const uint8_t secret[VOX_SESSION_LEN],
                              uint16_t src_id, uint16_t dst_id, uint8_t epoch,
                              vox_aead_t *out_aead)
{
    uint8_t info[sizeof(INFO_DIR) - 1 + 5];
    size_t  n = sizeof(INFO_DIR) - 1;
    memcpy(info, INFO_DIR, n);
    info[n++] = (uint8_t)(src_id & 0xFF);
    info[n++] = (uint8_t)(src_id >> 8);
    info[n++] = (uint8_t)(dst_id & 0xFF);
    info[n++] = (uint8_t)(dst_id >> 8);
    info[n++] = epoch;

    uint8_t okm[VOX_AEAD_KEY_LEN + VOX_AEAD_SALT_LEN];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int rc = mbedtls_hkdf_expand(md, secret, VOX_SESSION_LEN, info, n,
                                 okm, sizeof(okm));
    if (rc != 0) {
        return ESP_FAIL;
    }

    esp_err_t err = vox_aead_set_key(out_aead, okm, okm + VOX_AEAD_KEY_LEN);
    mbedtls_platform_zeroize(okm, sizeof(okm));
    return err;
}

esp_err_t vox_keys_derive_group(const uint8_t secret[VOX_SESSION_LEN],
                                uint8_t epoch, vox_aead_t *out_aead)
{
    uint8_t info[sizeof(INFO_GROUP) - 1 + 1];
    size_t  n = sizeof(INFO_GROUP) - 1;
    memcpy(info, INFO_GROUP, n);
    info[n++] = epoch;

    uint8_t okm[VOX_AEAD_KEY_LEN + VOX_AEAD_SALT_LEN];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int rc = mbedtls_hkdf_expand(md, secret, VOX_SESSION_LEN, info, n,
                                 okm, sizeof(okm));
    if (rc != 0) {
        return ESP_FAIL;
    }

    esp_err_t err = vox_aead_set_key(out_aead, okm, okm + VOX_AEAD_KEY_LEN);
    mbedtls_platform_zeroize(okm, sizeof(okm));
    return err;
}

esp_err_t vox_keys_hs_mac(const uint8_t *data, size_t len, uint8_t out[VOX_MAC_LEN])
{
    uint8_t full[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const uint8_t *key=s_boot_key;
    if (len < VOX_HDR_LEN) return ESP_ERR_INVALID_SIZE;
    const vox_hdr_t *h=(const vox_hdr_t *)data;
    uint16_t other=h->src_id==VOX_NODE_ID ? h->dst_id : h->src_id;
    /* Broadcast discovery carries no session/key material. */
    if (h->dst_id != VOX_BROADCAST_ID) {
        const uint8_t *pair=peer_key(other);
        if (pair) key=pair;
    }
    int rc = mbedtls_md_hmac(md, key, 32, data, len, full);
    if (rc != 0) {
        return ESP_FAIL;
    }
    memcpy(out, full, VOX_MAC_LEN);   /* truncated to 128 bits */
    mbedtls_platform_zeroize(full, sizeof(full));
    return ESP_OK;
}

bool vox_keys_hs_mac_verify(const uint8_t *data, size_t len, const uint8_t mac[VOX_MAC_LEN])
{
    uint8_t expect[VOX_MAC_LEN];
    if (vox_keys_hs_mac(data, len, expect) != ESP_OK) {
        return false;
    }
    /* Constant-time comparison: never early-exit on the first differing byte. */
    uint8_t diff = 0;
    for (size_t i = 0; i < VOX_MAC_LEN; i++) {
        diff |= (uint8_t)(expect[i] ^ mac[i]);
    }
    mbedtls_platform_zeroize(expect, sizeof(expect));
    return diff == 0;
}
