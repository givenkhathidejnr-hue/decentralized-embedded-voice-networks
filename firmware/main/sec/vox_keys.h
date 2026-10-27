/*
 * vox_keys.h - key schedule.
 *
 *   independent pair PSK (32 B, provisioned); legacy unicast may use PMK
 *     |
 *     |  HKDF-Extract-and-Expand
 *     |    salt = nonce_initiator || nonce_responder     (fresh per session)
 *     |    info = "vox/v2/session" || id_init || id_resp
 *     v
 *   session secret (32 B)                    -- survives epoch changes
 *     |
 *     |  HKDF-Expand
 *     |    info = "vox/v2/dir" || src_id || dst_id || epoch
 *     v
 *   direction key (16 B) || nonce salt (4 B) -- one per direction per epoch
 *
 * Three properties this buys, each of which the report needs to be able to
 * state precisely:
 *
 *   - Per-direction keys. A -> B and B -> A never share a key, so the two
 *     directions cannot collide in nonce space even though both start their
 *     sequence numbers at zero.
 *
 *   - Epoch-bound keys. The epoch is an input to the KDF, not merely a label
 *     on the wire. A rekey therefore produces genuinely new key material and
 *     the sequence counter is not reused under a repeated key. Epoch wrap
 *     forces a fresh session, rather than deriving an earlier epoch again.
 *
 *   - Session freshness without asymmetric cost. The two nonces make each
 *     session's keys independent of the last, using only symmetric
 *     primitives. The PSK-versus-full-handshake energy figures in the review
 *     (2.7 mC against 89.6 mC on a constrained node) are the reason this
 *     baseline does not put an ECDHE exchange on the critical path.
 *
 * WHAT THIS DOES NOT PROVIDE, and must not be claimed: no forward secrecy.
 * The pair PSK is long-term and provisioned; an attacker who later extracts it
 * from a device can derive every past session key given the recorded
 * handshake nonces. The report's compromise boundary already says endpoint
 * compromise breaks the affected link; this is the concrete mechanism. An
 * ephemeral-DH session establishment is the upgrade path if forward secrecy
 * becomes a requirement, and its handshake cost is measurable with the same
 * instrumentation.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "sec/vox_crypto.h"

#define VOX_PMK_LEN         32
#define VOX_SESSION_LEN     32
#define VOX_HS_NONCE_LEN    16
#define VOX_MAC_LEN         16

/* Load the provisioned master key: NVS namespace "vox" key "pmk" if present,
 * otherwise the CONFIG_VOX_PMK_HEX development default. Returns whether the
 * fallback was used so the run header can flag a non-provisioned build. */
esp_err_t vox_keys_init(bool *used_default_pmk);

const uint8_t *vox_keys_pmk(void);

/* Store a 32-byte PMK in NVS. Used by the console `pmk set <hex>` command. */
esp_err_t vox_keys_store_pmk(const uint8_t pmk[VOX_PMK_LEN]);

/* Independent per-pair PSKs are required for group control. The deployment
 * PMK remains a legacy unicast/discovery fallback, never a group credential.
 * Caller holds vox_security_lock when modifying/reading credentials. */
bool vox_keys_peer_isolated(uint16_t peer_id);
esp_err_t vox_keys_store_peer(uint16_t peer_id, const uint8_t key[VOX_PMK_LEN]);
esp_err_t vox_keys_remove_peer(uint16_t peer_id);

esp_err_t vox_keys_derive_session(const uint8_t nonce_init[VOX_HS_NONCE_LEN],
                                  const uint8_t nonce_resp[VOX_HS_NONCE_LEN],
                                  uint16_t id_init, uint16_t id_resp,
                                  uint8_t out_secret[VOX_SESSION_LEN]);

esp_err_t vox_keys_derive_dir(const uint8_t secret[VOX_SESSION_LEN],
                              uint16_t src_id, uint16_t dst_id, uint8_t epoch,
                              vox_aead_t *out_aead);

/*
 * Group key derivation. One AEAD context for the whole membership set --
 * unlike vox_keys_derive_dir(), there is no src/dst split, because every
 * member both encrypts and decrypts under the same key. Per-sender nonce
 * separation under that shared key comes from vox_aead_nonce()'s existing
 * src_id parameter, not from the key derivation, so no new nonce mechanism
 * is needed here.
 *
 * CRITICAL PROPERTY, do not change: the caller must supply a freshly
 * generated random `secret` on every call, never the previous group secret
 * run through this function again. Unlike a pairwise rekey -- which safely
 * derives the next epoch's key from the *same* long-lived session secret,
 * because both parties are still meant to be able to communicate -- a group
 * rekey exists specifically to exclude a revoked member, and a revoked
 * member still possesses the previous group secret. Deriving the new epoch
 * key from it would let that member derive the new key too, which would
 * make revocation a no-op. `epoch` is included in the KDF info purely for
 * domain separation and to keep the derivation shape consistent with
 * vox_keys_derive_dir(); the security of exclusion rests entirely on
 * `secret` being new, not on `epoch` changing.
 */
esp_err_t vox_keys_derive_group(const uint8_t secret[VOX_SESSION_LEN],
                                uint8_t epoch, vox_aead_t *out_aead);

/* Handshake authenticity. The handshake bodies are public (nonces and ids),
 * so they are authenticated rather than encrypted: HMAC-SHA256 truncated to
 * 16 bytes, under the peer PSK when provisioned. Broadcast discovery and
 * legacy unicast use the PMK-derived bootstrap key. Group control requires
 * isolated pair credentials regardless of discovery authentication. */
esp_err_t vox_keys_hs_mac(const uint8_t *data, size_t len, uint8_t out[VOX_MAC_LEN]);
bool      vox_keys_hs_mac_verify(const uint8_t *data, size_t len, const uint8_t mac[VOX_MAC_LEN]);
