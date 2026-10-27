/*
 * vox_session.h - peer table and pairwise security association.
 *
 * One vox_peer_t per receiver. In the unicast baseline this struct IS the
 * per-listener cost that RQ1 asks about: every field here is state the sender
 * must hold, and every AEAD context here is a key schedule that must be
 * derived, stored and rotated per receiver. sizeof(vox_peer_t) multiplied by
 * N is the key-state term of the scaling measurement, and vox_session_state_bytes()
 * reports it directly so the figure in the write-up is measured, not estimated.
 *
 * Two distinct freshening operations, deliberately separated because they
 * cost different amounts and the report needs both numbers:
 *
 *   vox_session_rekey()      cheap. epoch++, re-expand direction keys from the
 *                            existing session secret. One protected control
 *                            frame each way. Purpose: stay under the per-key
 *                            usage limit and keep sequence space clean.
 *                            Does NOT give post-compromise security.
 *
 *   vox_session_handshake()  expensive. Fresh nonces both ways, new session
 *                            secret, epoch reset to 0. Purpose: new session,
 *                            recovery from lost state, membership change.
 *
 * Epoch transitions keep the previous receive context alive for a grace
 * period so that audio frames already in flight under the old epoch are not
 * discarded. Without that, every rekey would punch an audible hole in the
 * stream, and the "missed-rekey recovery" test case would be measuring an
 * artefact of the implementation rather than a property of the design.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "vox_frame.h"
#include "sec/vox_crypto.h"
#include "sec/vox_keys.h"
#include "sec/vox_replay.h"

typedef enum {
    VOX_SESS_IDLE = 0,
    VOX_SESS_INIT_SENT,
    VOX_SESS_ESTABLISHED,
} vox_sess_state_t;

typedef struct {
    bool     in_use;
    bool     phantom;            /* synthetic peer: costs sender work, never replies */
    uint16_t peer_id;
    uint8_t  mac[6];

    vox_sess_state_t state;
    bool     initiator;
    bool     isolated;           /* established with an independent pair PSK */
    bool     hs_pending;
    bool     hs_have_response;
    int64_t  hs_next_retry_us;
    int64_t  hs_deadline_us;
    uint8_t  finished_i[VOX_HS_NONCE_LEN];
    uint8_t  finished_r[VOX_HS_NONCE_LEN];
    bool     has_finished;
    int64_t  hs_start_us;        /* for measuring establishment latency */
    int64_t  established_us;

    uint8_t  secret[VOX_SESSION_LEN];
    uint8_t  nonce_i[VOX_HS_NONCE_LEN];
    uint8_t  nonce_r[VOX_HS_NONCE_LEN];

    uint8_t  epoch;              /* epoch our transmits currently use */
    vox_aead_t tx;               /* us -> peer, current epoch */
    uint32_t tx_seq;
    uint32_t epoch_tx_frames;

    uint8_t    rx_epoch;         /* epoch `rx` decrypts */
    vox_aead_t rx;               /* peer -> us, current epoch */
    vox_replay_t replay;

    /* Previous-epoch receive context, kept briefly across a rekey. */
    bool       rx_prev_valid;
    uint8_t    rx_prev_epoch;
    vox_aead_t rx_prev;
    vox_replay_t replay_prev;
    int64_t    rx_prev_expiry_us;

    /* Pending outbound rekey, awaiting EPOCH_ACK. */
    bool       rekey_pending;
    uint8_t    rekey_target_epoch;
    int64_t    rekey_start_us;
    int64_t    rekey_retry_us;

    /* Per-peer security counters, reported per run. */
    uint32_t n_tx;
    uint32_t n_rx_ok;
    uint32_t n_auth_fail;
    uint32_t n_replay_drop;
    uint32_t n_epoch_unknown;
    uint32_t n_rekeys;
    uint32_t n_handshakes;
} vox_peer_t;

esp_err_t   vox_session_init(void);

vox_peer_t *vox_peer_add(const uint8_t mac[6], uint16_t peer_id, bool phantom);

/*
 * Broadcast an authenticated invite and accept whoever answers.
 *
 * Sends one SESS_INIT to the broadcast address. Every listener in range that
 * holds the same PMK authenticates it, adds this node as a peer, and replies
 * with a unicast SESS_RESP whose source address is its own MAC -- so this node
 * learns the address of boards it was never told about. Responses are accepted
 * for `window_ms` (0 selects 3000 ms), and only if their handshake MAC
 * verifies.
 *
 * This is what makes a headless rig practical: boards that are on no serial
 * cable cannot announce their MAC to the host any other way, and ESP-NOW has
 * no discovery mechanism of its own.
 */
esp_err_t vox_session_discover(uint32_t window_ms);

/* True while a discovery invite is still accepting answers. */
bool vox_session_invite_open(void);
esp_err_t   vox_peer_remove(uint16_t peer_id);
vox_peer_t *vox_peer_by_mac(const uint8_t mac[6]);
vox_peer_t *vox_peer_by_id(uint16_t peer_id);
int         vox_peer_count(void);
int         vox_peer_count_real(void);
vox_peer_t *vox_peer_at(int idx);

/* Total bytes of per-peer security and session state currently held. */
size_t      vox_session_state_bytes(void);
size_t      vox_session_bytes_per_peer(void);

/* Start (or restart) a full handshake with a peer. */
esp_err_t   vox_session_handshake(vox_peer_t *p);

/* Cheap epoch rotation under the existing session secret. */
esp_err_t   vox_session_rekey(vox_peer_t *p);

/* Called by the receive pipeline for VOX_T_SESS_* / VOX_T_EPOCH_* frames.
 * `src_mac` identifies the sender at link level. */
void        vox_session_on_control(const uint8_t src_mac[6], const vox_hdr_t *hdr,
                                   const uint8_t *body, size_t body_len);

/* Select the receive context matching `epoch`. Returns NULL if the epoch is
 * neither current nor the retained previous one. */
vox_aead_t *vox_session_rx_ctx(vox_peer_t *p, uint8_t epoch, vox_replay_t **out_replay);

/* Periodic housekeeping: retires expired previous-epoch contexts and triggers
 * automatic rekey once a peer reaches the per-key usage limit. */
void        vox_session_tick(void);

/* Reserve before sealing or waiting for radio. Caller holds security mutex. */
bool vox_session_reserve_seq(vox_peer_t *p, uint32_t *seq);
size_t vox_session_allocated_bytes(void);
