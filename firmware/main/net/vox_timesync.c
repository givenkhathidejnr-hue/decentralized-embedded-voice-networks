#include <string.h>
#include "net/vox_timesync.h"
#include "net/vox_link.h"
#include "vox_config.h"
#include "sec/vox_keys.h"
#include "sec/vox_session.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "vox.sync";

#define SYNC_SAMPLES     8
#define SYNC_MAX_RTT_US  100000     /* discard exchanges slower than 100 ms */
#define SYNC_SLOTS       VOX_MAX_PEERS          /* peers we track offsets for */

typedef struct {
    bool     in_use;
    uint16_t peer_id;
    int64_t  offset[SYNC_SAMPLES];
    int64_t  rtt[SYNC_SAMPLES];
    uint32_t n;                     /* total accepted samples */
    bool pending;
    uint32_t pending_t1;
    uint32_t head;
} sync_slot_t;

static sync_slot_t s_slots[SYNC_SLOTS];

static sync_slot_t *slot_get(uint16_t peer_id, bool create)
{
    for (int i = 0; i < SYNC_SLOTS; i++) {
        if (s_slots[i].in_use && s_slots[i].peer_id == peer_id) {   // found existing slot for this peer
            return &s_slots[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (int i = 0; i < SYNC_SLOTS; i++) {
        if (!s_slots[i].in_use) {
            memset(&s_slots[i], 0, sizeof(s_slots[i]));
            s_slots[i].in_use  = true;
            s_slots[i].peer_id = peer_id;
            return &s_slots[i];
        }
    }
    return NULL;
}

esp_err_t vox_timesync_init(void)
{
    memset(s_slots, 0, sizeof(s_slots));
    return ESP_OK;
}

/**
 * Fill a vox_hdr_t structure with the appropriate values for a timesync message.
 *
 * @param h     Pointer to the header to fill.
 * @param type  Message type (VOX_T_SYNC_REQ or VOX_T_SYNC_RESP).
 * @param dst   Destination peer ID.
 *
 * @return      None.
 */
static void hdr_fill(vox_hdr_t *h, uint8_t type, uint16_t dst)
{
    h->ver    = VOX_PROTO_VERSION;
    h->type   = type;
    h->epoch  = 0;
    h->flags  = 0;
    h->src_id = VOX_NODE_ID;
    h->dst_id = dst;
    h->seq    = 0;
}

/**
 * Send a timesync probe to a peer.
 *
 * @param peer_mac  MAC address of the peer.
 * @param peer_id   ID of the peer.
 *
 * @return          ESP_OK on success, or an error code on failure.
 */
esp_err_t vox_timesync_probe(const uint8_t peer_mac[6], uint16_t peer_id)
{
    uint8_t buf[VOX_HDR_LEN + sizeof(vox_sync_body_t) + VOX_MAC_LEN];
    vox_hdr_t *h = (vox_hdr_t *)buf;
    hdr_fill(h, VOX_T_SYNC_REQ, peer_id);

    vox_sync_body_t *b = (vox_sync_body_t *)(buf + VOX_HDR_LEN);
    b->t2_us = 0;
    b->t3_us = 0;
    /*
     * t1 is read as late as possible, immediately before handing the frame to
     * the driver, so it excludes our own frame-construction time.
     */
    b->t1_us = (uint32_t)esp_timer_get_time();
    sync_slot_t *pending=slot_get(peer_id,true);
    if(!pending) return ESP_ERR_NO_MEM;
    pending->pending=true; pending->pending_t1=b->t1_us;

    if (vox_keys_hs_mac(buf, VOX_HDR_LEN + sizeof(*b),
                        buf + VOX_HDR_LEN + sizeof(*b)) != ESP_OK) {
        return ESP_FAIL;
    }
    return vox_link_send(peer_mac, buf, sizeof(buf), 50, NULL);
}

void vox_timesync_on_frame(const uint8_t src_mac[6], const vox_hdr_t *hdr,
                           const uint8_t *body, size_t body_len, int64_t t_rx_us)
{
    if (body_len < sizeof(vox_sync_body_t) + VOX_MAC_LEN) {
        return;
    }
    vox_peer_t *peer=vox_peer_by_mac(src_mac);
    if(!peer || peer->peer_id!=hdr->src_id || hdr->dst_id!=VOX_NODE_ID ||
        peer->state!=VOX_SESS_ESTABLISHED) return;
    const vox_sync_body_t *b = (const vox_sync_body_t *)body;

    /*
     * Sync frames are authenticated even though they carry no secret. They
     * are not a confidentiality concern; they are a measurement-integrity
     * concern. An unauthenticated exchange would let a radio-range attacker
     * inject forged SYNC_RESP frames, drag the offset estimate anywhere it
     * liked, and thereby write whatever one-way delay figures it wanted into
     * the results. Authenticating them costs one HMAC a few times a second
     * and puts the latency measurement inside the same trust boundary as the
     * audio.
     */
    {
        uint8_t signed_buf[VOX_HDR_LEN + sizeof(vox_sync_body_t)];
        memcpy(signed_buf, hdr, VOX_HDR_LEN);
        memcpy(signed_buf + VOX_HDR_LEN, b, sizeof(*b));
        if (!vox_keys_hs_mac_verify(signed_buf, sizeof(signed_buf),
                                    body + sizeof(*b))) {
            ESP_LOGW(TAG, "sync frame from %u failed authentication", hdr->src_id);
            return;
        }
    }

    if (hdr->type == VOX_T_SYNC_REQ) {
        uint8_t buf[VOX_HDR_LEN + sizeof(vox_sync_body_t) + VOX_MAC_LEN];
        vox_hdr_t *h = (vox_hdr_t *)buf;
        hdr_fill(h, VOX_T_SYNC_RESP, hdr->src_id);

        vox_sync_body_t *r = (vox_sync_body_t *)(buf + VOX_HDR_LEN);
        r->t1_us = b->t1_us;
        r->t2_us = (uint32_t)t_rx_us;
        /* t3 and the MAC are computed last, so the MAC covers the final t3. */
        r->t3_us = (uint32_t)esp_timer_get_time();
        if (vox_keys_hs_mac(buf, VOX_HDR_LEN + sizeof(*r),
                            buf + VOX_HDR_LEN + sizeof(*r)) != ESP_OK) {
            return;
        }

        vox_link_send(src_mac, buf, sizeof(buf), 50, NULL);
        return;
    }

    if (hdr->type != VOX_T_SYNC_RESP) {
        return;
    }

    /*
     * All four timestamps are 32-bit microsecond readings from two different
     * clocks. Differences are taken in 32-bit arithmetic and then sign
     * extended, which makes them correct across the ~71.6 minute wrap as long
     * as each individual interval is well under 35 minutes. Round trips are
     * milliseconds, so that holds comfortably.
     */
    sync_slot_t *pending=slot_get(hdr->src_id,false);
    if(!pending || !pending->pending || pending->pending_t1!=b->t1_us) return;
    pending->pending=false;
    uint32_t t1 = b->t1_us;
    uint32_t t2 = b->t2_us;
    uint32_t t3 = b->t3_us;
    uint32_t t4 = (uint32_t)t_rx_us;

    int32_t d_req  = (int32_t)(t2 - t1);   /* peer_clock - our_clock + transit */
    int32_t d_resp = (int32_t)(t4 - t3);   /* our_clock - peer_clock + transit */

    int64_t rtt    = (int64_t)d_req + (int64_t)d_resp;
    int64_t offset = ((int64_t)d_resp - (int64_t)d_req) / 2;   /* ours - peer's */

    if (rtt < 0 || rtt > SYNC_MAX_RTT_US) {
        return;                            /* implausible, discard */
    }

    sync_slot_t *s = slot_get(hdr->src_id, true);
    if (s == NULL) {
        return;
    }
    s->offset[s->head] = offset;
    s->rtt[s->head]    = rtt;
    s->head = (s->head + 1) % SYNC_SAMPLES;
    s->n++;

    ESP_LOGD(TAG, "peer %u offset %lld us rtt %lld us",
             hdr->src_id, (long long)offset, (long long)rtt);
}

static bool best_sample(uint16_t peer_id, int64_t *out_offset, int64_t *out_rtt)
{
    sync_slot_t *s = slot_get(peer_id, false);
    if (s == NULL || s->n == 0) {
        return false;
    }
    uint32_t have = (s->n < SYNC_SAMPLES) ? s->n : SYNC_SAMPLES;
    int best = -1;
    for (uint32_t i = 0; i < have; i++) {
        if (best < 0 || s->rtt[i] < s->rtt[best]) {
            best = (int)i;
        }
    }
    if (best < 0) {
        return false;
    }
    if (out_offset) *out_offset = s->offset[best];
    if (out_rtt)    *out_rtt    = s->rtt[best];
    return true;
}

bool vox_timesync_valid(uint16_t peer_id)
{
    sync_slot_t *s = slot_get(peer_id, false);
    /* Two exchanges is the minimum that lets the min-RTT selection do
     * anything useful; below that the estimate is a single unfiltered sample
     * and should not be trusted for a published latency figure. */
    return (s != NULL) && (s->n >= 2);
}

int64_t vox_timesync_offset_us(uint16_t peer_id)
{
    int64_t off = 0;
    best_sample(peer_id, &off, NULL);
    return off;
}

int64_t vox_timesync_best_rtt_us(uint16_t peer_id)
{
    int64_t rtt = 0;
    best_sample(peer_id, NULL, &rtt);
    return rtt;
}

uint32_t vox_timesync_samples(uint16_t peer_id)
{
    sync_slot_t *s = slot_get(peer_id, false);
    return (s != NULL) ? s->n : 0;
}

int64_t vox_timesync_owd(uint16_t peer_id, uint32_t t_tx_us32, int64_t t_rx_us)
{
    if (!vox_timesync_valid(peer_id)) {
        return INT64_MIN;
    }
    int64_t offset = vox_timesync_offset_us(peer_id);

    /* t_tx is on the peer's clock. Bring it onto ours, then difference in
     * 32-bit space so the wrap cancels. */
    uint32_t tx_local = (uint32_t)((int64_t)t_tx_us32 + offset);
    uint32_t rx_local = (uint32_t)t_rx_us;
    int32_t  owd      = (int32_t)(rx_local - tx_local);

    return (int64_t)owd;
}

void vox_timesync_forget(uint16_t id)
{
    sync_slot_t *slot=slot_get(id,false);
    if(slot) memset(slot,0,sizeof(*slot));
}
