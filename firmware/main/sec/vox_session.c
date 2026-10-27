#include <string.h>
#include "sec/vox_session.h"
#include "net/vox_link.h"
#include "net/vox_timesync.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "mbedtls/platform_util.h"

static const char *TAG="vox.sess";
#define RETRY_US 200000
#define HANDSHAKE_US 5000000
#define VOX_EPOCH_GRACE_US 6000000
#define VOX_REKEY_TIMEOUT_US 4000000
static vox_peer_t s_peers[VOX_MAX_PEERS];
static uint8_t s_invite_nonce[VOX_HS_NONCE_LEN];
static int64_t s_invite_until_us;
static bool invite_open(void) { return esp_timer_get_time()<s_invite_until_us; }
bool vox_session_invite_open(void) { return invite_open(); }
static bool same(const uint8_t *a,const uint8_t *b) { return memcmp(a,b,VOX_HS_NONCE_LEN)==0; }
static void hdr_fill(vox_hdr_t *h,uint8_t type,uint8_t epoch,uint16_t dst,uint32_t seq)
{
    *h=(vox_hdr_t){.ver=VOX_PROTO_VERSION,.type=type,.epoch=epoch,
        .src_id=VOX_NODE_ID,.dst_id=dst,.seq=seq};
}
static esp_err_t send_hs(const uint8_t mac[6],uint8_t type,uint16_t dst,
                          const uint8_t *ni,const uint8_t *nr)
{
    uint8_t buf[VOX_HDR_LEN+sizeof(vox_sess_body_t)+VOX_MAC_LEN];
    hdr_fill((void *)buf,type,0,dst,0);
    vox_sess_body_t b={.node_id=VOX_NODE_ID,.proto=VOX_PROTO_VERSION};
    memcpy(b.nonce,ni,VOX_HS_NONCE_LEN); if(nr) memcpy(b.responder,nr,VOX_HS_NONCE_LEN);
    memcpy(buf+VOX_HDR_LEN,&b,sizeof(b));
    esp_err_t err=vox_keys_hs_mac(buf,VOX_HDR_LEN+sizeof(b),buf+VOX_HDR_LEN+sizeof(b));
    return err==ESP_OK ? vox_link_send(mac,buf,sizeof(buf),50,NULL) : err;
}
bool vox_session_reserve_seq(vox_peer_t *p,uint32_t *seq)
{
    if(!p->tx.ready || p->tx_seq==UINT32_MAX) return false;
    *seq=p->tx_seq++; p->epoch_tx_frames++; return true;
}
static esp_err_t send_protected(vox_peer_t *p,uint8_t type,const uint8_t *body,size_t n)
{
    if(n>8) return ESP_ERR_INVALID_SIZE;
    uint8_t buf[VOX_HDR_LEN+8+16]; uint32_t seq;
    if(!vox_session_reserve_seq(p,&seq)) return ESP_ERR_INVALID_STATE;
    vox_hdr_t *h=(void *)buf; hdr_fill(h,type,p->epoch,p->peer_id,seq);
#ifdef CONFIG_VOX_CRYPTO_ENABLED
    uint8_t nonce[VOX_AEAD_NONCE_LEN];
    vox_aead_nonce(&p->tx,VOX_NODE_ID,h->epoch,h->seq,nonce);
    esp_err_t err=vox_aead_seal(&p->tx,nonce,buf,VOX_HDR_LEN,body,n,
        buf+VOX_HDR_LEN,buf+VOX_HDR_LEN+n,VOX_TAG_LEN);
    if(err!=ESP_OK) return err;
#else
    h->flags=VOX_F_UNPROTECTED; if(n) memcpy(buf+VOX_HDR_LEN,body,n);
#endif
    return vox_link_send(p->mac,buf,VOX_HDR_LEN+n+VOX_TAG_LEN,50,NULL);
}
static esp_err_t install_epoch_keys(vox_peer_t *p,uint8_t epoch,bool tx,bool prev)
{
    if(prev && p->rx.ready) {
        if(vox_keys_derive_dir(p->secret,p->peer_id,VOX_NODE_ID,p->rx_epoch,&p->rx_prev)!=ESP_OK) return ESP_FAIL;
        p->rx_prev_epoch=p->rx_epoch; p->replay_prev=p->replay;
        p->rx_prev_valid=true; p->rx_prev_expiry_us=esp_timer_get_time()+VOX_EPOCH_GRACE_US;
    } else { vox_aead_clear(&p->rx_prev); p->rx_prev_valid=false; }
    if(vox_keys_derive_dir(p->secret,p->peer_id,VOX_NODE_ID,epoch,&p->rx)!=ESP_OK) {
        p->state=VOX_SESS_IDLE; return ESP_FAIL;
    }
    p->rx_epoch=epoch;
    if(tx) {
        if(vox_keys_derive_dir(p->secret,VOX_NODE_ID,p->peer_id,epoch,&p->tx)!=ESP_OK) {
            p->state=VOX_SESS_IDLE; return ESP_FAIL;
        }
        p->epoch=epoch; p->epoch_tx_frames=0;
    }
    return ESP_OK;
}
static void completed(vox_peer_t *p)
{
    vox_timesync_forget(p->peer_id); /* a reboot invalidates the old clock offset */
    p->state=VOX_SESS_ESTABLISHED; p->hs_pending=false;
    p->has_finished=true; memcpy(p->finished_i,p->nonce_i,VOX_HS_NONCE_LEN);
    memcpy(p->finished_r,p->nonce_r,VOX_HS_NONCE_LEN);
    p->established_us=esp_timer_get_time(); p->n_handshakes++;
    ESP_LOGI(TAG,"peer %u: session established, isolated=%d",p->peer_id,p->isolated);
}
static esp_err_t fresh_keys(vox_peer_t *p)
{
    if(vox_keys_derive_session(p->nonce_i,p->nonce_r,
        p->initiator?VOX_NODE_ID:p->peer_id,p->initiator?p->peer_id:VOX_NODE_ID,p->secret)!=ESP_OK) return ESP_FAIL;
    p->isolated=vox_keys_peer_isolated(p->peer_id);
    p->tx_seq=0; p->rekey_pending=false;
    vox_replay_reset(&p->replay);
    return install_epoch_keys(p,0,true,false);
}
esp_err_t vox_session_init(void)
{
    memset(s_peers, 0, sizeof(s_peers));
    return ESP_OK;
}

vox_peer_t *vox_peer_add(const uint8_t mac[6], uint16_t peer_id, bool phantom)
{
    if(!peer_id || peer_id==VOX_NODE_ID || peer_id==VOX_BROADCAST_ID) return NULL;
    vox_peer_t *existing = vox_peer_by_id(peer_id);
    if (existing != NULL) {
        return memcmp(existing->mac,mac,6)==0 ? existing : NULL;
    }
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        if (s_peers[i].in_use) {
            continue;
        }
        vox_peer_t *p = &s_peers[i];
        memset(p, 0, sizeof(*p));
        p->in_use  = true;
        p->phantom = phantom;
        p->peer_id = peer_id;
        memcpy(p->mac, mac, 6);
        p->state = VOX_SESS_IDLE;
        vox_replay_reset(&p->replay);

        if (vox_link_peer_add(mac, NULL) != ESP_OK) {
            p->in_use = false;
            ESP_LOGE(TAG, "ESP-NOW refused peer " MACSTR, MAC2STR(mac));
            return NULL;
        }
        ESP_LOGI(TAG, "peer %u added " MACSTR "%s", peer_id, MAC2STR(mac),
                 phantom ? " (phantom)" : "");
        return p;
    }
    ESP_LOGE(TAG, "peer table full (%d)", VOX_MAX_PEERS);
    return NULL;
}

esp_err_t vox_peer_remove(uint16_t peer_id)
{
    vox_peer_t *p = vox_peer_by_id(peer_id);
    if (p == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    vox_timesync_forget(peer_id);
    vox_link_peer_del(p->mac);
    vox_aead_clear(&p->tx);
    vox_aead_clear(&p->rx);
    vox_aead_clear(&p->rx_prev);
    mbedtls_platform_zeroize(p->secret, sizeof(p->secret));
    memset(p, 0, sizeof(*p));
    return ESP_OK;
}

vox_peer_t *vox_peer_by_mac(const uint8_t mac[6])
{
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        if (s_peers[i].in_use && memcmp(s_peers[i].mac, mac, 6) == 0) {
            return &s_peers[i];
        }
    }
    return NULL;
}

vox_peer_t *vox_peer_by_id(uint16_t peer_id)
{
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        if (s_peers[i].in_use && s_peers[i].peer_id == peer_id) {
            return &s_peers[i];
        }
    }
    return NULL;
}

int vox_peer_count(void)
{
    int n = 0;
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        if (s_peers[i].in_use) n++;
    }
    return n;
}

int vox_peer_count_real(void)
{
    int n = 0;
    for (int i = 0; i < VOX_MAX_PEERS; i++) {
        if (s_peers[i].in_use && !s_peers[i].phantom) n++;
    }
    return n;
}

vox_peer_t *vox_peer_at(int idx)
{
    if (idx < 0 || idx >= VOX_MAX_PEERS) {
        return NULL;
    }
    return s_peers[idx].in_use ? &s_peers[idx] : NULL;
}

size_t vox_session_bytes_per_peer(void)
{
    return sizeof(vox_peer_t);
}

size_t vox_session_state_bytes(void)
{
    return (size_t)vox_peer_count() * sizeof(vox_peer_t);
}

size_t vox_session_allocated_bytes(void) { return sizeof(s_peers); }
esp_err_t vox_session_handshake(vox_peer_t *p)
{
    if(!p) return ESP_ERR_INVALID_ARG;
    if(p->phantom) {
        esp_fill_random(p->secret,sizeof(p->secret)); p->tx_seq=0;
        if(install_epoch_keys(p,0,true,false)!=ESP_OK) return ESP_FAIL;
        p->state=VOX_SESS_ESTABLISHED; return ESP_OK;
    }
    esp_fill_random(p->nonce_i,sizeof(p->nonce_i)); memset(p->nonce_r,0,sizeof(p->nonce_r));
    p->initiator=true; p->hs_pending=true; p->hs_have_response=false;
    p->state=VOX_SESS_INIT_SENT; p->hs_start_us=esp_timer_get_time();
    p->hs_deadline_us=p->hs_start_us+HANDSHAKE_US; p->hs_next_retry_us=p->hs_start_us+RETRY_US;
    /* A failed send remains pending for bounded retry. */
    send_hs(p->mac,VOX_T_SESS_INIT,p->peer_id,p->nonce_i,NULL);
    return ESP_OK;
}
esp_err_t vox_session_discover(uint32_t window_ms)
{
    if(!window_ms) window_ms=3000;
    esp_fill_random(s_invite_nonce,sizeof(s_invite_nonce));
    s_invite_until_us=esp_timer_get_time()+(int64_t)window_ms*1000;
    return send_hs(VOX_BROADCAST_MAC,VOX_T_SESS_INIT,VOX_BROADCAST_ID,s_invite_nonce,NULL);
}
static void on_handshake(const uint8_t mac[6],const vox_hdr_t *h,const uint8_t *body,size_t len)
{
    if(len!=sizeof(vox_sess_body_t)+VOX_MAC_LEN || h->src_id==VOX_NODE_ID ||
        !h->src_id || h->src_id==VOX_BROADCAST_ID ||
        (h->dst_id!=VOX_NODE_ID && !(h->type==VOX_T_SESS_INIT && h->dst_id==VOX_BROADCAST_ID))) return;
    const vox_sess_body_t *b=(const void *)body;
    if(b->node_id!=h->src_id || b->proto!=VOX_PROTO_VERSION) return;
    uint8_t signed_buf[VOX_HDR_LEN+sizeof(*b)];
    memcpy(signed_buf,h,VOX_HDR_LEN); memcpy(signed_buf+VOX_HDR_LEN,b,sizeof(*b));
    if(!vox_keys_hs_mac_verify(signed_buf,sizeof(signed_buf),body+sizeof(*b))) return;
    vox_peer_t *p=vox_peer_by_mac(mac);
    if(p && p->peer_id!=h->src_id) return;
    if(!p) {
        if(h->type!=VOX_T_SESS_INIT && !(h->type==VOX_T_SESS_RESP && invite_open() && same(b->nonce,s_invite_nonce))) return;
        p=vox_peer_add(mac,h->src_id,false); if(!p) return;
    }
    if(h->type==VOX_T_SESS_INIT) {
        if(p->has_finished && same(b->nonce,p->finished_i)) {
            send_hs(mac,VOX_T_SESS_RESP,p->peer_id,p->finished_i,p->finished_r); return;
        }
        if(p->hs_pending && p->initiator && VOX_NODE_ID<p->peer_id) return;
        if(!(p->hs_pending && !p->initiator && same(p->nonce_i,b->nonce))) {
            memcpy(p->nonce_i,b->nonce,VOX_HS_NONCE_LEN); esp_fill_random(p->nonce_r,sizeof(p->nonce_r));
            p->initiator=false; p->hs_pending=true; p->hs_have_response=false;
            p->hs_start_us=esp_timer_get_time(); p->hs_deadline_us=p->hs_start_us+HANDSHAKE_US;
        }
        /* Keep the current association alive until fresh CONFIRM proves the
         * initiator received this responder's newly generated challenge. */
        send_hs(mac,VOX_T_SESS_RESP,p->peer_id,p->nonce_i,p->nonce_r);
        p->hs_next_retry_us=esp_timer_get_time()+RETRY_US;
    } else if(h->type==VOX_T_SESS_RESP) {
        if(!(p->hs_pending && p->initiator)) {
            if(!invite_open() || !same(b->nonce,s_invite_nonce)) return;
            if(p->has_finished && same(b->nonce,p->finished_i) && same(b->responder,p->finished_r)) return;
            p->initiator=true; p->hs_pending=true; p->hs_have_response=false;
            memcpy(p->nonce_i,s_invite_nonce,VOX_HS_NONCE_LEN);
            p->hs_start_us=esp_timer_get_time(); p->hs_deadline_us=p->hs_start_us+HANDSHAKE_US;
        }
        if(!same(b->nonce,p->nonce_i)) return;
        if(p->hs_have_response && !same(b->responder,p->nonce_r)) return;
        if(!p->hs_have_response) {
            memcpy(p->nonce_r,b->responder,VOX_HS_NONCE_LEN);
            if(fresh_keys(p)!=ESP_OK) return;
            p->state=VOX_SESS_INIT_SENT; p->hs_have_response=true;
        }
        send_hs(mac,VOX_T_SESS_CONFIRM,p->peer_id,p->nonce_i,p->nonce_r);
        p->hs_next_retry_us=esp_timer_get_time()+RETRY_US;
    } else if(h->type==VOX_T_SESS_CONFIRM) {
        /* Duplicate confirmation must only retransmit READY, never reinstall. */
        if(p->has_finished && same(b->nonce,p->finished_i) && same(b->responder,p->finished_r)) {
            if(p->epoch==0 && p->state==VOX_SESS_ESTABLISHED) send_protected(p,VOX_T_SESS_READY,NULL,0);
            return;
        }
        if(!p->hs_pending || p->initiator || !same(b->nonce,p->nonce_i) || !same(b->responder,p->nonce_r)) return;
        if(fresh_keys(p)!=ESP_OK) return;
        completed(p); send_protected(p,VOX_T_SESS_READY,NULL,0);
    }
}
vox_aead_t *vox_session_rx_ctx(vox_peer_t *p,uint8_t e,vox_replay_t **w)
{
    if(p->rx.ready && p->rx_epoch==e) { *w=&p->replay; return &p->rx; }
    if(p->rx_prev_valid && p->rx_prev.ready && p->rx_prev_epoch==e && esp_timer_get_time()<=p->rx_prev_expiry_us) {
        *w=&p->replay_prev; return &p->rx_prev;
    }
    return NULL;
}
esp_err_t vox_session_rekey(vox_peer_t *p)
{
    if(!p || p->state!=VOX_SESS_ESTABLISHED || p->rekey_pending || p->hs_pending) return ESP_ERR_INVALID_STATE;
    if(p->epoch==UINT8_MAX || p->tx_seq>UINT32_MAX-1024) return vox_session_handshake(p);
    uint8_t next=p->epoch+1;
    if(p->phantom) return install_epoch_keys(p,next,true,false);
    if(install_epoch_keys(p,next,false,true)!=ESP_OK) return ESP_FAIL;
    p->rekey_pending=true; p->rekey_target_epoch=next;
    p->rekey_start_us=esp_timer_get_time(); p->rekey_retry_us=p->rekey_start_us+RETRY_US;
    send_protected(p,VOX_T_EPOCH_REQ,&next,1); return ESP_OK;
}
void vox_session_on_control(const uint8_t mac[6],const vox_hdr_t *h,const uint8_t *body,size_t len)
{
    if(h->type==VOX_T_SESS_INIT || h->type==VOX_T_SESS_RESP || h->type==VOX_T_SESS_CONFIRM) {
        on_handshake(mac,h,body,len); return;
    }
    vox_peer_t *p=vox_peer_by_mac(mac);
    if(!p || p->peer_id!=h->src_id || h->dst_id!=VOX_NODE_ID) return;
    bool waiting_ready=h->type==VOX_T_SESS_READY && p->hs_pending && p->initiator && p->hs_have_response;
    if(p->state!=VOX_SESS_ESTABLISHED && !waiting_ready) return;
    uint8_t pt[8]; size_t n;
#ifdef CONFIG_VOX_CRYPTO_ENABLED
    if(len<VOX_TAG_LEN || len-VOX_TAG_LEN>sizeof(pt)) return;
    n=len-VOX_TAG_LEN;
    vox_replay_t *w=NULL; vox_aead_t *a=vox_session_rx_ctx(p,h->epoch,&w);
    if(!a) { p->n_epoch_unknown++; return; }
    if(!vox_replay_is_fresh(w,h->seq)) { p->n_replay_drop++; return; }
    uint8_t nonce[VOX_AEAD_NONCE_LEN]; vox_aead_nonce(a,h->src_id,h->epoch,h->seq,nonce);
    if(vox_aead_open(a,nonce,(const uint8_t *)h,VOX_HDR_LEN,body,n,body+n,VOX_TAG_LEN,pt)!=ESP_OK) { p->n_auth_fail++; return; }
    vox_replay_commit(w,h->seq);
#else
    if(len>sizeof(pt)) return;
    n=len;
    if(n) memcpy(pt,body,n);
#endif
    if(waiting_ready && h->epoch==0 && n==0) { completed(p); return; }
    if(h->type==VOX_T_EPOCH_REQ && n==1) {
        uint8_t next=pt[0];
        if(next==p->epoch) { send_protected(p,VOX_T_EPOCH_ACK,&next,1); return; }
        if(p->epoch==UINT8_MAX || next!=(uint8_t)(p->epoch+1)) return;
        /* Symmetric simultaneous requests for the same target are safe. */
        if(install_epoch_keys(p,next,true,p->rx_epoch!=next)!=ESP_OK) return;
        p->rekey_pending=false; p->n_rekeys++;
        send_protected(p,VOX_T_EPOCH_ACK,&next,1);
    } else if(h->type==VOX_T_EPOCH_ACK && n==1 && p->rekey_pending &&
              h->epoch==p->rekey_target_epoch && pt[0]==p->rekey_target_epoch) {
        if(vox_keys_derive_dir(p->secret,VOX_NODE_ID,p->peer_id,pt[0],&p->tx)!=ESP_OK) { p->state=VOX_SESS_IDLE; return; }
        p->epoch=pt[0]; p->epoch_tx_frames=0; p->rekey_pending=false; p->n_rekeys++;
    }
}
void vox_session_tick(void)
{
    int64_t now=esp_timer_get_time();
    for(int i=0;i<VOX_MAX_PEERS;i++) {
        vox_peer_t *p=&s_peers[i]; if(!p->in_use) continue;
        if(p->rx_prev_valid && now>p->rx_prev_expiry_us) { vox_aead_clear(&p->rx_prev); p->rx_prev_valid=false; }
        if(p->hs_pending) {
            if(now>p->hs_deadline_us) {
                p->hs_pending=false;
                if(p->state==VOX_SESS_INIT_SENT) p->state=VOX_SESS_IDLE;
                ESP_LOGW(TAG,"peer %u handshake timeout",p->peer_id);
            } else if(now>=p->hs_next_retry_us) {
                uint8_t type=p->initiator?(p->hs_have_response?VOX_T_SESS_CONFIRM:VOX_T_SESS_INIT):VOX_T_SESS_RESP;
                send_hs(p->mac,type,p->peer_id,p->nonce_i,type==VOX_T_SESS_INIT?NULL:p->nonce_r);
                p->hs_next_retry_us=now+RETRY_US;
            }
        }
        if(p->rekey_pending) {
            if(now-p->rekey_start_us>VOX_REKEY_TIMEOUT_US) {
                p->rekey_pending=false; vox_session_handshake(p);
            } else if(now>=p->rekey_retry_us) {
                send_protected(p,VOX_T_EPOCH_REQ,&p->rekey_target_epoch,1); p->rekey_retry_us=now+RETRY_US;
            }
        }
        if(p->state==VOX_SESS_ESTABLISHED && !p->hs_pending && !p->rekey_pending &&
            (p->epoch_tx_frames>=VOX_EPOCH_MAX_FRAMES || p->tx_seq>UINT32_MAX-1024)) vox_session_rekey(p);
    }
}
