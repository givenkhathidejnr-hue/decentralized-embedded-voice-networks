/*
 * app_main.c - the baseline voice pipeline.
 *
 * Four tasks, in descending order of deadline pressure:
 *
 *   playout    pops the jitter buffer and feeds the DAC. Paced by the I2S
 *              clock itself, which is the only clock in the system that is
 *              actually the audio clock.
 *   rx         drains the ESP-NOW ingress queue: verify, replay-check,
 *              decode, enqueue for playout.
 *   tx         captures, encodes once, then protects and transmits once per
 *              receiver.
 *   housekeep  clock-offset probes, session maintenance, resource sampling.
 *
 * THE SHAPE OF THE BASELINE, and why it is the right control condition:
 *
 * The codec runs once per frame. Protection and transmission run once per
 * frame PER RECEIVER, each under that receiver's own key, sequence counter
 * and replay window. That is what "independently protected unicast" means,
 * and it is the arm whose cost is expected to grow linearly with the
 * audience. Encoding once rather than N times is deliberate: it gives unicast
 * its best case, so the comparison against a group architecture is not won by
 * handicapping the baseline.
 *
 * Every stage boundary is timestamped separately, so the resulting numbers
 * can attribute cost to the codec, to the cryptography, or to the radio,
 * rather than reporting one undifferentiated "overhead".
 */
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "vox_config.h"
#include "vox_frame.h"
#include "vox_ptt.h"
#include "vox_console.h"
#include "audio/vox_audio.h"
#include "audio/vox_codec.h"
#include "audio/vox_jitterbuf.h"
#include "net/vox_link.h"
#include "net/vox_timesync.h"
#include "sec/vox_crypto.h"
#include "sec/vox_keys.h"
#include "sec/vox_security.h"
#include "esp_system.h"
#include "sec/vox_session.h"
#include "sec/vox_group.h"
#include "sec/vox_group_control.h"
#include "metrics/vox_metrics.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_random.h"

static const char *TAG = "vox";

/* Static working buffers. Nothing on the audio path allocates at run time:
 * a failed allocation mid-run would show up as a dropout and be misread as a
 * network or CPU effect. */
static int16_t s_pcm_tx[VOX_SAMPLES_PER_FRAME];
static uint8_t s_encoded[VOX_ENCODED_BYTES];
static uint8_t s_plain[VOX_AUDIO_PLAINTEXT];
static uint8_t s_txbuf[VOX_FRAME_MAX_LEN];

static int16_t s_pcm_rx[VOX_SAMPLES_PER_FRAME];
#ifdef CONFIG_VOX_CRYPTO_ENABLED
/* Decryption target. The unprotected build decodes straight out of the receive
 * buffer, so this would be VOX_MAX_PLAINTEXT bytes of DRAM nothing touches. */
static uint8_t s_rxplain[VOX_MAX_PLAINTEXT];
#endif
static int16_t s_ref[VOX_SAMPLES_PER_FRAME];
static int16_t s_silence[VOX_SAMPLES_PER_FRAME];

static uint32_t s_frame_ctr;      /* sender-side absolute frame index */

/*
 * The most recent frame actually put on the air, retained so the console can
 * act as the capture-and-inject attacker from the threat model. A real
 * adversary would sniff this off the air; keeping a copy locally reproduces
 * the same capability without needing a second radio, and the frame is
 * byte-identical to what was transmitted.
 */
static uint8_t  s_last_frame[VOX_FRAME_MAX_LEN];
static size_t   s_last_len;
static uint8_t  s_last_mac[6];
static bool     s_last_valid;
static bool     s_last_is_group;   /* captured frame was broadcast under the
                                     * group key, not sent unicast to s_last_mac --
                                     * inject() below needs to know which transport
                                     * to replay it over. See docs/DRAFT_CH4_GROUP_
                                     * METHODOLOGY.md SS4.5.1's "wrong credential and
                                     * hostile media" / "former-member attack" cases:
                                     * both require replaying/tampering a captured
                                     * frame that was protected under the GROUP key,
                                     * which the unicast-only capture below never
                                     * produced. */

/* ===================== reference-signal phase lock ======================= */
/*
 * The synthetic source repeats with a period of half a second. The receiver
 * does not know which frame index the sender was on, so it locks phase once
 * per talk burst by trying every frame-aligned offset within one period and
 * keeping the one with the lowest error. After that it simply advances with
 * the sequence number. Costs one correlation per burst and nothing per frame.
 */
#define REF_PERIOD_SAMPLES  (VOX_SAMPLE_RATE_HZ / 2)
#define REF_PHASE_SPAN      ((REF_PERIOD_SAMPLES + VOX_SAMPLES_PER_FRAME - 1) / VOX_SAMPLES_PER_FRAME)

static bool     s_ref_locked;
static uint16_t s_ref_stream;
static uint16_t s_ref_sender;
static uint32_t s_ref_seq_base;
static uint32_t s_ref_phase;

static uint32_t rms_err_against(const int16_t *got, uint32_t frame_index)
{
    if (!vox_audio_reference(frame_index * VOX_SAMPLES_PER_FRAME, s_ref,
                             VOX_SAMPLES_PER_FRAME)) {
        return UINT32_MAX;
    }
    uint64_t acc = 0;
    for (int i = 0; i < VOX_SAMPLES_PER_FRAME; i++) {
        int32_t d = (int32_t)got[i] - (int32_t)s_ref[i];
        acc += (uint64_t)((int64_t)d * (int64_t)d);
    }
    return (uint32_t)sqrt((double)acc / (double)VOX_SAMPLES_PER_FRAME);
}

static uint32_t reference_error(const int16_t *got, uint16_t stream_id, uint32_t seq)
{
    if (stream_id != s_ref_stream || !s_ref_locked) {
        uint32_t best = UINT32_MAX;
        uint32_t best_phase = 0;
        for (uint32_t ph = 0; ph < REF_PHASE_SPAN; ph++) {
            uint32_t e = rms_err_against(got, ph);
            if (e == UINT32_MAX) {
                return UINT32_MAX;      /* no reference available at all */
            }
            if (e < best) {
                best = e;
                best_phase = ph;
            }
        }
        s_ref_locked   = true;
        s_ref_stream   = stream_id;
        s_ref_seq_base = seq;
        s_ref_phase    = best_phase;
        return best;
    }

    uint32_t idx = s_ref_phase + (seq - s_ref_seq_base);
    return rms_err_against(got, idx);
}

/* ============================== transmit ================================ */

/* Media numbering is per talk burst; packet counters are per key/session.
 * Control traffic and rekeying never consume/reset media positions. */
static uint32_t s_media_seq;
static uint16_t s_tx_stream;
static bool s_tx_group;

static void send_media(bool group, size_t pt_len, uint8_t flags, bool end,
                       uint32_t encode_us)
{
    uint32_t protect_us=0, send_us=0, real_us=0, air_max=0;
    uint8_t npeer=0,nreal=0,nfail=0;
    for(int i=0;i<(group?1:VOX_MAX_PEERS);i++) {
        uint8_t mac[6]; bool phantom=false;
        vox_security_lock();
        vox_peer_t *p=group?NULL:vox_peer_at(i);
        vox_aead_t *a=NULL; uint32_t seq; uint8_t epoch; uint16_t dst;
        if(group) {
            if(!vox_group_reserve_seq(&seq)) { vox_security_unlock(); nfail++; break; }
            a=vox_group_aead(); epoch=vox_group_epoch(); dst=VOX_BROADCAST_ID;
            memcpy(mac,VOX_BROADCAST_MAC,6);
        } else {
            if(!p || p->state!=VOX_SESS_ESTABLISHED || !vox_session_reserve_seq(p,&seq)) {
                vox_security_unlock(); continue;
            }
            a=&p->tx; epoch=p->epoch; dst=p->peer_id; phantom=p->phantom;
            memcpy(mac,p->mac,6); p->n_tx++;
        }
        vox_hdr_t *h=(void *)s_txbuf;
        *h=(vox_hdr_t){.ver=VOX_PROTO_VERSION,.type=end?VOX_T_MEDIA_END:VOX_T_AUDIO,
            .epoch=epoch,.flags=flags,.src_id=VOX_NODE_ID,.dst_id=dst,.seq=seq};
        int64_t p0=esp_timer_get_time();
#ifdef CONFIG_VOX_CRYPTO_ENABLED
        uint8_t nonce[VOX_AEAD_NONCE_LEN]; vox_aead_nonce(a,VOX_NODE_ID,epoch,seq,nonce);
        esp_err_t seal=vox_aead_seal(a,nonce,s_txbuf,VOX_HDR_LEN,s_plain,pt_len,
            s_txbuf+VOX_HDR_LEN,s_txbuf+VOX_HDR_LEN+pt_len,VOX_TAG_LEN);
        if(seal!=ESP_OK) { vox_security_unlock(); nfail++; continue; }
#else
        (void)a; h->flags|=VOX_F_UNPROTECTED; memcpy(s_txbuf+VOX_HDR_LEN,s_plain,pt_len);
#endif
        protect_us+=(uint32_t)(esp_timer_get_time()-p0);
        size_t length=VOX_HDR_LEN+pt_len+VOX_TAG_LEN;
        if(!phantom && !end) {
            memcpy(s_last_frame,s_txbuf,length); memcpy(s_last_mac,mac,6);
            s_last_len=length; s_last_valid=true; s_last_is_group=group;
        }
        vox_security_unlock();
        int64_t p1=esp_timer_get_time();
        vox_trace_tx_pulse();
        int64_t air=0; esp_err_t err=vox_link_send(mac,s_txbuf,length,VOX_FRAME_MS*2,&air);
        uint32_t elapsed=(uint32_t)(esp_timer_get_time()-p1);
        send_us+=elapsed; if(air>air_max) air_max=(uint32_t)air;
        if(!phantom) { real_us+=elapsed; nreal++; if(err!=ESP_OK) nfail++; }
        npeer++;
    }
    if(!end) {
        vox_tx_sample_t sample={.seq=s_frame_ctr,.encode_us=encode_us,
            .protect_us=protect_us,.send_us=send_us,.send_real_us=real_us,
            .air_us_max=air_max,.npeer=npeer,.nreal=nreal,.nfail=nfail,
            .on_air_bytes=VOX_ON_AIR_BYTES+VOX_LINK_OVERHEAD_BYTES};
        vox_metrics_tx(&sample);
    }
}
static void tx_media_frame(void)
{
    int64_t capture=esp_timer_get_time();
    uint32_t media=s_media_seq++;
    uint32_t frame=s_frame_ctr++;
    if(!vox_audio_src_read(frame*VOX_SAMPLES_PER_FRAME,s_pcm_tx,VOX_SAMPLES_PER_FRAME,VOX_FRAME_MS*2)) return;
    int64_t t1=esp_timer_get_time();
    size_t enc=vox_codec()->encode(s_pcm_tx,VOX_SAMPLES_PER_FRAME,s_encoded,sizeof(s_encoded));
    int64_t t2=esp_timer_get_time(); if(!enc) return;
    vox_audio_sub_t *sub=(void *)s_plain;
    *sub=(vox_audio_sub_t){.t_tx_us=(uint32_t)capture,.stream_id=s_tx_stream,
        .codec=VOX_CODEC_ID,.media_seq=media};
    memcpy(s_plain+VOX_AUDIO_SUBHDR_LEN,s_encoded,enc);
    send_media(s_tx_group,VOX_AUDIO_SUBHDR_LEN+enc,media==0?VOX_F_TALK_START:0,false,(uint32_t)(t2-t1));
}
static void tx_end_frame(void)
{
    vox_audio_sub_t *sub=(void *)s_plain;
    *sub=(vox_audio_sub_t){.t_tx_us=(uint32_t)esp_timer_get_time(),.stream_id=s_tx_stream,
        .codec=VOX_CODEC_ID,.media_seq=s_media_seq};
    send_media(s_tx_group,VOX_AUDIO_SUBHDR_LEN,VOX_F_TALK_END,true,0);
}
static void tx_task(void *arg)
{
    (void)arg; TickType_t last=xTaskGetTickCount();
    bool was_active=false; unsigned end_retries=0;
    for(;;) {
        vTaskDelayUntil(&last,pdMS_TO_TICKS(VOX_FRAME_MS));
        bool active,group; uint16_t stream;
        vox_ptt_snapshot(&active,&group,&stream);
        if(active && (!was_active || stream!=s_tx_stream)) {
            s_tx_stream=stream; s_tx_group=group; s_media_seq=0; end_retries=0;
        }
        if(was_active && !active) end_retries=3;
        was_active=active;
        if(!active) { if(end_retries) { tx_end_frame(); end_retries--; } continue; }
        int64_t t=esp_timer_get_time(); tx_media_frame();
        if(esp_timer_get_time()-t>VOX_FRAME_MS*1000) vox_metrics_tx_deadline_miss();
    }
}

/* =============================== receive ================================ */

/* Open under a stable context and commit replay state atomically. Codec and
 * I2S work stay outside the security mutex so TX/RX retain pipeline overlap. */
static bool open_media(const vox_rx_pkt_t *pkt,const vox_hdr_t *h,
                       const uint8_t *body,size_t len,const uint8_t **pt,size_t *n)
{
    bool group=h->dst_id==VOX_BROADCAST_ID, ok=false;
    vox_security_lock();
    vox_peer_t *p=group?NULL:vox_peer_by_mac(pkt->src_mac);
    vox_aead_t *a=NULL; vox_replay_t *win=NULL;
    if(group) {
        if(!vox_group_ready() || h->epoch!=vox_group_epoch() || !(win=vox_group_replay_for(h->src_id))) {
            vox_metrics_rx_reject(VOX_REJECT_EPOCH); goto out;
        }
        a=vox_group_aead();
    } else {
        if(!p || p->state!=VOX_SESS_ESTABLISHED || h->src_id!=p->peer_id) {
            vox_metrics_rx_reject(VOX_REJECT_MALFORMED); goto out;
        }
        a=vox_session_rx_ctx(p,h->epoch,&win);
    }
#ifdef CONFIG_VOX_CRYPTO_ENABLED
    if(!a) { vox_metrics_rx_reject(VOX_REJECT_EPOCH); goto out; }
    if(len<VOX_TAG_LEN+VOX_AUDIO_SUBHDR_LEN || len-VOX_TAG_LEN>sizeof(s_rxplain)) {
        vox_metrics_rx_reject(VOX_REJECT_MALFORMED); goto out;
    }
    if(!vox_replay_is_fresh(win,h->seq)) { vox_metrics_rx_reject(VOX_REJECT_REPLAY); goto out; }
    uint8_t nonce[VOX_AEAD_NONCE_LEN]; vox_aead_nonce(a,h->src_id,h->epoch,h->seq,nonce);
    *n=len-VOX_TAG_LEN;
    if(vox_aead_open(a,nonce,(const uint8_t *)h,VOX_HDR_LEN,body,*n,body+*n,VOX_TAG_LEN,s_rxplain)!=ESP_OK) {
        vox_metrics_rx_reject(VOX_REJECT_AUTH); goto out;
    }
    vox_replay_commit(win,h->seq); *pt=s_rxplain;
#else
    (void)a; (void)win;
    if(group || len<VOX_AUDIO_SUBHDR_LEN) { vox_metrics_rx_reject(VOX_REJECT_MALFORMED); goto out; }
    *pt=body; *n=len;
#endif
    if(p && h->type==VOX_T_AUDIO) p->n_rx_ok++;
    ok=true;
out:
    vox_security_unlock(); return ok;
}
static void rx_audio(const vox_rx_pkt_t *pkt,const vox_hdr_t *h,const uint8_t *body,size_t len)
{
    const uint8_t *pt=NULL; size_t n=0;
    int64_t v0=esp_timer_get_time();
    if(!open_media(pkt,h,body,len,&pt,&n)) return;
    int64_t v1=esp_timer_get_time();
    const vox_audio_sub_t *sub=(const void *)pt;
    if(sub->codec!=VOX_CODEC_ID) { vox_metrics_rx_reject(VOX_REJECT_MALFORMED); return; }
    if(h->type==VOX_T_MEDIA_END) {
        if(n==VOX_AUDIO_SUBHDR_LEN) vox_jb_end(h->src_id,sub->stream_id,sub->media_seq);
        else vox_metrics_rx_reject(VOX_REJECT_MALFORMED);
        return;
    }
    if(n!=VOX_AUDIO_PLAINTEXT) { vox_metrics_rx_reject(VOX_REJECT_MALFORMED); return; }
    int64_t d0=esp_timer_get_time();
    size_t nsamp=vox_codec()->decode(pt+VOX_AUDIO_SUBHDR_LEN,n-VOX_AUDIO_SUBHDR_LEN,s_pcm_rx,VOX_SAMPLES_PER_FRAME);
    int64_t d1=esp_timer_get_time(); if(nsamp!=VOX_SAMPLES_PER_FRAME) { vox_metrics_rx_reject(VOX_REJECT_MALFORMED); return; }
    vox_security_lock();
    int64_t owd=vox_timesync_owd(h->src_id,sub->t_tx_us,pkt->t_rx_us);
    vox_security_unlock();
    /* Include sender identity when selecting the synthetic reference phase. */
    if(s_ref_sender!=h->src_id) { s_ref_locked=false; s_ref_sender=h->src_id; }
    uint32_t rms=reference_error(s_pcm_rx,sub->stream_id,sub->media_seq);
    vox_jb_frame_t f={.seq=sub->media_seq,.stream_id=sub->stream_id,.sender_id=h->src_id,
        .t_tx_us=sub->t_tx_us,.t_rx_us=pkt->t_rx_us,.nsamp=nsamp};
    memcpy(f.pcm,s_pcm_rx,nsamp*sizeof(int16_t));
    if(!vox_jb_push(&f)) vox_metrics_rx_reject(VOX_REJECT_LATE);
    vox_metrics_rx(sub->media_seq,owd,(uint32_t)(v1-v0),(uint32_t)(d1-d0),rms,(uint8_t)vox_jb_depth(),pkt->rssi);
}

static void rx_task(void *arg)
{
    (void)arg;
    static vox_rx_pkt_t pkt;

    for (;;) {
        if (!vox_link_recv(&pkt, 200)) {
            continue;
        }
        if (pkt.len < VOX_HDR_LEN) {
            vox_metrics_rx_reject(VOX_REJECT_MALFORMED);
            continue;
        }

        const vox_hdr_t *h = (const vox_hdr_t *)pkt.buf;
        if (h->ver != VOX_PROTO_VERSION) {
            vox_metrics_rx_reject(VOX_REJECT_MALFORMED);
            continue;
        }
        /*
         * Address filter, with a deliberate exemption for session
         * establishment.
         *
         * A node learns its peer's id FROM the handshake, so before a session
         * exists the initiator can only address SESS_INIT to whatever id the
         * operator typed into `peer add`. Enforcing the filter on those frames
         * would mean a mistyped id produces no error, no log line and no
         * session, which is the worst possible failure mode for someone
         * setting up a testbed. Handshake frames are authenticated by the
         * bootstrap HMAC regardless, so accepting a misaddressed one costs
         * nothing: an attacker still cannot produce a valid MAC, and a
         * legitimate peer gets a session instead of silence.
         */
        bool is_handshake = (h->type == VOX_T_SESS_INIT || h->type == VOX_T_SESS_RESP);
        if (!is_handshake &&
            h->dst_id != VOX_NODE_ID && h->dst_id != VOX_BROADCAST_ID) {
            continue;                       /* not addressed to us */
        }

        const uint8_t *body = pkt.buf + VOX_HDR_LEN;
        size_t body_len     = pkt.len - VOX_HDR_LEN;

        switch (h->type) {
        case VOX_T_AUDIO:
        case VOX_T_MEDIA_END:
            rx_audio(&pkt,h,body,body_len);
            break;
        case VOX_T_SYNC_REQ:
        case VOX_T_SYNC_RESP:
            vox_security_lock();
            vox_timesync_on_frame(pkt.src_mac, h, body, body_len, pkt.t_rx_us);
            vox_security_unlock();
            break;
        case VOX_T_SESS_INIT:
        case VOX_T_SESS_RESP:
        case VOX_T_SESS_CONFIRM:
        case VOX_T_SESS_READY:
        case VOX_T_EPOCH_REQ:
        case VOX_T_EPOCH_ACK:
            vox_security_lock();
            vox_session_on_control(pkt.src_mac, h, body, body_len);
            vox_security_unlock();
            break;
        case VOX_T_GRP_JOIN_REQ:
        case VOX_T_GRP_JOIN_GRANT:
        case VOX_T_GRP_LEAVE:
        case VOX_T_GRP_REVOKE:
        case VOX_T_GRP_REKEY:
        case VOX_T_GRP_REKEY_ACK:
        case VOX_T_GRP_COMMIT:
        case VOX_T_GRP_COMMIT_ACK:
        case VOX_T_GRP_COORD_CLAIM:
            vox_security_lock();
            vox_group_control_on_frame(pkt.src_mac, h, body, body_len);
            vox_security_unlock();
            break;
        default:
            vox_metrics_rx_reject(VOX_REJECT_MALFORMED);
            break;
        }
    }
}

/* =============================== playout ================================ */

static void playout_task(void *arg)
{
    (void)arg;
    vox_jb_frame_t f;

#if defined(CONFIG_VOX_SINK_NONE)
    TickType_t last = xTaskGetTickCount();
#endif

    for (;;) {
#if defined(CONFIG_VOX_SINK_NONE)
        /* No DMA to pace us, so run on the tick. */
        vTaskDelayUntil(&last, pdMS_TO_TICKS(VOX_FRAME_MS));
#endif
        if (vox_jb_pop(&f)) {
            vox_trace_rx_pulse();
            vox_audio_sink_write(f.pcm, f.nsamp, VOX_FRAME_MS * 4);
        } else {
            /*
             * Concealment is silence, not the previous frame. Repeating audio
             * would flatter the subjective result while leaving the loss
             * counters unchanged, which would make the two inconsistent.
             * Silence keeps what the listener hears aligned with what the
             * numbers say.
             */
            vox_audio_sink_write(s_silence, VOX_SAMPLES_PER_FRAME, VOX_FRAME_MS * 4);
        }
    }
}

/* ============================== housekeeping ============================ */

static void housekeep_task(void *arg)
{
    (void)arg;
    int64_t next_probe = 0;
    int64_t next_sample = 0;

    for (;;) {
        int64_t now = esp_timer_get_time();

        if (now >= next_probe) {
            for (int i = 0; i < VOX_MAX_PEERS; i++) {
                vox_security_lock();
                vox_peer_t *p = vox_peer_at(i);
                if (p != NULL && !p->phantom && p->state == VOX_SESS_ESTABLISHED) {
                    vox_timesync_probe(p->mac, p->peer_id);
                }
                vox_security_unlock();
            }
            next_probe = now + 500000;      /* 2 Hz */
        }

        if (now >= next_sample) {
            vox_metrics_sample_resources();
            next_sample = now + (CONFIG_VOX_METRICS_PERIOD_MS * 1000);
        }

        vox_security_lock();
        vox_session_tick();
        vox_group_control_tick();
        vox_security_unlock();
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

/* ========================= adversary simulation ========================= */
/*
 * Three injections, matching the concrete cases the threat model names.
 * They differ in which defence is expected to catch them, and that
 * difference is the result worth reporting:
 *
 *   replay  reuses the captured sequence number, so the replay window
 *           rejects it before any cryptography runs. Cheap rejection.
 *
 *   tamper  advances the sequence number so the frame is fresh, then flips a
 *           bit of ciphertext. The window lets it through; the AEAD tag
 *           catches it. Costs one failed decryption.
 *
 *   forge   fabricates ciphertext and tag under no key at all, again with a
 *           forward sequence number.
 *
 * Because the replay window is only advanced by vox_replay_commit(), which
 * runs only after the tag verifies, the forward sequence numbers used by
 * tamper and forge do NOT drag the receiver's window forward. Legitimate
 * frames keep arriving and being accepted throughout. That is the
 * counter-desynchronisation property, and this is the test that demonstrates
 * it: run 'attack tamper 500' during a live stream and the loss figure should
 * not move.
 */

static int inject(int count, bool advance_seq, bool corrupt, bool randomise,
                  uint32_t gap_ms)
{
    uint8_t captured[VOX_FRAME_MAX_LEN], mac[6]; size_t length; bool group;
    vox_security_lock();
    if(!s_last_valid) { vox_security_unlock(); return 0; }
    length=s_last_len; group=s_last_is_group;
    memcpy(captured,s_last_frame,length); memcpy(mac,s_last_mac,6);
    vox_security_unlock();
    static uint8_t buf[VOX_FRAME_MAX_LEN];
    int sent = 0;

    for (int i = 0; i < count; i++) {
        memcpy(buf, captured, length);
        vox_hdr_t *h = (vox_hdr_t *)buf;

        if (advance_seq) {
            /* Far enough ahead to clear the replay window comfortably. */
            h->seq += (uint32_t)(1000 + i);
        }
        if (randomise && length > VOX_HDR_LEN) {
            esp_fill_random(buf + VOX_HDR_LEN, length - VOX_HDR_LEN);
        } else if (corrupt && length > VOX_HDR_LEN) {
            buf[VOX_HDR_LEN + (i % (length - VOX_HDR_LEN))] ^= 0x01;
        }

        /*
         * A frame captured from the group broadcast path has no single
         * recipient to address -- it must go back out over the air the same
         * way the original did, so every current member is exposed to it
         * exactly as docs/DRAFT_CH4_GROUP_METHODOLOGY.md SS4.5.1 requires
         * ("tampering, forgery and replay... repeated against the group's
         * shared media key specifically"). A captured unicast frame keeps
         * going to the specific peer it was addressed to.
         */
        esp_err_t send_err = group
            ? vox_link_broadcast(buf, length, NULL)
            : vox_link_send(mac, buf, length, 50, NULL);
        if (send_err == ESP_OK) {
            sent++;
        }
        /*
         * The correctness attacks pace themselves so the receiver's counters
         * can be read cleanly. A flood deliberately does not: the question it
         * asks is what happens to legitimate audio while the receiver is
         * spending its budget rejecting frames, and pacing would answer a
         * different question.
         */
        if (gap_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(gap_ms));
        } else {
            taskYIELD();
        }
    }
    return sent;
}

void vox_attack_info(void)
{
    vox_security_lock();
    const vox_hdr_t *h=(const void *)s_last_frame;
    if(s_last_valid) printf("#CAPTURE,valid=1,group=%d,src=%u,epoch=%u,seq=%lu\n",
        s_last_is_group,h->src_id,h->epoch,(unsigned long)h->seq);
    else printf("#CAPTURE,valid=0\n");
    vox_security_unlock();
}
int vox_attack_replay(int count) { return inject(count, false, false, false, 2); }
int vox_attack_tamper(int count) { return inject(count, true,  true,  false, 2); }
int vox_attack_forge(int count)  { return inject(count, true,  false, true,  2); }

/*
 * Availability, not correctness.
 *
 * STRIDE's denial-of-service category is the one the other attacks do not
 * reach: replay, tamper and forge each prove that a malicious frame is
 * rejected, which says nothing about what rejecting thousands of them costs.
 * The review is explicit that an availability loss is a failure in its own
 * right rather than a by-product of cryptographic protection, so it needs its
 * own measurement.
 *
 * Forged frames carry a fresh sequence number, so they clear the replay window
 * cheaply and force a full AEAD verification each -- the expensive rejection
 * path, which is the one an attacker would choose. Run this during a talk
 * burst and read the receiver's loss, one-way delay and deadline behaviour:
 * the frames are still refused, and the question is what that refusal costs
 * the legitimate stream.
 */
int vox_attack_flood(int count)  { return inject(count, true,  false, true,  0); }

/* ================================= main ================================= */

static void add_phantom_peers(void)
{
#if CONFIG_VOX_PHANTOM_PEERS > 0
    /*
     * Locally administered, non-multicast addresses that no real device will
     * hold. They let the sender-side cost of N receivers be measured with
     * only two boards.
     */
    for (int i = 0; i < CONFIG_VOX_PHANTOM_PEERS; i++) {
        uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0xDE, (uint8_t)(0xA0 + i) };
        vox_peer_t *p = vox_peer_add(mac, (uint16_t)(1000 + i), true);
        if (p != NULL) {
            vox_session_handshake(p);       /* installs keys locally */
        }
    }
    ESP_LOGW(TAG, "%d phantom peers active: sender-side cost only, "
                  "their delivery and retry behaviour is not evidence",
             CONFIG_VOX_PHANTOM_PEERS);
#endif
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    memset(s_silence, 0, sizeof(s_silence));

    ESP_ERROR_CHECK(vox_security_init());
    printf("#BOOT,node=%u,protocol=%u,boot=%08lx,reset_reason=%d\n", VOX_NODE_ID,VOX_PROTO_VERSION,(unsigned long)esp_random(),esp_reset_reason());
    bool default_pmk = false;
    ESP_ERROR_CHECK(vox_keys_init(&default_pmk));
    ESP_ERROR_CHECK(vox_codec_init());
    ESP_ERROR_CHECK(vox_audio_src_init());
    ESP_ERROR_CHECK(vox_audio_sink_init());
    ESP_ERROR_CHECK(vox_link_init());
    ESP_ERROR_CHECK(vox_session_init());
    vox_group_init();
    ESP_ERROR_CHECK(vox_group_control_init());
    ESP_ERROR_CHECK(vox_timesync_init());
    ESP_ERROR_CHECK(vox_metrics_init());
    ESP_ERROR_CHECK(vox_ptt_init());
    vox_jb_reset();

    add_phantom_peers();

    const uint8_t *mac = vox_link_self_mac();
    ESP_LOGI(TAG, "=========================================================");
    ESP_LOGI(TAG, " node %u  mac " MACSTR, VOX_NODE_ID, MAC2STR(mac));
    ESP_LOGI(TAG, " codec %s  frame %d ms  %d B on air (+%d B link)",
             vox_codec()->name, VOX_FRAME_MS, VOX_ON_AIR_BYTES,
             VOX_LINK_OVERHEAD_BYTES);
    ESP_LOGI(TAG, " aead %s  tag %d B  replay window %d",
             vox_aead_name(), VOX_TAG_LEN, VOX_REPLAY_WINDOW);
    if (default_pmk) {
        ESP_LOGW(TAG, " PMK is the development default - set one with 'pmk set <hex>'");
    }
    ESP_LOGI(TAG, " tell the other board:  peer add " MACSTR " <id>", MAC2STR(mac));
    ESP_LOGI(TAG, "=========================================================");

#ifdef CONFIG_VOX_ROLE_LISTENER
    xTaskCreatePinnedToCore(playout_task, "vox_play", 8192, NULL, 6, NULL, 1);
#endif
    xTaskCreatePinnedToCore(rx_task, "vox_rx", 16384, NULL, 5, NULL, 1);
#ifdef CONFIG_VOX_ROLE_TALKER
    xTaskCreatePinnedToCore(tx_task, "vox_tx", 16384, NULL, 4, NULL, 0);
#endif
    xTaskCreatePinnedToCore(housekeep_task, "vox_hk", 3072, NULL, 3, NULL, 0);

    vox_console_start();
}
