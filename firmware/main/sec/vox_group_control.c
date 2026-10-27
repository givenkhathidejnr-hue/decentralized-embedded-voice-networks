#include <string.h>
#include <stdio.h>
#include "sec/vox_group_control.h"
#include "sec/vox_group.h"
#include "sec/vox_session.h"
#include "net/vox_link.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"

#define RETRY_US 250000
#define DEADLINE_US 8000000
#define BODY_MAX sizeof(vox_grp_grant_body_t)

static struct {
    int phase;                  /* 0 idle, 1 prepare, 2 commit */
    vox_grp_grant_body_t snapshot;
    uint16_t joining;
    uint8_t token[VOX_JOIN_TOKEN_LEN];
    uint8_t acked;               /* one bit per snapshot member, not message */
    int64_t start, deadline, next_send;
    int cursor;
    const char *reason;
    const char *status;
} s_txn;
static struct {
    bool pending;
    uint8_t type;
    uint16_t coordinator;
    vox_grp_ctrl_body_t body;
    int64_t start, deadline, next_send;
} s_request;
static uint16_t s_expected_coordinator;

esp_err_t vox_group_control_init(void)
{
    memset(&s_txn,0,sizeof(s_txn)); memset(&s_request,0,sizeof(s_request));
    s_txn.status="idle"; s_expected_coordinator=0; return ESP_OK;
}
bool vox_group_control_busy(void) { return s_txn.phase!=0 || s_request.pending; }
const char *vox_group_control_status(void) { return s_txn.status; }
static bool secure_peer(vox_peer_t *p)
{
    return p && p->state==VOX_SESS_ESTABLISHED && p->isolated && vox_keys_peer_isolated(p->peer_id);
}
static esp_err_t send_body(vox_peer_t *p,uint8_t type,const void *body,size_t n)
{
#ifndef CONFIG_VOX_CRYPTO_ENABLED
    return ESP_ERR_NOT_SUPPORTED; /* group security is never silently disabled */
#else
    if(!secure_peer(p) || n>BODY_MAX) return ESP_ERR_INVALID_STATE;
    uint8_t buf[VOX_HDR_LEN+BODY_MAX+VOX_TAG_LEN],nonce[VOX_AEAD_NONCE_LEN];
    vox_hdr_t *h=(void *)buf;
    uint32_t seq;
    if(!vox_session_reserve_seq(p,&seq)) return ESP_ERR_INVALID_STATE;
    *h=(vox_hdr_t){.ver=VOX_PROTO_VERSION,.type=type,.epoch=p->epoch,
        .src_id=VOX_NODE_ID,.dst_id=p->peer_id,.seq=seq};
    vox_aead_nonce(&p->tx,VOX_NODE_ID,h->epoch,h->seq,nonce);
    esp_err_t err=vox_aead_seal(&p->tx,nonce,buf,VOX_HDR_LEN,body,n,
        buf+VOX_HDR_LEN,buf+VOX_HDR_LEN+n,VOX_TAG_LEN);
    return err==ESP_OK ? vox_link_send(p->mac,buf,VOX_HDR_LEN+n+VOX_TAG_LEN,50,NULL) : err;
#endif
}
static void current_ctrl(vox_grp_ctrl_body_t *b)
{
    memset(b,0,sizeof(*b)); memcpy(b->group_id,vox_group_id(),VOX_GROUP_ID_LEN);
    b->generation=vox_group_generation(); b->member_id=VOX_NODE_ID;
}
static esp_err_t reply(vox_peer_t *p,uint8_t type)
{
    vox_grp_ctrl_body_t b; current_ctrl(&b); return send_body(p,type,&b,sizeof(b));
}
#ifdef CONFIG_VOX_CRYPTO_ENABLED
static bool matches(const vox_grp_ctrl_body_t *b)
{
    return vox_group_active() && b->generation==vox_group_generation() &&
        !memcmp(b->group_id,vox_group_id(),VOX_GROUP_ID_LEN);
}
#endif
static int index_of(const vox_grp_grant_body_t *b,uint16_t id)
{
    for(int i=0;i<b->member_count;i++) if(b->members[i]==id) return i;
    return -1;
}
static void remove_id(uint16_t *ids,uint8_t *n,uint16_t id)
{
    for(int i=0;i<*n;i++) if(ids[i]==id) {
        memmove(&ids[i],&ids[i+1],(*n-i-1)*sizeof(*ids)); ids[--(*n)]=0; return;
    }
}
/* Packed arrays must not be passed to unaligned uint16_t pointer helpers. */
static void remove_from(vox_grp_grant_body_t *b,uint16_t id,bool deny)
{
    uint16_t ids[VOX_MAX_GROUP_MEMBERS];
    memcpy(ids,b->members,sizeof(ids)); remove_id(ids,&b->member_count,id);
    memcpy(b->members,ids,sizeof(ids));
    if(deny) {
        memcpy(ids,b->allowed,sizeof(ids)); remove_id(ids,&b->allowed_count,id);
        memcpy(b->allowed,ids,sizeof(ids));
    }
}
static void finish(bool ok)
{
    int acked=0; for(int i=0;i<s_txn.snapshot.member_count;i++)
        if(s_txn.snapshot.members[i]!=VOX_NODE_ID && (s_txn.acked & (1u<<i))) acked++;
    printf("#GRPOP,op=%s,status=%s,generation=%lu,us=%lld,members=%u,acked=%d\n",
        s_txn.reason,ok?"complete":"failed",(unsigned long)s_txn.snapshot.generation,
        (long long)(esp_timer_get_time()-s_txn.start),s_txn.snapshot.member_count-1,acked);
    s_txn.status=ok?"complete":"failed"; s_txn.phase=0;
    vox_group_set_ready(ok);
    /* Keep only the last join token, not an extra stale secret. */
    mbedtls_platform_zeroize(s_txn.snapshot.secret,sizeof(s_txn.snapshot.secret));
}
static void advance(void)
{
    uint8_t all=(uint8_t)((1u<<s_txn.snapshot.member_count)-1);
    if(s_txn.acked!=all) return;
    if(s_txn.phase==1) {
        s_txn.phase=2; s_txn.acked=(uint8_t)(1u<<index_of(&s_txn.snapshot,VOX_NODE_ID));
        s_txn.cursor=0; s_txn.next_send=0;
        if(s_txn.snapshot.member_count==1) finish(true);
    } else if(s_txn.phase==2) finish(true);
}
static esp_err_t start_change(vox_grp_grant_body_t *b,const char *reason,
                              uint16_t joining,const uint8_t *token)
{
    if(s_txn.phase || b->generation==UINT32_MAX) return ESP_ERR_INVALID_STATE;
    for(int i=0;i<b->member_count;i++)
        if(b->members[i]!=VOX_NODE_ID && !secure_peer(vox_peer_by_id(b->members[i])))
            return ESP_ERR_INVALID_STATE;
    b->generation++; esp_fill_random(b->secret,sizeof(b->secret));
    memset(b->join_token,0,sizeof(b->join_token));
    esp_err_t err=vox_group_apply(b);
    if(err!=ESP_OK) return err;
    memset(&s_txn,0,sizeof(s_txn)); s_txn.snapshot=*b;
    s_txn.phase=1; s_txn.reason=reason; s_txn.status="pending";
    s_txn.joining=joining; if(token) memcpy(s_txn.token,token,VOX_JOIN_TOKEN_LEN);
    s_txn.start=esp_timer_get_time(); s_txn.deadline=s_txn.start+DEADLINE_US;
    s_txn.acked=(uint8_t)(1u<<index_of(b,VOX_NODE_ID));
    advance(); return ESP_OK; /* accepted; only #GRPOP complete proves completion */
}
static esp_err_t change_current(const char *reason)
{
    if(!vox_group_is_coordinator()) return ESP_ERR_INVALID_STATE;
    vox_grp_grant_body_t b; vox_group_snapshot(&b);
    esp_err_t err=start_change(&b,reason,0,NULL);
    mbedtls_platform_zeroize(&b,sizeof(b)); return err;
}
esp_err_t vox_group_control_rekey(void) { return change_current("rekey"); }
esp_err_t vox_group_control_allow(uint16_t id)
{
    if(!vox_group_is_coordinator() || !id || id==VOX_BROADCAST_ID ||
        (id!=VOX_NODE_ID && !vox_keys_peer_isolated(id))) return ESP_ERR_INVALID_STATE;
    if(vox_group_is_allowed(id)) return ESP_OK;
    vox_grp_grant_body_t b; vox_group_snapshot(&b);
    if(b.allowed_count>=VOX_MAX_GROUP_MEMBERS) { mbedtls_platform_zeroize(&b,sizeof(b)); return ESP_ERR_NO_MEM; }
    b.allowed[b.allowed_count++]=id;
    esp_err_t err=start_change(&b,"allow",0,NULL); mbedtls_platform_zeroize(&b,sizeof(b)); return err;
}
esp_err_t vox_group_control_revoke(uint16_t id)
{
    if(!vox_group_is_coordinator() || id==VOX_NODE_ID) return ESP_ERR_INVALID_STATE;
    if(!vox_group_is_allowed(id)) return ESP_ERR_NOT_FOUND;
    vox_grp_grant_body_t b; vox_group_snapshot(&b); remove_from(&b,id,true);
    esp_err_t err=start_change(&b,"revoke",0,NULL); mbedtls_platform_zeroize(&b,sizeof(b)); return err;
}
esp_err_t vox_group_control_join(uint16_t id)
{
    if(vox_group_control_busy() || !secure_peer(vox_peer_by_id(id))) return ESP_ERR_INVALID_STATE;
    memset(&s_request,0,sizeof(s_request)); s_request.pending=true;
    s_request.type=VOX_T_GRP_JOIN_REQ; s_request.coordinator=id;
    s_request.body.member_id=VOX_NODE_ID;
    esp_fill_random(s_request.body.join_token,VOX_JOIN_TOKEN_LEN);
    s_request.start=esp_timer_get_time(); s_request.deadline=s_request.start+DEADLINE_US*2;
    if(vox_group_active()) {
        if(id!=vox_group_coordinator()) { s_request.pending=false; return ESP_ERR_INVALID_STATE; }
        memcpy(s_request.body.group_id,vox_group_id(),VOX_GROUP_ID_LEN);
        s_request.body.generation=vox_group_generation();
    }
    return ESP_OK;
}
esp_err_t vox_group_control_leave(void)
{
    if(!vox_group_active() || vox_group_is_coordinator() || vox_group_control_busy()) return ESP_ERR_INVALID_STATE;
    memset(&s_request,0,sizeof(s_request)); s_request.pending=true;
    s_request.type=VOX_T_GRP_LEAVE; s_request.coordinator=vox_group_coordinator();
    current_ctrl(&s_request.body); s_request.start=esp_timer_get_time();
    s_request.deadline=s_request.start+DEADLINE_US;
    vox_group_leave(); return ESP_OK;
}
esp_err_t vox_group_control_expect(uint16_t id)
{
    if(!vox_group_active() || vox_group_control_busy() || !vox_group_is_member(id)) return ESP_ERR_INVALID_STATE;
    s_expected_coordinator=id; return ESP_OK;
}
esp_err_t vox_group_control_claim_coordinator(void)
{
    if(!vox_group_active() || s_expected_coordinator!=VOX_NODE_ID || vox_group_control_busy()) return ESP_ERR_INVALID_STATE;
    vox_grp_grant_body_t b; vox_group_snapshot(&b);
    if(b.coordinator_id!=VOX_NODE_ID) remove_from(&b,b.coordinator_id,false);
    b.coordinator_id=VOX_NODE_ID;
    esp_err_t err=start_change(&b,"coord_claim",0,NULL);
    mbedtls_platform_zeroize(&b,sizeof(b));
    if(err==ESP_OK) s_expected_coordinator=0;
    return err;
}
#ifdef CONFIG_VOX_CRYPTO_ENABLED
static void on_join(vox_peer_t *p,const vox_grp_ctrl_body_t *b)
{
    if(!vox_group_is_coordinator() || !vox_group_is_allowed(p->peer_id)) return;
    if(s_txn.joining==p->peer_id && !memcmp(s_txn.token,b->join_token,VOX_JOIN_TOKEN_LEN)) {
        if(!s_txn.phase && !strcmp(s_txn.status,"complete") &&
            s_txn.snapshot.generation==vox_group_generation()) {
            vox_grp_grant_body_t grant; vox_group_snapshot(&grant);
            memcpy(grant.join_token,b->join_token,VOX_JOIN_TOKEN_LEN);
            send_body(p,VOX_T_GRP_JOIN_GRANT,&grant,sizeof(grant));
            reply(p,VOX_T_GRP_COMMIT);
            mbedtls_platform_zeroize(&grant,sizeof(grant));
        }
        return; /* retries of the same request never generate another key */
    }
    if(s_txn.phase) return;
    vox_grp_grant_body_t next; vox_group_snapshot(&next);
    if(index_of(&next,p->peer_id)<0) {
        if(next.member_count>=VOX_MAX_GROUP_MEMBERS) { mbedtls_platform_zeroize(&next,sizeof(next)); return; }
        next.members[next.member_count++]=p->peer_id;
    }
    start_change(&next,"join",p->peer_id,b->join_token);
    mbedtls_platform_zeroize(&next,sizeof(next));
}
static void on_grant(vox_peer_t *p,uint8_t type,const vox_grp_grant_body_t *b)
{
    if(b->coordinator_id!=p->peer_id) return;
    bool initial=type==VOX_T_GRP_JOIN_GRANT && s_request.pending &&
        s_request.type==VOX_T_GRP_JOIN_REQ && s_request.coordinator==p->peer_id &&
        !memcmp(s_request.body.join_token,b->join_token,VOX_JOIN_TOKEN_LEN);
    bool current=vox_group_active() && (p->peer_id==vox_group_coordinator() ||
        (s_expected_coordinator && p->peer_id==s_expected_coordinator && vox_group_is_member(p->peer_id))) &&
        !memcmp(b->group_id,vox_group_id(),VOX_GROUP_ID_LEN);
    if(type==VOX_T_GRP_JOIN_GRANT ? !initial : !current) return;
    if(vox_group_apply(b)!=ESP_OK) return;
    s_expected_coordinator=0;
    reply(p,VOX_T_GRP_REKEY_ACK);
}
#endif
void vox_group_control_on_frame(const uint8_t mac[6],const vox_hdr_t *h,const uint8_t *body,size_t len)
{
#ifndef CONFIG_VOX_CRYPTO_ENABLED
    return;
#else
    vox_peer_t *p=vox_peer_by_mac(mac);
    if(!secure_peer(p) || h->src_id!=p->peer_id || h->dst_id!=VOX_NODE_ID ||
        len<VOX_TAG_LEN || len-VOX_TAG_LEN>BODY_MAX) return;
    size_t n=len-VOX_TAG_LEN;
    vox_replay_t *win=NULL; vox_aead_t *a=vox_session_rx_ctx(p,h->epoch,&win);
    if(!a || !vox_replay_is_fresh(win,h->seq)) return;
    uint8_t nonce[VOX_AEAD_NONCE_LEN],pt[BODY_MAX];
    vox_aead_nonce(a,h->src_id,h->epoch,h->seq,nonce);
    if(vox_aead_open(a,nonce,(const uint8_t *)h,VOX_HDR_LEN,body,n,body+n,VOX_TAG_LEN,pt)!=ESP_OK) return;
    vox_replay_commit(win,h->seq);
    if(h->type==VOX_T_GRP_JOIN_GRANT || h->type==VOX_T_GRP_REKEY) {
        if(n==sizeof(vox_grp_grant_body_t)) on_grant(p,h->type,(const void *)pt);
        mbedtls_platform_zeroize(pt,sizeof(pt)); return;
    }
    if(n!=sizeof(vox_grp_ctrl_body_t)) { mbedtls_platform_zeroize(pt,sizeof(pt)); return; }
    const vox_grp_ctrl_body_t *b=(const void *)pt;
    if(b->member_id!=p->peer_id) return;
    if(h->type==VOX_T_GRP_JOIN_REQ) { on_join(p,b); return; }
    if(h->type==VOX_T_GRP_LEAVE) {
        if(!vox_group_is_coordinator() || memcmp(b->group_id,vox_group_id(),VOX_GROUP_ID_LEN)) return;
        if(!vox_group_is_member(p->peer_id)) { reply(p,VOX_T_GRP_REVOKE); return; }
        if(s_txn.phase) return;
        vox_grp_grant_body_t next; vox_group_snapshot(&next); remove_from(&next,p->peer_id,false);
        if(start_change(&next,"leave",0,NULL)==ESP_OK) reply(p,VOX_T_GRP_REVOKE);
        mbedtls_platform_zeroize(&next,sizeof(next)); return;
    }
    if(h->type==VOX_T_GRP_REVOKE && s_request.pending && s_request.type==VOX_T_GRP_LEAVE &&
        p->peer_id==s_request.coordinator && !memcmp(b->group_id,s_request.body.group_id,VOX_GROUP_ID_LEN)) {
        s_request.pending=false; return;
    }
    if(!matches(b)) return;
    if(h->type==VOX_T_GRP_COMMIT && p->peer_id==vox_group_coordinator()) {
        vox_group_set_ready(true); reply(p,VOX_T_GRP_COMMIT_ACK);
        if(s_request.pending && s_request.type==VOX_T_GRP_JOIN_REQ && p->peer_id==s_request.coordinator) {
            printf("#GRPOP,op=join,status=complete,generation=%lu,us=%lld\n",
                (unsigned long)b->generation,(long long)(esp_timer_get_time()-s_request.start));
            s_request.pending=false;
        }
    } else if(vox_group_is_coordinator() && s_txn.phase &&
        ((h->type==VOX_T_GRP_REKEY_ACK && s_txn.phase==1) ||
         (h->type==VOX_T_GRP_COMMIT_ACK && s_txn.phase==2))) {
        int i=index_of(&s_txn.snapshot,p->peer_id);
        if(i>=0) { s_txn.acked|=(uint8_t)(1u<<i); advance(); }
    }
#endif
}
void vox_group_control_tick(void)
{
    int64_t now=esp_timer_get_time();
    if(s_request.pending) {
        if(now>s_request.deadline) {
            printf("#GRPOP,op=%s,status=failed,reason=timeout\n",s_request.type==VOX_T_GRP_JOIN_REQ?"join":"leave");
            s_request.pending=false;
        } else if(now>=s_request.next_send) {
            send_body(vox_peer_by_id(s_request.coordinator),s_request.type,&s_request.body,sizeof(s_request.body));
            s_request.next_send=now+RETRY_US;
        }
    }
    if(!s_txn.phase) return;
    if(now>s_txn.deadline) { finish(false); return; }
    if(now<s_txn.next_send) return;
    for(int j=0;j<s_txn.snapshot.member_count;j++) {
        int i=s_txn.cursor++ % s_txn.snapshot.member_count;
        if(s_txn.acked & (1u<<i)) continue;
        uint16_t id=s_txn.snapshot.members[i]; vox_peer_t *p=vox_peer_by_id(id);
        if(s_txn.phase==1) {
            vox_grp_grant_body_t grant=s_txn.snapshot;
            if(id==s_txn.joining) memcpy(grant.join_token,s_txn.token,VOX_JOIN_TOKEN_LEN);
            send_body(p,id==s_txn.joining?VOX_T_GRP_JOIN_GRANT:VOX_T_GRP_REKEY,&grant,sizeof(grant));
            mbedtls_platform_zeroize(&grant,sizeof(grant));
        } else reply(p,VOX_T_GRP_COMMIT);
        s_txn.next_send=now+RETRY_US/s_txn.snapshot.member_count;
        return;
    }
    advance();
}
