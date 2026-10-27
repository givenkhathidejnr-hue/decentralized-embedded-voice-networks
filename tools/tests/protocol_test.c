/* Production protocol state machines, virtual time/radio/NVS, real host crypto.
 * State copying is ONLY valid for the test ABI's key-only GCM contexts. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
unsigned test_node=1;
#define TAG keys_tag
#include "../../firmware/main/sec/vox_keys.c"
#undef TAG
#define TAG crypto_tag
#include "../../firmware/main/sec/vox_crypto.c"
#undef TAG
#include "../../firmware/main/sec/vox_replay.c"
#include "../../firmware/main/sec/vox_group.c"
#define TAG session_tag
#include "../../firmware/main/sec/vox_session.c"
#undef TAG
#undef RETRY_US
#include "../../firmware/main/sec/vox_group_control.c"
#define TAG sync_tag
#define hdr_fill sync_hdr_fill
#include "../../firmware/main/net/vox_timesync.c"
#undef hdr_fill
#undef TAG
#define TAG jitter_tag
#include "../../firmware/main/audio/vox_jitterbuf.c"
#undef TAG
#define s_lock security_lock
#include "../../firmware/main/sec/vox_security.c"
#undef s_lock

#define NODES 6
#define OK(x) assert((x)==ESP_OK)
static int64_t clock_us=1000000;
int64_t esp_timer_get_time(void) { return clock_us; }
static uint64_t rng=123456789;
uint32_t esp_random(void) { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }
void esp_fill_random(void *p,size_t n) { uint8_t *b=p; while(n--) *b++=esp_random(); }
const uint8_t VOX_BROADCAST_MAC[6]={255,255,255,255,255,255};
static void mac_for(int id,uint8_t mac[6]) { memset(mac,0,6); mac[0]=2; mac[5]=id; }
esp_err_t vox_link_peer_add(const uint8_t m[6],const uint8_t *k) { (void)m;(void)k;return ESP_OK; }
esp_err_t vox_link_peer_del(const uint8_t m[6]) { (void)m;return ESP_OK; }
static struct { uint8_t b[2048]; size_t n; } nv[NODES+1][2];
esp_err_t nvs_open(const char *n,int mode,nvs_handle_t *h) { (void)n;(void)mode;*h=test_node;return ESP_OK; }
esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *p,size_t *n) {
    int i=!strcmp(k,"pairs_v2"); if(!nv[h][i].n) return ESP_ERR_NOT_FOUND;
    assert(*n>=nv[h][i].n); *n=nv[h][i].n; memcpy(p,nv[h][i].b,*n);return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *p,size_t n) {
    int i=!strcmp(k,"pairs_v2"); assert(n<=sizeof(nv[h][i].b)); memcpy(nv[h][i].b,p,n);nv[h][i].n=n;return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h) { (void)h;return ESP_OK; }
void nvs_close(nvs_handle_t h) { (void)h; }
static uint8_t nonce_history[30000][28]; static size_t nonce_count;
void test_nonce_used(const uint8_t key[16],const uint8_t nonce[12]) {
    uint8_t pair[28];memcpy(pair,key,16);memcpy(pair+16,nonce,12);
    for(size_t i=0;i<nonce_count;i++) if(!memcmp(pair,nonce_history[i],28)) {
        fprintf(stderr,"NONCE REUSE on node %u after %zu seals\n",test_node,nonce_count);abort();
    }
    assert(nonce_count<30000);memcpy(nonce_history[nonce_count++],pair,28);
}
struct node {
    __typeof__(s_grp) grp; __typeof__(s_peers) peers; __typeof__(s_pairs) pairs;
    __typeof__(s_slots) slots; __typeof__(s_txn) txn; __typeof__(s_request) request;
    uint8_t pmk[32],boot[32],invite[16]; int64_t invite_until; uint16_t expected;
};
static struct node nodes[NODES+1];
static void save(void) {
    struct node *n=&nodes[test_node];n->grp=s_grp;n->txn=s_txn;n->request=s_request;
    memcpy(n->slots,s_slots,sizeof(s_slots));memcpy(n->peers,s_peers,sizeof(s_peers));memcpy(n->pairs,s_pairs,sizeof(s_pairs));
    memcpy(n->pmk,s_pmk,32);memcpy(n->boot,s_boot_key,32);memcpy(n->invite,s_invite_nonce,16);
    n->invite_until=s_invite_until_us;n->expected=s_expected_coordinator;
}
static void select_node(unsigned id) {
    save();test_node=id;struct node *n=&nodes[id];s_grp=n->grp;s_txn=n->txn;s_request=n->request;
    memcpy(s_slots,n->slots,sizeof(s_slots));memcpy(s_peers,n->peers,sizeof(s_peers));memcpy(s_pairs,n->pairs,sizeof(s_pairs));
    memcpy(s_pmk,n->pmk,32);memcpy(s_boot_key,n->boot,32);memcpy(s_invite_nonce,n->invite,16);
    s_invite_until_us=n->invite_until;s_expected_coordinator=n->expected;
}
struct packet { unsigned src,dst; size_t len; uint8_t b[250]; };
static struct packet queue[20000];static size_t head,tail;
static int drop_type=-1,drop_src,drop_dst,drop_left;
esp_err_t vox_link_send(const uint8_t m[6],const uint8_t *p,size_t n,uint32_t timeout,int64_t *air) {
    (void)timeout;if(air)*air=10;assert(n<=250);
    const vox_hdr_t *h=(const void *)p;
    if(h->type==drop_type && (!drop_src || (int)test_node==drop_src) &&
       (!drop_dst || m[5]==drop_dst) && drop_left) { if(drop_left>0)drop_left--;return ESP_OK; }
    assert(tail<20000);queue[tail]=(struct packet){.src=test_node,.dst=m[5],.len=n};
    memcpy(queue[tail++].b,p,n);return ESP_OK;
}
static void deliver(struct packet p,unsigned dst) {
    select_node(dst);uint8_t mac[6];mac_for(p.src,mac);vox_hdr_t *h=(void *)p.b;
    if(h->dst_id!=VOX_BROADCAST_ID && h->dst_id!=dst)return;
    vox_security_lock();
    if(h->type>=VOX_T_GRP_JOIN_REQ) vox_group_control_on_frame(mac,h,p.b+VOX_HDR_LEN,p.len-VOX_HDR_LEN);
    else if(h->type==VOX_T_SYNC_REQ || h->type==VOX_T_SYNC_RESP) vox_timesync_on_frame(mac,h,p.b+VOX_HDR_LEN,p.len-VOX_HDR_LEN,clock_us);
    else vox_session_on_control(mac,h,p.b+VOX_HDR_LEN,p.len-VOX_HDR_LEN);
    vox_security_unlock();
}
static void drain(void) {
    while(head<tail) {struct packet p=queue[head++];
        if(p.dst==255) {for(unsigned i=1;i<=NODES;i++)if(i!=p.src)deliver(p,i);}
        else deliver(p,p.dst);
    }head=tail=0;
}
static void drive(unsigned ms) {
    for(unsigned t=0;t<ms;t+=50) {clock_us+=50000;
        for(unsigned i=1;i<=NODES;i++){select_node(i);vox_session_tick();vox_group_control_tick();}
        drain();
    }
}
static void drop(int type,int src,int dst,int count) {drop_type=type;drop_src=src;drop_dst=dst;drop_left=count;}
static void establish(unsigned a,unsigned b) {
    select_node(a);OK(vox_session_handshake(vox_peer_by_id(b)));drive(1500);
    select_node(a);assert(vox_peer_by_id(b)->state==VOX_SESS_ESTABLISHED);
    select_node(b);assert(vox_peer_by_id(a)->state==VOX_SESS_ESTABLISHED);
    assert(vox_peer_by_id(a)->isolated);
}
static void group_check(unsigned first,unsigned last,unsigned count,unsigned coord) {
    uint8_t secret[32]={0};uint32_t gen=0;
    for(unsigned id=first;id<=last;id++){select_node(id);
        assert(vox_group_ready());assert(vox_group_member_count()==(int)count);
        assert(vox_group_coordinator()==coord);
        if(!gen){gen=vox_group_generation();memcpy(secret,s_grp.snapshot.secret,32);}
        assert(gen==vox_group_generation());assert(!memcmp(secret,s_grp.snapshot.secret,32));
        for(unsigned j=first;j<=last;j++)assert(vox_group_is_member(j));
    }
}
static void group_crypto(void) {
    select_node(1);uint32_t seq;assert(vox_group_reserve_seq(&seq));
    vox_hdr_t h={.ver=VOX_PROTO_VERSION,.type=VOX_T_AUDIO,.epoch=vox_group_epoch(),.src_id=1,.dst_id=VOX_BROADCAST_ID,.seq=seq};
    uint8_t nonce[12],ct[4],tag[16],pt[4],msg[4]={1,2,3,4};
    vox_aead_nonce(vox_group_aead(),1,h.epoch,seq,nonce);
    OK(vox_aead_seal(vox_group_aead(),nonce,(void *)&h,sizeof(h),msg,4,ct,tag,16));
    vox_grp_grant_body_t snapshot;vox_group_snapshot(&snapshot);uint32_t next=s_grp.tx_seq;
    OK(vox_group_apply(&snapshot));assert(s_grp.tx_seq==next);
    snapshot.secret[0]^=1;assert(vox_group_apply(&snapshot)!=ESP_OK);
    for(unsigned i=2;i<=NODES;i++){select_node(i);vox_replay_t *w=vox_group_replay_for(1);assert(vox_replay_is_fresh(w,seq));
        tag[0]^=1;assert(vox_aead_open(vox_group_aead(),nonce,(void *)&h,sizeof(h),ct,4,tag,16,pt)!=ESP_OK);
        assert(vox_replay_is_fresh(w,seq));tag[0]^=1;
        OK(vox_aead_open(vox_group_aead(),nonce,(void *)&h,sizeof(h),ct,4,tag,16,pt));assert(!memcmp(pt,msg,4));
        vox_replay_commit(w,seq);assert(!vox_replay_is_fresh(w,seq));
        vox_group_snapshot(&snapshot);OK(vox_group_apply(&snapshot));assert(!vox_replay_is_fresh(vox_group_replay_for(1),seq));
    }
}
struct sealed_media { vox_hdr_t h; uint8_t nonce[12],ct[4],tag[16]; };
static struct sealed_media capture_group(void) {
    struct sealed_media p={0};uint32_t seq;assert(vox_group_reserve_seq(&seq));
    p.h=(vox_hdr_t){.ver=2,.type=VOX_T_AUDIO,.src_id=VOX_NODE_ID,.dst_id=VOX_BROADCAST_ID,.epoch=vox_group_epoch(),.seq=seq};
    uint8_t msg[4]={7,8,9,10};vox_aead_nonce(vox_group_aead(),VOX_NODE_ID,p.h.epoch,seq,p.nonce);
    OK(vox_aead_seal(vox_group_aead(),p.nonce,(void *)&p.h,sizeof(p.h),msg,4,p.ct,p.tag,16));return p;
}
static void cannot_open(struct sealed_media p,vox_aead_t *a) {
    uint8_t pt[4];assert(vox_aead_open(a,p.nonce,(void *)&p.h,sizeof(p.h),p.ct,4,p.tag,16,pt)!=ESP_OK);
}
static void authority_test(void) {
    select_node(6);vox_grp_grant_body_t b;vox_group_snapshot(&b);uint32_t gen=b.generation;
    b.generation++;b.coordinator_id=6;esp_fill_random(b.secret,32);
    OK(send_body(vox_peer_by_id(2),VOX_T_GRP_REKEY,&b,sizeof(b)));drain();
    select_node(2);assert(vox_group_generation()==gen && vox_group_coordinator()==1);
    select_node(1);b.coordinator_id=1;OK(send_body(vox_peer_by_id(2),VOX_T_GRP_JOIN_GRANT,&b,sizeof(b)));drain();
    select_node(2);assert(vox_group_generation()==gen);
    select_node(6);vox_grp_ctrl_body_t ctl;current_ctrl(&ctl);ctl.member_id=3;
    OK(send_body(vox_peer_by_id(1),VOX_T_GRP_LEAVE,&ctl,sizeof(ctl)));drain();
    select_node(1);assert(vox_group_is_member(3) && vox_group_generation()==gen);
    puts("PASS non-coordinator rekey, unsolicited grant and forged body identity rejected");
}
static void jitter_test(void) {
    vox_jb_reset();vox_jb_frame_t f={.sender_id=1,.stream_id=10,.seq=2},out;
    assert(vox_jb_push(&f));assert(vox_jb_pop(&out));
    for(int i=0;i<100;i++)assert(!vox_jb_pop(&out));
    f.seq=105;assert(vox_jb_push(&f));vox_jb_end(1,10,110);
    vox_jb_stats_t st;vox_jb_stats(&st);assert(st.media_expected==110 && st.media_received==2);
    assert(st.silence_ticks==100);assert(vox_jb_loss_complete());
    assert(!vox_jb_push(&f));
    f.stream_id=11;f.seq=0;assert(vox_jb_push(&f));vox_jb_end(1,11,1);
    vox_jb_end(1,10,110);vox_jb_stats(&st);assert(st.media_expected==111);
    puts("PASS media indices, leading/trailing losses, sustained outages, stale END");
}
static void *reserve_worker(void *arg) {
    (void)arg;for(int i=0;i<2000;i++) {vox_security_lock();uint32_t seq;
        assert(vox_group_reserve_seq(&seq));assert(seq==s_grp.tx_seq-1);vox_security_unlock();}return NULL;
}
static void concurrent_reserve(void) {
    select_node(2);uint32_t start=s_grp.tx_seq;pthread_t threads[4];
    for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,reserve_worker,NULL));
    for(int i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
    assert(s_grp.tx_seq==start+8000);s_grp.tx_seq=UINT32_MAX;uint32_t seq;
    assert(!vox_group_reserve_seq(&seq));
    puts("PASS concurrent counter reservation and exhaustion refusal");
}
int main(void) {
    OK(vox_security_init());
    for(unsigned i=1;i<=NODES;i++){select_node(i);OK(vox_keys_init(NULL));OK(vox_session_init());vox_group_init();OK(vox_group_control_init());
        for(unsigned j=1;j<=NODES;j++)if(j!=i){uint8_t k[32],mac[6];
            for(int x=0;x<32;x++)k[x]=(uint8_t)(x*7+(i<j?i:j)*31+(i<j?j:i)*13);
            OK(vox_keys_store_peer(j,k));mac_for(j,mac);assert(vox_peer_add(mac,j,false));}
    }
    select_node(5);uint8_t credential[32],wrong[32]={99};memcpy(credential,peer_key(6),32);
    OK(vox_keys_store_peer(6,wrong));OK(vox_session_handshake(vox_peer_by_id(6)));drive(6000);
    select_node(5);assert(vox_peer_by_id(6)->state!=VOX_SESS_ESTABLISHED);OK(vox_keys_store_peer(6,credential));
    puts("PASS wrong independent credential cannot establish a session");
    for(unsigned i=1;i<=NODES;i++)for(unsigned j=i+1;j<=NODES;j++)establish(i,j);
    puts("PASS six-node isolated full mesh");
    for(int round=0;round<2;round++)for(unsigned j=2;j<=6;j++){
        select_node(1);clock_us+=100;OK(vox_timesync_probe(vox_peer_by_id(j)->mac,j));drain();
    }
    select_node(1);for(unsigned j=2;j<=6;j++)assert(vox_timesync_valid(j));
    uint8_t ni[16]={1},nr[16]={2},honest[32],attacker[32];
    OK(vox_keys_derive_session(ni,nr,1,3,honest));select_node(2);
    OK(vox_keys_derive_session(ni,nr,1,3,attacker));assert(memcmp(honest,attacker,32));
    puts("PASS five simultaneous clock peers and pairwise key isolation from another member");
    const int loss_types[]={VOX_T_SESS_RESP,VOX_T_SESS_CONFIRM,VOX_T_SESS_READY};
    for(unsigned i=0;i<3;i++){drop(loss_types[i],0,0,2);establish(1,2);}drop(-1,0,0,0);
    select_node(1);OK(vox_session_handshake(vox_peer_by_id(2)));struct packet old_init=queue[0];drain();
    select_node(2);uint8_t live[32];memcpy(live,vox_peer_by_id(1)->secret,32);uint32_t tx=vox_peer_by_id(1)->tx_seq;
    deliver(old_init,2);drain();select_node(2);assert(!memcmp(live,vox_peer_by_id(1)->secret,32));assert(vox_peer_by_id(1)->tx_seq>=tx);
    drop(VOX_T_EPOCH_ACK,2,1,3);select_node(1);OK(vox_session_rekey(vox_peer_by_id(2)));drive(1800);
    select_node(1);assert(!vox_peer_by_id(2)->rekey_pending && vox_peer_by_id(2)->epoch==1);
    drop(VOX_T_EPOCH_ACK,2,1,-1);OK(vox_session_rekey(vox_peer_by_id(2)));drive(6500);drop(-1,0,0,0);
    select_node(1);assert(vox_peer_by_id(2)->state==VOX_SESS_ESTABLISHED && vox_peer_by_id(2)->epoch==0);
    puts("PASS handshake retransmission, transcript replay, lost rekey ACK and fresh-session recovery");
    select_node(1);OK(vox_group_create());for(unsigned j=2;j<=NODES;j++)OK(vox_group_control_allow(j));
    for(unsigned j=2;j<=NODES;j++){select_node(1);uint8_t old[32];memcpy(old,s_grp.snapshot.secret,32);struct sealed_media before=capture_group();
        select_node(j);OK(vox_group_control_join(1));drive(2500);group_check(1,j,j,1);
        assert(memcmp(old,s_grp.snapshot.secret,32));select_node(j);cannot_open(before,vox_group_aead());}
    puts("PASS admissions through six members, complete rosters and fresh join keys");group_crypto();authority_test();
    const int group_loss[]={VOX_T_GRP_REKEY_ACK,VOX_T_GRP_COMMIT,VOX_T_GRP_COMMIT_ACK};
    for(unsigned i=0;i<3;i++){drop(group_loss[i],0,0,3);select_node(1);OK(vox_group_control_rekey());drive(3000);group_check(1,6,6,1);}
    puts("PASS prepare/commit/ACK loss recovery, idempotent installs, authentication/replay");
    drop(VOX_T_GRP_REKEY_ACK,6,1,-1);select_node(1);OK(vox_group_control_rekey());drive(1000);
    select_node(2);OK(reply(vox_peer_by_id(1),VOX_T_GRP_REKEY_ACK));OK(reply(vox_peer_by_id(1),VOX_T_GRP_REKEY_ACK));drain();
    select_node(1);assert(s_txn.phase==1);drive(8000);
    select_node(1);assert(!vox_group_ready());assert(!strcmp(vox_group_control_status(),"failed"));
    drop(-1,0,0,0);OK(vox_group_control_rekey());drive(2500);group_check(1,6,6,1);
    puts("PASS missing member ACK cannot be replaced by others; timeout pauses and explicit retry recovers");
    select_node(6);vox_aead_t retained=*vox_group_aead();
    select_node(1);OK(vox_group_control_revoke(6));drive(2500);group_check(1,5,5,1);select_node(1);cannot_open(capture_group(),&retained);
    select_node(6);OK(vox_group_control_join(1));drive(17000);select_node(1);assert(!vox_group_is_allowed(6) && !vox_group_is_member(6));
    puts("PASS revoked member cannot rejoin");
    select_node(5);vox_group_leave();OK(vox_group_control_init());OK(vox_session_init());OK(vox_keys_init(NULL));
    uint8_t mac[6];mac_for(1,mac);assert(vox_peer_add(mac,1,false));establish(5,1);
    select_node(5);OK(vox_group_control_join(1));drive(2500);group_check(1,5,5,1);
    /* Restore the rebooted node's other sessions for a coordinator transfer. */
    for(unsigned j=2;j<=4;j++){select_node(5);mac_for(j,mac);assert(vox_peer_add(mac,j,false));establish(5,j);}
    for(unsigned j=2;j<=5;j++){select_node(j);OK(vox_group_control_expect(2));}
    select_node(2);OK(vox_group_control_claim_coordinator());drive(2500);group_check(2,5,4,2);
    puts("PASS reboot recovery and explicitly authorized coordinator transfer");
    jitter_test();concurrent_reserve();printf("PASS %zu real AEAD seals with globally unique (key, nonce) pairs\n",nonce_count);
}
