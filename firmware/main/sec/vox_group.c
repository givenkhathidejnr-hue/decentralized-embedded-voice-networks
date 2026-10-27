#include <string.h>
#include "sec/vox_group.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"

static struct {
    bool active, ready;
    vox_grp_grant_body_t snapshot;
    vox_aead_t aead;
    uint32_t tx_seq;
    vox_group_member_t members[VOX_MAX_GROUP_MEMBERS];
} s_grp;

void vox_group_init(void) { memset(&s_grp,0,sizeof(s_grp)); }
void vox_group_leave(void)
{
    vox_aead_clear(&s_grp.aead);
    mbedtls_platform_zeroize(&s_grp,sizeof(s_grp));
}
static bool contains(const uint16_t *ids, int n, uint16_t id)
{
    for (int i=0;i<n;i++) if (ids[i]==id) return true;
    return false;
}
static bool valid_ids(const uint16_t *ids, int n)
{
    if (n<1 || n>VOX_MAX_GROUP_MEMBERS) return false;
    for (int i=0;i<n;i++) {
        if (!ids[i] || ids[i]==VOX_BROADCAST_ID) return false;
        for (int j=0;j<i;j++) if(ids[i]==ids[j]) return false;
    }
    return true;
}
esp_err_t vox_group_apply(const vox_grp_grant_body_t *b)
{
    /* Copy packed arrays before dereferencing them as uint16_t arrays. */
    uint16_t members[VOX_MAX_GROUP_MEMBERS], allowed[VOX_MAX_GROUP_MEMBERS];
    memcpy(members,b->members,sizeof(members)); memcpy(allowed,b->allowed,sizeof(allowed));
    if (!b->generation || !valid_ids(members,b->member_count) ||
        !valid_ids(allowed,b->allowed_count) ||
        !contains(members,b->member_count,VOX_NODE_ID) ||
        !contains(members,b->member_count,b->coordinator_id)) return ESP_ERR_INVALID_ARG;
    for (int i=0;i<b->member_count;i++)
        if (!contains(allowed,b->allowed_count,members[i])) return ESP_ERR_INVALID_ARG;
    vox_grp_grant_body_t clean=*b;
    memset(clean.join_token,0,sizeof(clean.join_token));
    if (s_grp.active) {
        if (memcmp(clean.group_id,s_grp.snapshot.group_id,VOX_GROUP_ID_LEN))
            return ESP_ERR_INVALID_STATE;
        if (clean.generation==s_grp.snapshot.generation)
            return memcmp(&clean,&s_grp.snapshot,sizeof(clean))==0 ? ESP_OK : ESP_ERR_INVALID_STATE;
        if (clean.generation<s_grp.snapshot.generation ||
            !memcmp(clean.secret,s_grp.snapshot.secret,VOX_SESSION_LEN)) return ESP_ERR_INVALID_STATE;
    }
    /* A derivation failure must not leave a ready association with a cleared
     * context. Fail closed; a fresh authenticated transaction can recover. */
    s_grp.ready=false;
    esp_err_t err=vox_keys_derive_group(clean.secret,(uint8_t)clean.generation,&s_grp.aead);
    if (err!=ESP_OK) return err;
    s_grp.snapshot=clean;
    s_grp.tx_seq=0;
    memset(s_grp.members,0,sizeof(s_grp.members));
    for (int i=0;i<clean.member_count;i++) {
        s_grp.members[i].in_use=true;
        s_grp.members[i].member_id=members[i];
        vox_replay_reset(&s_grp.members[i].replay);
    }
    s_grp.active=true;
    return ESP_OK;
}
esp_err_t vox_group_create(void)
{
    if(s_grp.active) return ESP_ERR_INVALID_STATE;
    vox_grp_grant_body_t b={0};
    esp_fill_random(b.secret,sizeof(b.secret)); esp_fill_random(b.group_id,sizeof(b.group_id));
    b.generation=1; b.coordinator_id=VOX_NODE_ID;
    b.member_count=b.allowed_count=1; b.members[0]=b.allowed[0]=VOX_NODE_ID;
    esp_err_t err=vox_group_apply(&b);
    mbedtls_platform_zeroize(&b,sizeof(b));
    if(err==ESP_OK) s_grp.ready=true;
    return err;
}
bool vox_group_active(void) { return s_grp.active; }
bool vox_group_ready(void) { return s_grp.active && s_grp.ready; }
void vox_group_set_ready(bool ready) { s_grp.ready=ready && s_grp.active; }
uint8_t vox_group_epoch(void) { return (uint8_t)s_grp.snapshot.generation; }
uint32_t vox_group_generation(void) { return s_grp.snapshot.generation; }
const uint8_t *vox_group_id(void) { return s_grp.snapshot.group_id; }
uint16_t vox_group_coordinator(void) { return s_grp.snapshot.coordinator_id; }
bool vox_group_is_coordinator(void) { return s_grp.active && vox_group_coordinator()==VOX_NODE_ID; }
vox_group_member_t *vox_group_member_by_id(uint16_t id)
{
    for(int i=0;i<VOX_MAX_GROUP_MEMBERS;i++)
        if(s_grp.members[i].in_use && s_grp.members[i].member_id==id) return &s_grp.members[i];
    return NULL;
}
bool vox_group_is_member(uint16_t id) { return vox_group_member_by_id(id)!=NULL; }
bool vox_group_is_allowed(uint16_t id)
{
    for(int i=0;i<s_grp.snapshot.allowed_count;i++) if(s_grp.snapshot.allowed[i]==id) return true;
    return false;
}
int vox_group_member_count(void) { return s_grp.active ? s_grp.snapshot.member_count : 0; }
vox_group_member_t *vox_group_member_at(int i)
{
    return i>=0 && i<VOX_MAX_GROUP_MEMBERS && s_grp.members[i].in_use ? &s_grp.members[i] : NULL;
}
vox_replay_t *vox_group_replay_for(uint16_t id)
{
    vox_group_member_t *m=vox_group_member_by_id(id); return m ? &m->replay : NULL;
}
vox_aead_t *vox_group_aead(void) { return s_grp.active ? &s_grp.aead : NULL; }
bool vox_group_reserve_seq(uint32_t *seq)
{
    if(!vox_group_ready() || s_grp.tx_seq==UINT32_MAX) return false;
    *seq=s_grp.tx_seq++; return true;
}
void vox_group_snapshot(vox_grp_grant_body_t *b) { *b=s_grp.snapshot; }
size_t vox_group_state_bytes(void) { return sizeof(s_grp); }
size_t vox_group_active_state_bytes(void)
{
    return s_grp.active ? sizeof(s_grp.snapshot)+sizeof(s_grp.aead)+
        s_grp.snapshot.member_count*sizeof(vox_group_member_t) : 0;
}
