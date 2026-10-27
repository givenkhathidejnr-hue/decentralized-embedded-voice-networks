#pragma once
#include <stdbool.h>
#include "vox_frame.h"
#include "sec/vox_keys.h"
#include "sec/vox_replay.h"

/* All access (including returned pointers) requires vox_security_lock. */
typedef struct {
    bool in_use;
    uint16_t member_id;
    vox_replay_t replay;
} vox_group_member_t;
void vox_group_init(void);
esp_err_t vox_group_create(void);
void vox_group_leave(void);
bool vox_group_active(void);
bool vox_group_ready(void);
void vox_group_set_ready(bool ready);
uint8_t vox_group_epoch(void);
uint32_t vox_group_generation(void);
const uint8_t *vox_group_id(void);
uint16_t vox_group_coordinator(void);
bool vox_group_is_coordinator(void);
bool vox_group_is_member(uint16_t id);
bool vox_group_is_allowed(uint16_t id);
int vox_group_member_count(void);
vox_group_member_t *vox_group_member_at(int index);
vox_group_member_t *vox_group_member_by_id(uint16_t id);
vox_replay_t *vox_group_replay_for(uint16_t id);
vox_aead_t *vox_group_aead(void);
bool vox_group_reserve_seq(uint32_t *seq);
void vox_group_snapshot(vox_grp_grant_body_t *snapshot);
/* Validates complete snapshot; identical installs are idempotent. New
 * generations stay paused until the matching commit is authenticated. */
esp_err_t vox_group_apply(const vox_grp_grant_body_t *snapshot);
size_t vox_group_state_bytes(void);       /* actual static allocation */
size_t vox_group_active_state_bytes(void);
