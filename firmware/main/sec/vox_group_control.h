#pragma once
#include "vox_frame.h"
#include "esp_err.h"
/* Task entry points are called under vox_security_lock. tick is nonblocking
 * apart from one bounded radio send per call; all retries have deadlines. */
esp_err_t vox_group_control_init(void);
esp_err_t vox_group_control_join(uint16_t coordinator);
esp_err_t vox_group_control_leave(void);
esp_err_t vox_group_control_revoke(uint16_t member);
esp_err_t vox_group_control_allow(uint16_t member);
esp_err_t vox_group_control_rekey(void);
esp_err_t vox_group_control_expect(uint16_t candidate);
esp_err_t vox_group_control_claim_coordinator(void);
bool vox_group_control_busy(void);
const char *vox_group_control_status(void);
void vox_group_control_tick(void);
void vox_group_control_on_frame(const uint8_t mac[6], const vox_hdr_t *h,
                               const uint8_t *body, size_t length);
