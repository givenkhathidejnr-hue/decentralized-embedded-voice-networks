/* Protocol v2: incompatible with archived v1 experimental firmware.
 * Header is AEAD associated data. Nonces use key salt, sender, epoch and
 * packet sequence. Media ordering is independent of that security counter.
 * All multi-byte fields use little endian (ESP32); packed wire sizes below.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "vox_config.h"
#define VOX_PROTO_VERSION 2u
#define VOX_F_TALK_START (1u << 0)
#define VOX_F_TALK_END (1u << 1)
#define VOX_F_UNPROTECTED (1u << 7)
enum vox_frame_type {
    VOX_T_AUDIO=0x01, VOX_T_MEDIA_END=0x02,
    VOX_T_SESS_INIT=0x10, VOX_T_SESS_RESP=0x11,
    VOX_T_EPOCH_REQ=0x12, VOX_T_EPOCH_ACK=0x13,
    VOX_T_SESS_CONFIRM=0x14, VOX_T_SESS_READY=0x15,
    VOX_T_SYNC_REQ=0x20, VOX_T_SYNC_RESP=0x21, VOX_T_CTRL=0x30,
    VOX_T_GRP_JOIN_REQ=0x40, VOX_T_GRP_JOIN_GRANT=0x41,
    VOX_T_GRP_LEAVE=0x42, VOX_T_GRP_REVOKE=0x43,
    VOX_T_GRP_REKEY=0x44, VOX_T_GRP_REKEY_ACK=0x45,
    VOX_T_GRP_COORD_CLAIM=0x46, VOX_T_GRP_COMMIT=0x47,
    VOX_T_GRP_COMMIT_ACK=0x48
};
typedef struct __attribute__((packed)) {
    uint8_t ver, type, epoch, flags;
    uint16_t src_id, dst_id;
    uint32_t seq;
} vox_hdr_t;
_Static_assert(sizeof(vox_hdr_t)==VOX_HDR_LEN, "wire header");
typedef struct __attribute__((packed)) {
    uint32_t t_tx_us;       /* capture-start timestamp, common to all peers */
    uint16_t stream_id;
    uint8_t codec, reserved;
    uint32_t media_seq;     /* source-frame counter, unaffected by rekey/control */
} vox_audio_sub_t;
_Static_assert(sizeof(vox_audio_sub_t)==VOX_AUDIO_SUBHDR_LEN, "audio header");
typedef struct __attribute__((packed)) {
    uint8_t nonce[16];      /* initiator nonce, also echoed by RESP/CONFIRM */
    uint8_t responder[16];
    uint16_t node_id;
    uint8_t proto, reserved;
} vox_sess_body_t;
typedef struct __attribute__((packed)) {
    uint32_t t1_us, t2_us, t3_us;
} vox_sync_body_t;
#define VOX_GROUP_ID_LEN 16
#define VOX_JOIN_TOKEN_LEN 16
/* A complete versioned roster and admission policy accompanies every key.
 * A join token binds a grant to a fresh request, including after reboot. */
typedef struct __attribute__((packed)) {
    uint8_t secret[32];
    uint8_t group_id[VOX_GROUP_ID_LEN];
    uint32_t generation;
    uint16_t coordinator_id;
    uint8_t member_count, allowed_count;
    uint16_t members[VOX_MAX_GROUP_MEMBERS];
    uint16_t allowed[VOX_MAX_GROUP_MEMBERS];
    uint8_t join_token[VOX_JOIN_TOKEN_LEN];
} vox_grp_grant_body_t;
typedef struct __attribute__((packed)) {
    uint8_t group_id[VOX_GROUP_ID_LEN];
    uint32_t generation;
    uint16_t member_id;
    uint8_t reserved[2];
    uint8_t join_token[VOX_JOIN_TOKEN_LEN];
} vox_grp_ctrl_body_t;
_Static_assert(sizeof(vox_grp_grant_body_t)+VOX_HDR_LEN+16 <= ESP_NOW_MAX_DATA_LEN,
               "group snapshot must fit one packet");
#define VOX_FRAME_MAX_LEN ESP_NOW_MAX_DATA_LEN
