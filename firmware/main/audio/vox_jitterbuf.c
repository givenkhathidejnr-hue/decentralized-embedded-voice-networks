#include <string.h>
#include "audio/vox_jitterbuf.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "sec/vox_replay.h"

static const char *TAG = "vox.jb";

#define JB_CAP          CONFIG_VOX_JITTER_MAX_FRAMES
#define JB_TARGET       CONFIG_VOX_JITTER_TARGET_FRAMES

_Static_assert(JB_TARGET < JB_CAP, "jitter target must be below capacity");

typedef struct {
    bool           valid;
    vox_jb_frame_t f;
} slot_t;

static slot_t            s_slot[JB_CAP];
static bool              s_playing;      /* false while filling */
static bool              s_primed;
static uint32_t          s_next_seq;     /* next sequence due for playout */
static uint16_t          s_stream;
static uint16_t          s_sender;
static bool              s_ended;
static uint32_t          s_expected;
static uint32_t          s_end_seq;
static vox_replay_t      s_media_seen;
static vox_jb_stats_t    s_stats;
static SemaphoreHandle_t s_lock;
/* Prevent delayed authenticated packets from reopening a retired burst.
 * The replay window bounds how far radio reordering can extend. */
static struct { uint16_t sender, stream; bool valid; } s_retired[VOX_MAX_PEERS][VOX_REPLAY_WINDOW];
static unsigned s_retired_cursor[VOX_MAX_PEERS];
static uint16_t s_retired_sender[VOX_MAX_PEERS];

static int sender_slot(uint16_t sender)
{
    for(int i=0;i<VOX_MAX_PEERS;i++) if(s_retired_sender[i]==sender) return i;
    for(int i=0;i<VOX_MAX_PEERS;i++) if(!s_retired_sender[i]) {
        s_retired_sender[i]=sender; return i;
    }
    return -1;
}
static bool retired(uint16_t sender,uint16_t stream)
{
    int i=sender_slot(sender); if(i<0) return true;
    for(int j=0;j<VOX_REPLAY_WINDOW;j++) if(s_retired[i][j].valid && s_retired[i][j].stream==stream) return true;
    return false;
}
static void retire_current(void)
{
    if(!s_primed) return;
    int i=sender_slot(s_sender); if(i<0) return;
    unsigned j=s_retired_cursor[i]++ % VOX_REPLAY_WINDOW;
    s_retired[i][j].sender=s_sender; s_retired[i][j].stream=s_stream; s_retired[i][j].valid=true;
}

static void lock_init_once(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
}

void vox_jb_reset(void)
{
    lock_init_once();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_slot, 0, sizeof(s_slot));
    s_playing  = false;
    s_primed   = false;
    s_next_seq = 0;
    s_stream   = 0;
    s_sender=0; s_ended=false; s_expected=0; s_end_seq=0; vox_replay_reset(&s_media_seen);
    memset(&s_stats, 0, sizeof(s_stats));
    memset(s_retired,0,sizeof(s_retired));
    memset(s_retired_sender,0,sizeof(s_retired_sender));
    memset(s_retired_cursor,0,sizeof(s_retired_cursor));
    xSemaphoreGive(s_lock);
}

static size_t depth_locked(void)
{
    size_t n = 0;
    for (int i = 0; i < JB_CAP; i++) {
        if (s_slot[i].valid) n++;
    }
    return n;
}

bool vox_jb_push(const vox_jb_frame_t *f)
{
    lock_init_once();
    xSemaphoreTake(s_lock, portMAX_DELAY);

    bool stored = false;

    if (!s_primed || f->stream_id!=s_stream || f->sender_id!=s_sender) {
        if(retired(f->sender_id,f->stream_id)) goto out;
        retire_current();
        if(s_primed && !s_ended) s_stats.incomplete_streams++;
        if(s_primed) s_stats.resyncs++;
        memset(s_slot,0,sizeof(s_slot));
        s_primed=true; s_playing=false; s_ended=false;
        s_stream=f->stream_id; s_sender=f->sender_id;
        s_next_seq=f->seq; s_expected=0; vox_replay_reset(&s_media_seen);
    }
    if(f->seq==UINT32_MAX || (s_ended && f->seq>=s_end_seq)) goto out;
    if(!vox_replay_is_fresh(&s_media_seen,f->seq)) { s_stats.duplicate++; goto out; }
    vox_replay_commit(&s_media_seen,f->seq);
    s_stats.media_received++;
    if(f->seq+1>s_expected) {
        s_stats.media_expected+=f->seq+1-s_expected; s_expected=f->seq+1;
    }
    if(f->seq>s_next_seq && f->seq-s_next_seq>=JB_CAP) {
        memset(s_slot,0,sizeof(s_slot)); s_next_seq=f->seq;
        s_playing=false; s_stats.resyncs++;
    }

    if (f->seq < s_next_seq) {
        s_stats.late++;                 /* its playout instant has passed */
        goto out;
    }

    if ((f->seq - s_next_seq) >= (uint32_t)JB_CAP) {
        s_stats.overflow++;
        goto out;
    }

    slot_t *sl = &s_slot[f->seq % JB_CAP];
    if (sl->valid && sl->f.seq == f->seq) {
        s_stats.duplicate++;
        goto out;
    }

    sl->valid = true;
    sl->f     = *f;
    s_stats.pushed++;
    stored = true;

    size_t d = depth_locked();
    if (d > s_stats.max_depth) {
        s_stats.max_depth = (uint32_t)d;
    }
    if (!s_playing && d >= (size_t)JB_TARGET) {
        s_playing = true;
        ESP_LOGD(TAG, "playout started, stream %u, seq %u", s_stream, (unsigned)s_next_seq);
    }

out:
    xSemaphoreGive(s_lock);
    return stored;
}

bool vox_jb_pop(vox_jb_frame_t *out)
{
    lock_init_once();
    xSemaphoreTake(s_lock, portMAX_DELAY);

    bool got = false;
    if(s_ended && s_next_seq>=s_end_seq) { s_playing=false; goto out; }
    if (!s_playing) {
        if(s_primed && !s_ended) s_stats.silence_ticks++;
        goto out;
    }

    slot_t *sl = &s_slot[s_next_seq % JB_CAP];
    if (sl->valid && sl->f.seq == s_next_seq) {
        *out = sl->f;
        sl->valid = false;
        s_next_seq++;
        s_stats.popped++;
        got = true;
    } else {
        /* Nothing for this instant: the frame is lost or still in flight.
         * Advance regardless, so the play cursor stays locked to the audio
         * clock and a single loss does not shift every later frame. */
        s_next_seq++;
        s_stats.concealed++;

        s_stats.silence_ticks++;
        /* Keep counting silence through outages. Packet loss uses authenticated
         * media indices, not this playback-clock counter. */
    }

out:
    xSemaphoreGive(s_lock);
    return got;
}

size_t vox_jb_depth(void)
{
    lock_init_once();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    size_t d = depth_locked();
    xSemaphoreGive(s_lock);
    return d;
}

void vox_jb_stats(vox_jb_stats_t *out)
{
    lock_init_once();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_stats;
    xSemaphoreGive(s_lock);
}

size_t vox_jb_bytes(void)
{
    return sizeof(s_slot)+sizeof(s_retired)+sizeof(s_retired_cursor)+sizeof(s_retired_sender)+
        sizeof(s_stats)+sizeof(s_media_seen)+sizeof(s_lock)+sizeof(s_next_seq)+sizeof(s_stream)+
        sizeof(s_sender)+sizeof(s_expected)+sizeof(s_end_seq)+sizeof(s_primed)+sizeof(s_ended)+sizeof(s_playing);
}

void vox_jb_end(uint16_t sender,uint16_t stream,uint32_t end)
{
    lock_init_once(); xSemaphoreTake(s_lock,portMAX_DELAY);
    if(!s_primed || s_sender!=sender || s_stream!=stream) {
        if(retired(sender,stream)) { xSemaphoreGive(s_lock); return; }
        retire_current();
        if(s_primed && !s_ended) s_stats.incomplete_streams++;
        memset(s_slot,0,sizeof(s_slot)); s_playing=false; s_primed=true;
        s_sender=sender; s_stream=stream; s_expected=0; s_next_seq=end;
        s_ended=false; vox_replay_reset(&s_media_seen);
    }
    if(!s_ended && end>=s_expected) {
        s_stats.media_expected+=end-s_expected; s_expected=end;
        s_end_seq=end; s_ended=true; s_stats.ended_streams++;
    }
    xSemaphoreGive(s_lock);
}
bool vox_jb_loss_complete(void)
{
    lock_init_once(); xSemaphoreTake(s_lock,portMAX_DELAY);
    bool complete=s_primed && s_ended && !s_stats.incomplete_streams;
    xSemaphoreGive(s_lock); return complete;
}
