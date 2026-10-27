idf_component_register(
    SRCS
        "app_main.c"
        "vox_console.c"
        "vox_ptt.c"
        "audio/vox_audio_src.c"
        "audio/vox_audio_sink.c"
        "audio/vox_codec.c"
        "audio/vox_jitterbuf.c"
        "net/vox_link.c"
        "net/vox_timesync.c"
        "sec/vox_crypto.c"
        "sec/vox_security.c"
        "sec/vox_keys.c"
        "sec/vox_replay.c"
        "sec/vox_session.c"
        "sec/vox_group.c"
        "sec/vox_group_control.c"
        "metrics/vox_metrics.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        esp_wifi
        esp_netif
        esp_event
        esp_timer
        esp_hw_support
        esp_app_format
        driver
        nvs_flash
        mbedtls
        console
        codec2
        ed25519_bench
)

# Measurement builds must be optimised. Timing a -Og build and reporting the
# numbers as the platform's cost would overstate every stage in the pipeline,
# and would overstate the cryptography most of all.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wno-unused-parameter)
