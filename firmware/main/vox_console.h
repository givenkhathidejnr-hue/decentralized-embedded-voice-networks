/*
 * vox_console.h - serial control of the experiment.
 *
 * The receiver-count sweep, the crypto on/off control, the rekey timing and
 * the security test cases are all driven from here rather than from rebuilds,
 * so one flashed image can produce a whole results table and the build is
 * identical across every point in it.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

esp_err_t vox_console_start(void);

/*
 * Adversary simulation, implemented in app_main.c because it replays the
 * pipeline's own last transmitted frame.
 *
 * These reproduce the radio-range attacker of the threat model: capture and
 * inject, no physical access, no credentials. Each one should produce a
 * specific, countable rejection at the receiver, and the counts are the
 * evidence that the protection works:
 *
 *   replay  -> rx_replay_drop rises, rx_frames does not
 *   tamper  -> rx_auth_fail rises, rx_frames does not
 *   forge   -> rx_auth_fail rises, rx_frames does not
 *
 * If any of them increases rx_frames instead, the protection is broken and
 * the run is a finding rather than a measurement.
 */
int vox_attack_replay(int count);
void vox_attack_info(void);
int vox_attack_tamper(int count);
int vox_attack_forge(int count);
int vox_attack_flood(int count);
