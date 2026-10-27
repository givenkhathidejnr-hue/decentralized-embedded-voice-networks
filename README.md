# Decentralized Embedded Voice Networks

This repository contains the project-authored firmware and experimental tools
for the final-year project, *Investigation into the Scalability and Security of
Decentralized Embedded Voice Networks*.

## Included

- `firmware/main/`: the project firmware for the ESP32 voice-network prototype.
- `firmware/CMakeLists.txt`: the ESP-IDF project configuration.
- `tools/`: project-authored flashing, capture, analysis, plotting, and host-test
  utilities.

Generated build output, serial logs, Python caches, report files, and other
local artefacts are excluded from the repository.

## External components

The firmware also uses Codec2 and the vendored Ed25519 implementation. Those
third-party sources are not included in this repository because this repository
is intended to contain the project-authored source. Their licences and source
attributions should be obtained from their respective upstream projects when
reproducing a complete build.
