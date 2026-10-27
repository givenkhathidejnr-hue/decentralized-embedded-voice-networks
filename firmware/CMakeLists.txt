# Baseline architecture for "Investigation into the Scalability and Security of
# Decentralized Embedded Voice Networks" (S. Kubheka, UCT EE).
#
# Target: ESP32-WROOM-32 (no PSRAM assumed), ESP-IDF v5.2+
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(vox_baseline)
