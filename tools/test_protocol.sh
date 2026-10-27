#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp /tmp/vox-protocol-test.XXXXXX)
trap 'rm -f "$out"' EXIT
for mode in gcm ccm; do
  flags=()
  if [[ "$mode" == ccm ]]; then flags+=(-DTEST_CCM); fi
  cc -std=gnu11 -g -O1 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter \
    -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" \
    -Itools/tests/stubs -Ifirmware/main tools/tests/protocol_test.c tools/tests/crypto_adapter.c \
    -lcrypto -pthread -o "$out"
  echo "Testing AES-$mode protocol path"
  ASAN_OPTIONS=detect_leaks=0 "$out"
done
