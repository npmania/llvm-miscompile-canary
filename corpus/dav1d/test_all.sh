#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
status=0

for sub in \
  meson_headers \
  decode_av1_8bpc \
  decode_av1_8bpc_mt \
  decode_av1_10bpc \
  decode_av1_10bpc_mt \
  fuzzer_8bpc \
  fuzzer_10bpc_mt
do
  if ! "$script_dir/test_one.sh" "$sub"; then
    echo "FAIL_ID: $sub"
    status=1
  fi
done

exit "$status"
