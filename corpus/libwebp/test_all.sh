#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
status=0

for sub in \
  decode_ref \
  lossless_roundtrip \
  near_lossless_roundtrip \
  lossy_sharpyuv_mt \
  webpmux_info
do
  if ! "$script_dir/test_one.sh" "$sub"; then
    echo "FAIL_ID: $sub"
    status=1
  fi
done

exit "$status"
