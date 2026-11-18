#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
failed=0
for t in fullbench fuzzer zstreamtest cli_roundtrip; do
  if ! "$script_dir/test_one.sh" "$t" >/dev/null 2>&1; then
    echo "FAIL_ID: $t"
    failed=1
  fi
done

exit "$failed"
