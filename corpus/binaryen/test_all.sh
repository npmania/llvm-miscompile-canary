#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
status=0
for t in \
  licm.wast \
  merge-blocks.wast \
  duplicate-import-elimination.wast \
  func-metrics.wast \
  fuzz-exec_O.wast \
  interesting-pass-mix.wast \
  O1_print-stack-ir.wast \
  O2_print-stack-ir.wast \
  O3_print-stack-ir.wast \
  optimize-added-constants_low-memory-unused.wast
do
  if ! "$script_dir/test_one.sh" "$t"; then
    echo "FAIL_ID: $t"
    status=1
  fi
done

exit "$status"
