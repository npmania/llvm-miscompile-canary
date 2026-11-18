#!/bin/sh
set -eu

failed=0
for t in i32_bits i64_arith f64_math linear_mem control_recursion; do
  if ! "$BUILD_DIR/iwasm" -f run "$BUILD_DIR/wasm-tests/${t}.wasm" >/dev/null; then
    echo "FAIL_ID: $t"
    failed=1
  fi
done

exit "$failed"
