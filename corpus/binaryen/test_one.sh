#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
tmp_dir="${TMPDIR:-/tmp}/lmc-binaryen-$$"
mkdir -p "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

(
  cd "$tmp_dir"
  python3 "$SRC_DIR/check.py" \
    --binaryen-bin "$BUILD_DIR/bin" \
    --binaryen-root "$SRC_DIR" \
    --no-torture \
    --filter "*/${test_id}" \
    wasm-opt
)
