#!/bin/sh
set -eu

find_bin() {
  name="$1"
  sub="$2"
  if [ -x "$BUILD_DIR/$sub/$name" ]; then
    echo "$BUILD_DIR/$sub/$name"
  elif [ -x "$BUILD_DIR/$name" ]; then
    echo "$BUILD_DIR/$name"
  else
    echo "missing zstd binary: $name" >&2
    exit 1
  fi
}

case "$1" in
  fullbench)
    exec "$(find_bin fullbench tests)" -i1
    ;;
  fuzzer)
    exec "$(find_bin fuzzer tests)" -s1 -i200 --no-big-tests
    ;;
  zstreamtest)
    exec "$(find_bin zstreamtest tests)" -s1 -i200 --no-big-tests
    ;;
  cli_roundtrip)
    ZSTD_BIN="$(find_bin zstd programs)"
    DATAGEN_BIN="$(find_bin datagen tests)"
    TMP_WORK="$BUILD_DIR/zstd-rt-$$"
    mkdir -p "$TMP_WORK"
    trap 'rm -rf "$TMP_WORK"' EXIT
    "$DATAGEN_BIN" -g256K -s42 >"$TMP_WORK/input.bin"
    for lvl in 1 3 9 15; do
      "$ZSTD_BIN" -q -f "-$lvl" "$TMP_WORK/input.bin" -o "$TMP_WORK/out.zst"
      "$ZSTD_BIN" -q -f -d "$TMP_WORK/out.zst" -o "$TMP_WORK/roundtrip.bin"
      cmp -s "$TMP_WORK/input.bin" "$TMP_WORK/roundtrip.bin"
    done
    ;;
  *)
    echo "unknown zstd subtest: $1" >&2
    exit 1
    ;;
esac
