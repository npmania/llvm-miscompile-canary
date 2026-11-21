#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

make -C "$BUILD_DIR" fate-clear-reports >/dev/null 2>&1 || true

if ! make -C "$BUILD_DIR" -k -j "$JOBS" \
  FATE_CHECKASM= \
  FATE_VSYNTH2= \
  FATE_VSYNTH3= \
  FATE_PIXFMT_8= \
  FATE_PIXFMT_EXT= \
  FATE_PIXFMT_16= \
  fate; then
  found=0
  for rep in "$BUILD_DIR"/tests/data/fate/*.rep; do
    [ -f "$rep" ] || continue
    fail_name=$(awk -F: '$2 != 0 { print "fate-" $1 }' "$rep")
    if [ -n "$fail_name" ]; then
      echo "FAIL_ID: $fail_name"
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "FAIL_ID: fate-adler32"
  fi
  exit 1
fi
