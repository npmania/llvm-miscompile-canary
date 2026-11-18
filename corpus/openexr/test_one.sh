#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"

case "$test_id" in
  Half.*)
    bin=$(find "$BUILD_DIR" -type f -name HalfTest -perm -111 | head -n 1)
    exec "$bin" "${test_id#Half.}"
    ;;
  Imath.*)
    bin=$(find "$BUILD_DIR" -type f -name ImathTest -perm -111 | head -n 1)
    exec "$bin" "${test_id#Imath.}"
    ;;
  *)
    escaped=$(printf '%s' "$test_id" | sed 's/[][\\.^$*+?()|{}]/\\&/g')
    exec ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^${escaped}$"
    ;;
esac
