#!/bin/sh
set -eu

kind="${1%%:*}"
name="${1#*:}"

case "$kind" in
  UnitTest)
    exec "$BUILD_DIR/Luau.UnitTest" --test-suite="$name"
    ;;
  Conformance)
    exec "$BUILD_DIR/Luau.Conformance" --test-case="$name"
    ;;
  *)
    echo "unknown luau subtest id: $1" >&2
    exit 1
    ;;
esac
