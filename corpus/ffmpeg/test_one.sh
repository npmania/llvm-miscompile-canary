#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
case "$test_id" in
  fate-*) ;;
  *) test_id="fate-${test_id}" ;;
esac

exec make -C "$BUILD_DIR" "$test_id"
