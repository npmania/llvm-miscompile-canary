#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
exec "$BUILD_DIR/bin/test" "$test_id"
