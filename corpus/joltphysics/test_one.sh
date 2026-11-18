#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"

if [ -x "$BUILD_DIR/UnitTests.app/Contents/MacOS/UnitTests" ]; then
  BIN="$BUILD_DIR/UnitTests.app/Contents/MacOS/UnitTests"
else
  BIN="$BUILD_DIR/UnitTests"
fi

exec "$BIN" --no-intro -ts="$test_id"
