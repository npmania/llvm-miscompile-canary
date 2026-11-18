#!/bin/sh
set -eu

if [ -x "$BUILD_DIR/test-z3" ]; then
  TEST_Z3="$BUILD_DIR/test-z3"
elif [ -x "$BUILD_DIR/src/test/test-z3" ]; then
  TEST_Z3="$BUILD_DIR/src/test/test-z3"
else
  echo "test-z3 binary not found in $BUILD_DIR" >&2
  exit 1
fi

exec "$TEST_Z3" /seq "$1"
