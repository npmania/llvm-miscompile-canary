#!/bin/sh
set -eu

if [ -x "$BUILD_DIR/test/unittest" ]; then
  UNITTEST="$BUILD_DIR/test/unittest"
elif [ -x "$BUILD_DIR/unittest" ]; then
  UNITTEST="$BUILD_DIR/unittest"
else
  echo "duckdb unittest binary not found in $BUILD_DIR" >&2
  exit 1
fi

TEMP_DB_DIR="$BUILD_DIR/duckdb-tmp-$$"
rm -rf "$TEMP_DB_DIR"
trap 'rm -rf "$TEMP_DB_DIR"' EXIT

"$UNITTEST" --test-dir "$SRC_DIR" --test-temp-dir "$TEMP_DB_DIR" "$1"
