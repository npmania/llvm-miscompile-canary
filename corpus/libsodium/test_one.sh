#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
cd "$BUILD_DIR/test/default"

if [ ! -x "./$test_id" ]; then
  echo "Unknown libsodium test binary: $test_id" >&2
  exit 2
fi

exec "./$test_id"
