#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
bin="$BUILD_DIR/tests/$test_id"

if [ ! -x "$bin" ]; then
  echo "Unknown highway test binary: $test_id" >&2
  exit 2
fi

exec "$bin"
