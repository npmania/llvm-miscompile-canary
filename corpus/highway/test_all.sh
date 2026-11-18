#!/bin/sh
set -eu

status=0
ran=0

for bin in "$BUILD_DIR"/tests/*_test; do
  [ -x "$bin" ] || continue
  name=$(basename "$bin")
  ran=$((ran + 1))
  if ! "$bin"; then
    echo "FAIL_ID: $name"
    status=1
  fi
done

if [ "$ran" -eq 0 ]; then
  echo "No highway test binaries found in $BUILD_DIR/tests" >&2
  exit 2
fi

exit "$status"
