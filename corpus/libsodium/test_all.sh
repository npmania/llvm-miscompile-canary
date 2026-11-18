#!/bin/sh
set -eu

cd "$BUILD_DIR/test/default"

status=0
ran=0
for src in "$SRC_DIR"/test/default/*.c; do
  name=$(basename "$src" .c)
  if [ -x "./$name" ]; then
    ran=$((ran + 1))
    if ! "./$name"; then
      echo "FAIL_ID: $name"
      status=1
    fi
  fi
done

if [ "$ran" -eq 0 ]; then
  echo "No libsodium test binaries found in $BUILD_DIR/test/default" >&2
  exit 2
fi

exit "$status"
