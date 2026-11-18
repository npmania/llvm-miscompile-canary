#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
KBUILD="$BUILD_DIR/kissat-work/build"

failed=0
for s in \
  kitten \
  collect \
  terminate \
  heap \
  sort \
  bump \
  parse \
  references \
  arena \
  queue \
  stack \
  vector_basics \
  allocate_basic \
  endianness \
  solve \
  prove
do
  if ! (cd "$KBUILD" && ./tissat "-j$JOBS" "$s" >/dev/null 2>&1); then
    echo "FAIL_ID: $s"
    failed=1
  fi
done

exit "$failed"
