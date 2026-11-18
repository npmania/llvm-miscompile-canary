#!/bin/sh
set -eu

WORK_TMP="$BUILD_DIR/lua-test-cwd"
rm -rf "$WORK_TMP"
mkdir -p "$WORK_TMP"

export LUA_PATH="$SRC_DIR/testes/?.lua;;"

failed=0
for suite in \
  math \
  bitwise \
  bwcoercion \
  calls \
  closure \
  code \
  constructs \
  coroutine \
  events \
  gc \
  gengc \
  goto \
  literals \
  locals \
  nextvar \
  pm \
  sort \
  strings \
  tpack \
  utf8 \
  vararg
do
  if ! (cd "$WORK_TMP" && "$BUILD_DIR/lua" -e "_U=true" "$SRC_DIR/testes/${suite}.lua" >/dev/null); then
    echo "FAIL_ID: $suite"
    failed=1
  fi
done

exit "$failed"
