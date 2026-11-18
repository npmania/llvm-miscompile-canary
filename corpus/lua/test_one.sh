#!/bin/sh
set -eu

WORK_TMP="$BUILD_DIR/lua-test-one-$$"
mkdir -p "$WORK_TMP"
trap 'rm -rf "$WORK_TMP"' EXIT

export LUA_PATH="$SRC_DIR/testes/?.lua;;"
cd "$WORK_TMP"
"$BUILD_DIR/lua" -e "_U=true" "$SRC_DIR/testes/${1}.lua"
