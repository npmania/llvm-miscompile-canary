#!/bin/sh
set -eu

exec "$BUILD_DIR/iwasm" -f run "$BUILD_DIR/wasm-tests/${1}.wasm"
