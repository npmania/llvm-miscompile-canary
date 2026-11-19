#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

set -- "CC=$CC"
if [ -n "${AR:-}" ]; then set -- "$@" "AR=$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" "RANLIB=$RANLIB"; fi

CROSS_HOST=""
if [ "${LMC_PLATFORM:-}" = "linux-riscv64" ] && [ "$(uname -m)" != "riscv64" ]; then
  CROSS_HOST="--host=riscv64-linux-gnu"
fi

(
  cd "$BUILD_DIR"
  env "$@" "$SRC_DIR/configure" \
    ${CROSS_HOST:+"$CROSS_HOST"} \
    --disable-asm \
    --disable-shared \
    --enable-static \
    --disable-dependency-tracking
)

make -C "$BUILD_DIR" -j "$JOBS"
make -C "$BUILD_DIR/test/default" -j "$JOBS" check TESTS=
