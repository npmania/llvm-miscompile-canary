#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

set -- \
  --cc="$CC" \
  --cxx="${CXX:-$CC}" \
  --host-cc="$CC" \
  --disable-asm \
  --disable-doc \
  --disable-network \
  --disable-autodetect \
  --disable-shared \
  --enable-static
if [ -n "${AR:-}" ]; then set -- "$@" --ar="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" --ranlib="$RANLIB"; fi

(
  cd "$BUILD_DIR"
  "$SRC_DIR/configure" "$@"
)

make -C "$BUILD_DIR" -j "$JOBS" all testprogs
