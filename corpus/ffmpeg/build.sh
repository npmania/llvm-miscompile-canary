#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

HOST_CC="$CC"
set -- \
  --cc="$CC" \
  --cxx="${CXX:-$CC}" \
  --disable-asm \
  --disable-doc \
  --disable-large-tests \
  --disable-network \
  --disable-autodetect \
  --disable-shared \
  --enable-static
if [ "${LMC_PLATFORM:-}" = "linux-riscv64" ] && [ "$(uname -m)" != "riscv64" ]; then
  HOST_CC="${LMC_REAL_CC:-cc}"
  set -- "$@" --enable-cross-compile --arch=riscv64 --target-os=linux --disable-stripping
fi
set -- "$@" --host-cc="$HOST_CC"
if [ -n "${AR:-}" ]; then set -- "$@" --ar="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" --ranlib="$RANLIB"; fi
if [ -n "${NM:-}" ]; then set -- "$@" --nm="$NM"; fi

(
  cd "$BUILD_DIR"
  "$SRC_DIR/configure" "$@"
)

make -C "$BUILD_DIR" -j "$JOBS" all testprogs
