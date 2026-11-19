#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

export CC
if [ -n "${CXX:-}" ]; then export CXX; fi
if [ -n "${AR:-}" ]; then export AR; fi
if [ -n "${RANLIB:-}" ]; then export RANLIB; fi

set --
if [ -f "$BUILD_DIR/build.ninja" ]; then set -- --wipe; fi
if [ "${LMC_PLATFORM:-}" = "linux-riscv64" ] && [ "$(uname -m)" != "riscv64" ]; then
  cat >"$BUILD_DIR/cross.ini" <<EOF
[binaries]
c = '${CC:-cc}'
ar = '${AR:-ar}'
ranlib = '${RANLIB:-ranlib}'

[properties]
needs_exe_wrapper = false

[host_machine]
system = 'linux'
cpu_family = 'riscv64'
cpu = 'riscv64'
endian = 'little'
EOF
  set -- "$@" --cross-file "$BUILD_DIR/cross.ini"
fi

meson setup "$@" "$BUILD_DIR" "$SRC_DIR" \
  --buildtype=release \
  --default-library=static \
  -Denable_asm=false \
  -Denable_tests=true \
  -Denable_tools=true \
  -Denable_examples=false \
  -Denable_docs=false

ninja -C "$BUILD_DIR" -j "$JOBS"
