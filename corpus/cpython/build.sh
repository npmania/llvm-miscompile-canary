#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

set -- \
  --with-computed-gotos \
  --without-ensurepip \
  --without-pymalloc \
  --without-mimalloc \
  CC="${CC:-cc}" \
  CXX="${CXX:-c++}"
if [ -n "${AR:-}" ]; then set -- "$@" AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" RANLIB="$RANLIB"; fi
if [ "$(uname -s)" = "Darwin" ]; then
  set -- "$@" LDFLAGS="${LDFLAGS:+$LDFLAGS }-Wl,-export_dynamic"
fi

"$SRC_DIR/configure" "$@"
make -C "$BUILD_DIR" -j "$JOBS"
