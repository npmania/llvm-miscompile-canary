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
if [ "${LMC_PLATFORM:-}" = "linux-riscv64" ] && [ "$(uname -m)" != "riscv64" ]; then
  HOST_PY_DIR="$BUILD_DIR/host-python"
  mkdir -p "$HOST_PY_DIR"
  (
    cd "$HOST_PY_DIR"
    "$SRC_DIR/configure" \
      --without-ensurepip \
      --without-pymalloc \
      --without-mimalloc \
      CC="${LMC_REAL_CC:-cc}" \
      CXX="${LMC_REAL_CXX:-c++}"
    make -j "$JOBS" python
  )
  set -- "$@" \
    --build="$(CC_FOR_BUILD="${LMC_REAL_CC:-cc}" "$SRC_DIR/config.guess")" \
    --host=riscv64-linux-gnu \
    --with-build-python="$HOST_PY_DIR/python" \
    PKG_CONFIG=false \
    ac_cv_file__dev_ptmx=yes \
    ac_cv_file__dev_ptc=no \
    ac_cv_buggy_getaddrinfo=no
fi

"$SRC_DIR/configure" "$@"
make -C "$BUILD_DIR" -j "$JOBS"
for f in "$BUILD_DIR"/Modules/*_failed*.so; do
  [ -e "$f" ] || continue
  b=${f##*/}
  mv "$f" "$BUILD_DIR/Modules/${b%%_failed*}${b#*_failed}"
done
make -C "$BUILD_DIR" sharedmods
