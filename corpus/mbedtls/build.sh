#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

set -- \
  -S "$SRC_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DENABLE_TESTING=ON \
  -DENABLE_PROGRAMS=OFF \
  -DMBEDTLS_FATAL_WARNINGS=OFF \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
  -DUSE_STATIC_MBEDTLS_LIBRARY=ON
if command -v ninja >/dev/null 2>&1; then set -- "$@" -G Ninja; fi
if [ -n "${AR:-}" ]; then set -- "$@" -DCMAKE_AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then
  if [ "$(uname -s)" = "Darwin" ]; then
    # mbedtls library/CMakeLists.txt passes Apple ranlib flags rejected by llvm-ranlib
    shim="$BUILD_DIR/ranlib-shim.sh"
    cat >"$shim" <<EOF
#!/bin/sh
set -eu
for arg do
  shift
  case "\$arg" in
    -no_warning_for_no_symbols|-c) ;;
    *) set -- "\$@" "\$arg" ;;
  esac
done
exec "$RANLIB" "\$@"
EOF
    chmod +x "$shim"
    set -- "$@" -DCMAKE_RANLIB="$shim"
  else
    set -- "$@" -DCMAKE_RANLIB="$RANLIB"
  fi
fi

cmake "$@"
cmake --build "$BUILD_DIR" -j "$JOBS"
