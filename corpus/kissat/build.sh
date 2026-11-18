#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

WORK_SRC="$BUILD_DIR/kissat-work"
rm -rf "$WORK_SRC"
mkdir -p "$WORK_SRC"
cp -R "$SRC_DIR/." "$WORK_SRC/"

cd "$WORK_SRC"
./configure -c --test --kitten CC="${CC:-cc}"
make -C "$WORK_SRC/build" -j "$JOBS" AR="${AR:-ar}" all tissat
