#!/bin/sh
set -eu

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export PYTHONHASHSEED=0

if [ -f "$BUILD_DIR/python.exe" ] && [ -x "$BUILD_DIR/python.exe" ]; then
  PY="$BUILD_DIR/python.exe"
elif [ -f "$BUILD_DIR/python" ] && [ -x "$BUILD_DIR/python" ]; then
  PY="$BUILD_DIR/python"
else
  echo "cpython executable not found in $BUILD_DIR" >&2
  exit 1
fi

exec "$PY" -m test --dont-add-python-opts "$1"
