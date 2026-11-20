#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
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

set -- \
  test_math \
  test_int \
  test_float \
  test_decimal \
  test_fractions \
  test_random \
  test_hashlib \
  test_zlib \
  test_struct \
  test_json \
  test_re \
  test_collections \
  test_itertools \
  test_functools \
  test_ctypes \
  test_dict \
  test_set \
  test_tuple \
  test_slice \
  test_range \
  test_str \
  test_sort \
  test_long \
  test_strtod \
  test_complex \
  test_cmath \
  test_bool \
  test_compare \
  test_format \
  test_opcodes \
  test_genexps \
  test_patma \
  test_array \
  test_binascii \
  test_bisect \
  test_heapq \
  test_csv \
  test_operator \
  test_deque \
  test_ordered_dict

STATUS_DIR="$BUILD_DIR/.lmc-test-status"
rm -rf "$STATUS_DIR"
mkdir -p "$STATUS_DIR"

running=0
for mod do
  (
    if ! "$PY" -m test --dont-add-python-opts "$mod" >"$STATUS_DIR/$mod.log" 2>&1; then
      echo "$mod" >"$STATUS_DIR/$mod.fail"
    fi
  ) &
  running=$((running + 1))
  if [ "$running" -ge "$JOBS" ]; then
    wait
    running=0
  fi
done
wait

failed=0
for mod do
  if [ -f "$STATUS_DIR/$mod.fail" ]; then
    cat "$STATUS_DIR/$mod.log" >&2 || true
    echo "FAIL_ID: $mod"
    failed=1
  fi
done

exit "$failed"
