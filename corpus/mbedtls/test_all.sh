#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
fail_log="$BUILD_DIR/Testing/Temporary/LastTestsFailed.log"
status=0

print_failed() {
  if [ -f "$fail_log" ]; then
    awk '{ sub(/^[0-9]+:/, ""); if (length($0) > 0) print "FAIL_ID: " $0 }' "$fail_log"
  fi
}

rm -f "$fail_log"
if ! ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -E "^(psa_crypto|psa_its)" -j "$JOBS"; then
  print_failed
  status=1
fi

# psa suites share *.psa_its files in $BUILD_DIR/tests and must run serially
rm -f "$fail_log" "$BUILD_DIR"/tests/*.psa_its
if ! ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^(psa_crypto|psa_its)" -j 1; then
  print_failed
  status=1
fi
rm -f "$BUILD_DIR"/tests/*.psa_its

exit "$status"
