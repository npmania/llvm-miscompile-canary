#!/bin/sh
set -eu

if [ -x "$BUILD_DIR/UnitTests.app/Contents/MacOS/UnitTests" ]; then
  BIN="$BUILD_DIR/UnitTests.app/Contents/MacOS/UnitTests"
else
  BIN="$BUILD_DIR/UnitTests"
fi

if "$BIN" --no-intro; then
  exit 0
fi

suites_file="${TMPDIR:-/tmp}/lmc-jolt-$$"
trap 'rm -f "$suites_file"' EXIT
"$BIN" --no-intro --list-test-suites >"$suites_file"

found=0
while IFS= read -r suite; do
  case "$suite" in
    ""|\[*|===*) continue ;;
  esac
  if ! "$BIN" --no-intro -ts="$suite" >/dev/null 2>&1; then
    echo "FAIL_ID: $suite"
    found=1
  fi
done <"$suites_file"

if [ "$found" -eq 0 ]; then
  echo "FAIL_ID: Mat44Tests"
fi
exit 1
