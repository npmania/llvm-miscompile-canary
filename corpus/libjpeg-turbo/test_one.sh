#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"

# *-cmp checks MD5 of output from the base test, so re-run the producer first
case "$test_id" in
  *-cmp)
    prod="${test_id%-cmp}"
    prod_esc=$(printf '%s' "$prod" | sed 's/[][\\.^$*+?()|{}]/\\&/g')
    if ctest --test-dir "$BUILD_DIR" -N -R "^${prod_esc}$" 2>/dev/null | grep -q "Test  *#"; then
      ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^${prod_esc}$"
    fi
    ;;
esac

escaped=$(printf '%s' "$test_id" | sed 's/[][\\.^$*+?()|{}]/\\&/g')
exec ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^${escaped}$"
