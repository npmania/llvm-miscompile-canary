#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
rm -f "$BUILD_DIR"/tests/*.psa_its

escaped=$(printf '%s' "$test_id" | sed 's/[][\\.^$*+?()|{}]/\\&/g')
exec ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^${escaped}$"
