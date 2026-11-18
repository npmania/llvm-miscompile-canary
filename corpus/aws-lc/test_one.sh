#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
cd "$BUILD_DIR"

case "$test_id" in
  urandom_test)
    exec ./crypto/urandom_test
    ;;
  crypto_test)
    exec ./crypto/crypto_test
    ;;
  ssl_test)
    exec ./ssl/ssl_test
    ;;
esac

if ./crypto/crypto_test --gtest_list_tests --gtest_filter="$test_id" 2>/dev/null | grep -q '^  [A-Za-z0-9_]'; then
  exec ./crypto/crypto_test --gtest_filter="$test_id"
fi

if ./ssl/ssl_test --gtest_list_tests --gtest_filter="$test_id" 2>/dev/null | grep -q '^  [A-Za-z0-9_]'; then
  exec ./ssl/ssl_test --gtest_filter="$test_id"
fi

echo "Unknown aws-lc test id: $test_id" >&2
exit 2
