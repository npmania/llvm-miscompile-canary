#!/bin/sh
set -eu

status=0
log_dir="${TMPDIR:-/tmp}/lmc-awslc-$$"
mkdir -p "$log_dir"
trap 'rm -rf "$log_dir"' EXIT

if ! (cd "$BUILD_DIR" && ./crypto/urandom_test) >"$log_dir/urandom.log" 2>&1; then
  cat "$log_dir/urandom.log" >&2
  echo "FAIL_ID: urandom_test"
  status=1
fi

run_gtest_bin() {
  bin="$1"
  label="$2"
  log="$log_dir/${label}.log"
  if ! (cd "$BUILD_DIR" && "$bin") >"$log" 2>&1; then
    tail -n 80 "$log" >&2 || true
    fails=$(awk '/^\[  FAILED  \] [A-Za-z0-9_\/]+\.[A-Za-z0-9_\/]+/{print $4}' "$log" | sed 's/,$//' | sort -u)
    if [ -z "$fails" ]; then
      fails=$(awk '/^\[ RUN      \] /{last=$4} /^\[       OK \] /{last=""} END{if (last!="") print last}' "$log")
    fi
    if [ -n "$fails" ]; then
      printf '%s\n' "$fails" | while IFS= read -r t; do
        [ -n "$t" ] && echo "FAIL_ID: $t"
      done
    else
      echo "FAIL_ID: $label"
    fi
    status=1
  fi
}

run_gtest_bin ./crypto/crypto_test crypto_test
run_gtest_bin ./ssl/ssl_test ssl_test

exit "$status"
