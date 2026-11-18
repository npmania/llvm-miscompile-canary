#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

if [ -x "$BUILD_DIR/test-z3" ]; then
  TEST_Z3="$BUILD_DIR/test-z3"
elif [ -x "$BUILD_DIR/src/test/test-z3" ]; then
  TEST_Z3="$BUILD_DIR/src/test/test-z3"
else
  echo "test-z3 binary not found in $BUILD_DIR" >&2
  exit 1
fi

set -- \
  rational \
  inf_rational \
  bit_vector \
  fixed_bit_vector \
  tbv \
  ast \
  mpz \
  mpq \
  mpf \
  fpa \
  polynomial \
  upolynomial \
  horner \
  grobner \
  simplifier \
  bit_blaster \
  var_subst \
  egraph \
  nlarith_util \
  arith_rewriter \
  factor_rewriter \
  sat_config \
  sat_unsat_core \
  smt_context \
  check_assumptions \
  finite_field \
  zstring

OUT_LOG="$BUILD_DIR/z3-test-all.log"
if ! "$TEST_Z3" "/j:$JOBS" "$@" >"$OUT_LOG" 2>&1; then
  cat "$OUT_LOG" >&2 || true
  failed_line=$(grep -E '^Failed tests:' "$OUT_LOG" || true)
  if [ -n "$failed_line" ]; then
    # shellcheck disable=SC2086
    for name in ${failed_line#Failed tests:}; do
      echo "FAIL_ID: $name"
    done
  else
    for m do
      if ! "$TEST_Z3" /seq "$m" >/dev/null 2>&1; then
        echo "FAIL_ID: $m"
      fi
    done
  fi
  exit 1
fi
