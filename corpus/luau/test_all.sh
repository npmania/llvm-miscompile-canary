#!/bin/sh
set -eu

failed=0
for suite in Optimization ConstantFolding TypeInferPrimitives NotNull; do
  if ! "$BUILD_DIR/Luau.UnitTest" --test-suite="$suite" >/dev/null; then
    echo "FAIL_ID: UnitTest:$suite"
    failed=1
  fi
done

for tc in \
  Basic \
  Math \
  Tables \
  PatternMatch \
  Sort \
  Strings \
  StringInterp \
  VarArg \
  Locals \
  Literals \
  Constructs \
  Closure \
  Calls \
  GC \
  Bitwise \
  UTF8 \
  Coroutine \
  Vector \
  Buffers
do
  if ! "$BUILD_DIR/Luau.Conformance" --test-case="$tc" >/dev/null; then
    echo "FAIL_ID: Conformance:$tc"
    failed=1
  fi
done

exit "$failed"
