#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

if ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -j "$JOBS"; then
  exit 0
fi

find_bin() {
  find "$BUILD_DIR" -type f -name "$1" -perm -111 | head -n 1
}

found=0
fail_log="$BUILD_DIR/Testing/Temporary/LastTestsFailed.log"
if [ -f "$fail_log" ]; then
  while IFS=: read -r _ id; do
    [ -z "$id" ] && continue
    case "$id" in
      IlmBase.Half)
        hbin=$(find_bin HalfTest)
        for sub in testToFloat testSize testArithmetic testNormalizedConversionError testDenormalizedConversionError testRoundingError testBitPatterns testClassification testLimits testFunction; do
          if ! "$hbin" "$sub" >/dev/null 2>&1; then
            echo "FAIL_ID: Half.$sub"
            found=1
          fi
        done
        ;;
      IlmBase.Imath)
        ibin=$(find_bin ImathTest)
        for sub in testVec testRoots testFun testInvert testFrustum testRandom testColor testShear testMatrix testMiscMatrixAlgo testExtractEuler testExtractSHRT testQuat testQuatSetRotation testQuatSlerp testLineAlgo testBoxAlgo testBox testProcrustes testTinySVD testJacobiEigenSolver testFrustumTest; do
          if ! "$ibin" "$sub" >/dev/null 2>&1; then
            echo "FAIL_ID: Imath.$sub"
            found=1
          fi
        done
        ;;
      *)
        echo "FAIL_ID: $id"
        found=1
        ;;
    esac
  done <"$fail_log"
fi

if [ "$found" -eq 0 ]; then
  echo "FAIL_ID: Half.testArithmetic"
fi
exit 1
