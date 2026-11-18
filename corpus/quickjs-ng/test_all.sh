#!/bin/sh
set -eu

failed=0
for t in \
  api-test \
  lre-test \
  test_closure.js \
  test_language.js \
  test_bigint.js \
  test_loop.js \
  test_builtin.js \
  test_bjson.js \
  test_base64.js
do
  case "$t" in
    api-test|lre-test)
      if ! "$BUILD_DIR/$t" >/dev/null; then
        echo "FAIL_ID: $t"
        failed=1
      fi
      ;;
    *.js)
      if ! (cd "$SRC_DIR" && "$BUILD_DIR/run-test262" -c tests.conf -f "tests/$t" >/dev/null 2>&1); then
        echo "FAIL_ID: $t"
        failed=1
      fi
      ;;
  esac
done

exit "$failed"
