#!/bin/sh
set -eu

case "$1" in
  api-test|lre-test)
    exec "$BUILD_DIR/$1"
    ;;
  *.js)
    cd "$SRC_DIR"
    exec "$BUILD_DIR/run-test262" -c tests.conf -f "tests/$1"
    ;;
  *)
    echo "unknown quickjs-ng subtest: $1" >&2
    exit 1
    ;;
esac
