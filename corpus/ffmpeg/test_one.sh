#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
case "$test_id" in
  fate-*) ;;
  *) test_id="fate-${test_id}" ;;
esac

# remove stripped binaries so 1s mtime make always refreshes from relinked *_g
rm -f "$BUILD_DIR/ffmpeg" "$BUILD_DIR/ffprobe"
exec make -C "$BUILD_DIR" "$test_id"
