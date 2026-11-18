#!/bin/sh
set -eu

cd "$BUILD_DIR/kissat-work/build"
exec ./tissat -s "$1"
