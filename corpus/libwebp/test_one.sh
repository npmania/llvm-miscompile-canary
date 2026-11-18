#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
tmp_dir="${TMPDIR:-/tmp}/lmc-webp-$$"
mkdir -p "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

ref_ppm="$SRC_DIR/examples/test_ref.ppm"
ref_webp="$SRC_DIR/examples/test.webp"

case "$test_id" in
  decode_ref)
    "$BUILD_DIR/dwebp" "$ref_webp" -ppm -o "$tmp_dir/dec.ppm" >/dev/null 2>&1
    [ -s "$tmp_dir/dec.ppm" ]
    head -n 2 "$tmp_dir/dec.ppm" | grep -q "128 128"
    ;;
  lossless_roundtrip)
    "$BUILD_DIR/cwebp" -quiet -lossless -z 6 "$ref_ppm" -o "$tmp_dir/ll.webp"
    "$BUILD_DIR/dwebp" "$tmp_dir/ll.webp" -ppm -o "$tmp_dir/ll.ppm" >/dev/null 2>&1
    cmp -s "$ref_ppm" "$tmp_dir/ll.ppm"
    ;;
  near_lossless_roundtrip)
    "$BUILD_DIR/cwebp" -quiet -near_lossless 60 "$ref_ppm" -o "$tmp_dir/nl.webp"
    "$BUILD_DIR/webpinfo" "$tmp_dir/nl.webp" | grep -q "Format: Lossless"
    "$BUILD_DIR/dwebp" "$tmp_dir/nl.webp" -pam -o "$tmp_dir/nl.pam" >/dev/null 2>&1
    [ -s "$tmp_dir/nl.pam" ]
    ;;
  lossy_sharpyuv_mt)
    "$BUILD_DIR/cwebp" -quiet -q 85 -m 6 -sharp_yuv -mt "$ref_ppm" -o "$tmp_dir/sy.webp"
    "$BUILD_DIR/webpinfo" "$tmp_dir/sy.webp" | grep -q "Format: Lossy"
    "$BUILD_DIR/dwebp" "$tmp_dir/sy.webp" -mt -ppm -o "$tmp_dir/sy.ppm" >/dev/null 2>&1
    head -n 2 "$tmp_dir/sy.ppm" | grep -q "128 128"
    ;;
  webpmux_info)
    "$BUILD_DIR/webpmux" -info "$ref_webp" | grep -q "Canvas size"
    ;;
  *)
    echo "Unknown libwebp test id: $test_id" >&2
    exit 2
    ;;
esac
