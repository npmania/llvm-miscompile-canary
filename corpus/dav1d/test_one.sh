#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
tmp_dir="${TMPDIR:-/tmp}/lmc-dav1d-$$"
mkdir -p "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

write_sample8() {
  python3 -m base64 -d >"$tmp_dir/sample8.ivf" <<'EOF'
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
EOF
}

write_sample10() {
  python3 -m base64 -d >"$tmp_dir/sample10.ivf" <<'EOF'
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
cAFIDfxT0CviMjlBUA==
EOF
}

case "$test_id" in
  meson_headers)
    meson test -C "$BUILD_DIR" --no-rebuild --print-errorlogs
    ;;
  decode_av1_8bpc)
    write_sample8
    "$BUILD_DIR/tools/dav1d" -q -i "$tmp_dir/sample8.ivf" --threads 1 --muxer md5 -o - >"$tmp_dir/md5.out"
    got=$(tr -d '[:space:]' <"$tmp_dir/md5.out")
    [ "$got" = "4a899f3f4cd06281530a54a3cbc55464" ]
    ;;
  decode_av1_8bpc_mt)
    write_sample8
    "$BUILD_DIR/tools/dav1d" -q -i "$tmp_dir/sample8.ivf" --threads 2 --muxer md5 -o - >"$tmp_dir/md5.out"
    got=$(tr -d '[:space:]' <"$tmp_dir/md5.out")
    [ "$got" = "4a899f3f4cd06281530a54a3cbc55464" ]
    ;;
  decode_av1_10bpc)
    write_sample10
    "$BUILD_DIR/tools/dav1d" -q -i "$tmp_dir/sample10.ivf" --threads 1 --muxer md5 -o - >"$tmp_dir/md5.out"
    got=$(tr -d '[:space:]' <"$tmp_dir/md5.out")
    [ "$got" = "896e5368c865743fe698d07ed3b5facb" ]
    ;;
  decode_av1_10bpc_mt)
    write_sample10
    "$BUILD_DIR/tools/dav1d" -q -i "$tmp_dir/sample10.ivf" --threads 2 --muxer md5 -o - >"$tmp_dir/md5.out"
    got=$(tr -d '[:space:]' <"$tmp_dir/md5.out")
    [ "$got" = "896e5368c865743fe698d07ed3b5facb" ]
    ;;
  fuzzer_8bpc)
    write_sample8
    "$BUILD_DIR/tests/libfuzzer/dav1d_fuzzer" "$tmp_dir/sample8.ivf"
    ;;
  fuzzer_10bpc_mt)
    write_sample10
    "$BUILD_DIR/tests/libfuzzer/dav1d_fuzzer_mt" "$tmp_dir/sample10.ivf"
    ;;
  *)
    meson test -C "$BUILD_DIR" --no-rebuild --print-errorlogs "$test_id"
    ;;
esac
