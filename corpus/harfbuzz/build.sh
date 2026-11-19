#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

HARNESS_DIR="$BUILD_DIR/hb-harness-src"
rm -rf "$HARNESS_DIR"
mkdir -p "$HARNESS_DIR"

cat >"$HARNESS_DIR/test_shape_subset.cc" <<'EOF'
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstring>
#include "hb.h"
#include "hb-ot.h"
#include "hb-subset.h"

int main(int argc, char **argv) {
  assert(argc >= 2);
  hb_blob_t *blob = hb_blob_create_from_file_or_fail(argv[1]);
  assert(blob != nullptr);
  hb_face_t *face = hb_face_create(blob, 0);
  hb_blob_destroy(blob);
  assert(hb_face_get_glyph_count(face) > 0);

  hb_font_t *font = hb_font_create(face);
  hb_ot_font_set_funcs(font);

  hb_buffer_t *buf = hb_buffer_create();
  hb_buffer_add_utf8(buf, "AVATAR Office ffi 0123456789", -1, 0, -1);
  hb_buffer_guess_segment_properties(buf);
  hb_shape(font, buf, nullptr, 0);

  unsigned int len = 0;
  hb_glyph_info_t *infos = hb_buffer_get_glyph_infos(buf, &len);
  hb_glyph_position_t *pos = hb_buffer_get_glyph_positions(buf, &len);
  assert(len > 0 && infos != nullptr && pos != nullptr);

  hb_subset_input_t *input = hb_subset_input_create_or_fail();
  assert(input != nullptr);
  hb_set_t *unicodes = hb_subset_input_unicode_set(input);
  for (unsigned cp = 'A'; cp <= 'z'; ++cp) hb_set_add(unicodes, cp);
  hb_face_t *sub_face = hb_subset_or_fail(face, input);
  assert(sub_face != nullptr);
  assert(hb_face_get_glyph_count(sub_face) > 0);

  hb_face_destroy(sub_face);
  hb_subset_input_destroy(input);
  hb_buffer_destroy(buf);
  hb_font_destroy(font);
  hb_face_destroy(face);
  return 0;
}
EOF

cat >"$HARNESS_DIR/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(harfbuzz_canary_harness LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(HB_HAVE_FREETYPE OFF CACHE BOOL "" FORCE)
set(HB_HAVE_GLIB OFF CACHE BOOL "" FORCE)
set(HB_HAVE_ICU OFF CACHE BOOL "" FORCE)
set(HB_HAVE_CAIRO OFF CACHE BOOL "" FORCE)
set(HB_HAVE_CORETEXT OFF CACHE BOOL "" FORCE)
set(HB_HAVE_GOBJECT OFF CACHE BOOL "" FORCE)
set(HB_HAVE_INTROSPECTION OFF CACHE BOOL "" FORCE)
set(HB_BUILD_UTILS OFF CACHE BOOL "" FORCE)
set(HB_BUILD_SUBSET ON CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)

add_subdirectory("${HB_SRC_DIR}" hb_build)
enable_testing()

function(add_hb_internal_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "${HB_SRC_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}/hb_build/src")
  target_compile_options(${name} PRIVATE -UNDEBUG)
  target_link_libraries(${name} PRIVATE harfbuzz harfbuzz-subset)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_hb_internal_test(test-algs "${HB_SRC_DIR}/src/test-algs.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-array "${HB_SRC_DIR}/src/test-array.cc")
add_hb_internal_test(test-bimap "${HB_SRC_DIR}/src/test-bimap.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-cache "${HB_SRC_DIR}/src/test-cache.cc")
add_hb_internal_test(test-decycler "${HB_SRC_DIR}/src/test-decycler.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-geometry "${HB_SRC_DIR}/src/test-geometry.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-iter "${HB_SRC_DIR}/src/test-iter.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-machinery "${HB_SRC_DIR}/src/test-machinery.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-map "${HB_SRC_DIR}/src/test-map.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-multimap "${HB_SRC_DIR}/src/test-multimap.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-number "${HB_SRC_DIR}/src/test-number.cc" "${HB_SRC_DIR}/src/hb-number.cc")
add_hb_internal_test(test-priority-queue "${HB_SRC_DIR}/src/test-priority-queue.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-repacker "${HB_SRC_DIR}/src/test-repacker.cc" "${HB_SRC_DIR}/src/hb-static.cc" "${HB_SRC_DIR}/src/graph/gsubgpos-context.cc")
add_hb_internal_test(test-result "${HB_SRC_DIR}/src/test-result.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-serialize "${HB_SRC_DIR}/src/test-serialize.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-set "${HB_SRC_DIR}/src/test-set.cc" "${HB_SRC_DIR}/src/hb-static.cc")
add_hb_internal_test(test-unicode-ranges "${HB_SRC_DIR}/src/test-unicode-ranges.cc")
add_hb_internal_test(test-vector "${HB_SRC_DIR}/src/test-vector.cc" "${HB_SRC_DIR}/src/hb-static.cc")

add_executable(test-shape-subset test_shape_subset.cc)
target_include_directories(test-shape-subset PRIVATE "${HB_SRC_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}/hb_build/src")
target_compile_options(test-shape-subset PRIVATE -UNDEBUG)
target_link_libraries(test-shape-subset PRIVATE harfbuzz harfbuzz-subset)
add_test(NAME test-shape-subset COMMAND test-shape-subset "${HB_TEST_FONT}")
EOF

TEST_FONT=$(find "$SRC_DIR/test" -name "*.ttf" | LC_ALL=C sort | head -n 1)
if [ -z "$TEST_FONT" ]; then
  echo "no bundled .ttf font found in $SRC_DIR/test" >&2
  exit 1
fi

set -- \
  -S "$HARNESS_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="${CC:-cc}" \
  -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DHB_SRC_DIR="$SRC_DIR" \
  -DHB_TEST_FONT="$TEST_FONT"
if command -v ninja >/dev/null 2>&1; then set -- "$@" -G Ninja; fi
if [ -n "${AR:-}" ]; then set -- "$@" -DCMAKE_AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" -DCMAKE_RANLIB="$RANLIB"; fi

cmake "$@"
cmake --build "$BUILD_DIR" -j "$JOBS"
