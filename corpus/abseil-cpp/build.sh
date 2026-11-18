#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

HARNESS_DIR="$BUILD_DIR/harness-src"
rm -rf "$HARNESS_DIR"
mkdir -p "$HARNESS_DIR"

cat >"$HARNESS_DIR/check.h" <<'EOF'
#pragma once
#include <cstdio>
#include <cstdlib>

#define LMC_CHECK(cond)                                                        \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__,   \
                   #cond);                                                     \
      std::abort();                                                            \
    }                                                                          \
  } while (0)
EOF

cat >"$HARNESS_DIR/swiss_table_test.cc" <<'EOF'
#include "check.h"
#include <string>
#include <string_view>
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"

int main() {
  absl::flat_hash_map<std::string, int> m;
  for (int i = 0; i < 2000; ++i) {
    m.emplace("key_" + std::to_string(i), i * 3 + 1);
  }
  LMC_CHECK(m.size() == 2000);
  for (int i = 0; i < 2000; i += 2) {
    LMC_CHECK(m.erase("key_" + std::to_string(i)) == 1);
  }
  LMC_CHECK(m.size() == 1000);
  long long sum = 0;
  for (const auto& kv : m) {
    sum += kv.second;
  }
  LMC_CHECK(sum == 3001000LL);

  absl::flat_hash_set<int> s;
  for (int i = 0; i < 1024; ++i) s.insert(i * 17);
  for (int i = 0; i < 1024; ++i) LMC_CHECK(s.contains(i * 17));
  LMC_CHECK(!s.contains(3));

  absl::node_hash_map<int, std::string> nm;
  for (int i = 0; i < 256; ++i) nm[i] = std::to_string(i * i);
  LMC_CHECK(nm.at(15) == "225");
  return 0;
}
EOF

cat >"$HARNESS_DIR/btree_test.cc" <<'EOF'
#include "check.h"
#include <string>
#include "absl/container/btree_map.h"
#include "absl/container/btree_set.h"

int main() {
  absl::btree_map<int, int> bm;
  for (int i = 1500; i >= 1; --i) {
    bm[(i * 73) % 1501] = i;
  }
  LMC_CHECK(bm.size() == 1500);
  int prev = -1;
  for (const auto& [k, v] : bm) {
    LMC_CHECK(k > prev);
    prev = k;
  }
  auto it = bm.lower_bound(500);
  LMC_CHECK(it != bm.end() && it->first >= 500);
  for (int k = 100; k < 400; ++k) bm.erase(k);
  LMC_CHECK(bm.size() == 1200);

  absl::btree_set<std::string> bs = {"delta", "alpha", "charlie", "bravo"};
  LMC_CHECK(*bs.begin() == "alpha");
  LMC_CHECK(*bs.rbegin() == "delta");
  return 0;
}
EOF

cat >"$HARNESS_DIR/strings_format_test.cc" <<'EOF'
#include "check.h"
#include <string>
#include <vector>
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"

int main() {
  std::string s = absl::StrFormat("%s:%04d:%.3f", "canary", 42, 3.125);
  LMC_CHECK(s == "canary:0042:3.125");

  std::vector<std::string> parts = absl::StrSplit("a,bb,ccc,,d", ',', absl::SkipEmpty());
  LMC_CHECK(parts.size() == 4);
  LMC_CHECK(absl::StrJoin(parts, "-") == "a-bb-ccc-d");

  int iv = 0;
  double dv = 0.0;
  LMC_CHECK(absl::SimpleAtoi("-987654", &iv) && iv == -987654);
  LMC_CHECK(absl::SimpleAtod("1234.5625", &dv) && dv == 1234.5625);

  std::string b64 = absl::Base64Escape(absl::StrCat("hello-", 12345));
  std::string raw;
  LMC_CHECK(absl::Base64Unescape(b64, &raw) && raw == "hello-12345");
  return 0;
}
EOF

cat >"$HARNESS_DIR/hash_crc_test.cc" <<'EOF'
#include "check.h"
#include <string>
#include <tuple>
#include "absl/crc/crc32c.h"
#include "absl/hash/hash.h"

int main() {
  std::string a = "The quick brown fox ";
  std::string b = "jumps over the lazy dog";
  absl::crc32c_t ca = absl::ComputeCrc32c(a);
  absl::crc32c_t cb = absl::ComputeCrc32c(b);
  absl::crc32c_t cab = absl::ComputeCrc32c(a + b);
  LMC_CHECK(absl::ConcatCrc32c(ca, cb, b.size()) == cab);
  LMC_CHECK(absl::ComputeCrc32c("123456789") == absl::crc32c_t{0xe3069283});

  absl::Hash<std::tuple<int, std::string, double>> hasher;
  auto h1 = hasher({7, "llvm", 2.5});
  auto h2 = hasher({7, "llvm", 2.5});
  auto h3 = hasher({8, "llvm", 2.5});
  LMC_CHECK(h1 == h2 && h1 != h3);
  return 0;
}
EOF

cat >"$HARNESS_DIR/int128_bits_test.cc" <<'EOF'
#include "check.h"
#include <cstdint>
#include "absl/numeric/bits.h"
#include "absl/numeric/int128.h"

int main() {
  absl::uint128 hi = absl::MakeUint128(0x0123456789abcdefULL, 0xfedcba9876543210ULL);
  absl::uint128 d = absl::MakeUint128(0, 0x000000010000001bULL);
  absl::uint128 q = hi / d;
  absl::uint128 r = hi % d;
  LMC_CHECK(q * d + r == hi);

  absl::int128 neg = -absl::int128(1000000000000LL) * absl::int128(1000000000000LL);
  LMC_CHECK(neg / absl::int128(-1000000000000LL) == absl::int128(1000000000000LL));

  LMC_CHECK(absl::popcount(0x5555555555555555ULL) == 32);
  LMC_CHECK(absl::countl_zero(uint64_t{1} << 40) == 23);
  LMC_CHECK(absl::bit_width(uint32_t{255}) == 8);
  return 0;
}
EOF

cat >"$HARNESS_DIR/time_status_sync_test.cc" <<'EOF'
#include "check.h"
#include <string>
#include <thread>
#include "absl/container/inlined_vector.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"

static absl::StatusOr<int> parse_pos(int x) {
  if (x <= 0) return absl::InvalidArgumentError("non-positive");
  return x * 2;
}

int main() {
  absl::Duration d = absl::Hours(2) + absl::Minutes(30) + absl::Milliseconds(500);
  LMC_CHECK(absl::ToInt64Milliseconds(d) == 9000500);
  absl::CivilSecond cs(2026, 2, 28, 23, 59, 59);
  cs += 2;
  LMC_CHECK(cs.month() == 3 && cs.day() == 1 && cs.second() == 1);

  auto ok = parse_pos(21);
  LMC_CHECK(ok.ok() && *ok == 42);
  LMC_CHECK(!parse_pos(-1).ok());

  absl::InlinedVector<int, 4> iv = {1, 2, 3, 4, 5, 6};
  LMC_CHECK(iv.size() == 6 && iv[5] == 6);

  absl::Mutex mu;
  int counter = 0;
  std::thread t1([&] { for (int i = 0; i < 500; ++i) { absl::MutexLock l(&mu); ++counter; } });
  std::thread t2([&] { for (int i = 0; i < 500; ++i) { absl::MutexLock l(&mu); ++counter; } });
  t1.join();
  t2.join();
  LMC_CHECK(counter == 1000);
  return 0;
}
EOF

cat >"$HARNESS_DIR/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(absl_canary_harness LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory("${ABSL_SRC_DIR}" absl_build)
enable_testing()

function(add_absl_canary_test name)
  add_executable(${name} ${name}.cc)
  target_link_libraries(${name} PRIVATE ${ARGN})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_absl_canary_test(swiss_table_test absl::flat_hash_map absl::flat_hash_set absl::node_hash_map)
add_absl_canary_test(btree_test absl::btree)
add_absl_canary_test(strings_format_test absl::strings absl::str_format)
add_absl_canary_test(hash_crc_test absl::crc32c absl::hash)
add_absl_canary_test(int128_bits_test absl::int128 absl::numeric)
add_absl_canary_test(time_status_sync_test absl::time absl::status absl::statusor absl::inlined_vector absl::synchronization)
EOF

set -- \
  -S "$HARNESS_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DABSL_SRC_DIR="$SRC_DIR"
if command -v ninja >/dev/null 2>&1; then set -- "$@" -G Ninja; fi
if [ -n "${AR:-}" ]; then set -- "$@" -DCMAKE_AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" -DCMAKE_RANLIB="$RANLIB"; fi

cmake "$@"
cmake --build "$BUILD_DIR" -j "$JOBS"
