#!/bin/sh
set -eu

OUT_BIN=${1:-${ALIVE_TV_OUT:-/tmp/alive2-install/bin/alive-tv}}
WORK_DIR=${ALIVE2_WORK_DIR:-/tmp/alive2-build}
ALIVE2_REPO=${ALIVE2_REPO:-https://github.com/AliveToolkit/alive2.git}
ALIVE2_REF=${ALIVE2_REF:-}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}

die() {
	printf 'build-alive2: %s\n' "$*" >&2
	exit 1
}

has_rtti_llvm() {
	[ -n "${1:-}" ] &&
		[ -f "$1/LLVMConfig.cmake" ] &&
		grep -q 'set(LLVM_ENABLE_RTTI ON)' "$1/LLVMConfig.cmake" 2>/dev/null
}

if [ -x "$OUT_BIN" ]; then
	printf '%s\n' "$OUT_BIN"
	exit 0
fi

[ "$(uname -s)" = "Linux" ] || die "linux only"

for cmd in cmake ninja re2c git; do
	command -v "$cmd" >/dev/null 2>&1 || die "missing $cmd"
done
if [ ! -f /usr/include/z3.h ] && [ ! -f /usr/local/include/z3.h ]; then
	die "z3.h not found"
fi

LLVM_CMAKE_DIR=""
LLVM_BUILD_DIR=""

if [ "${BUILD_ALIVE2_LLVM:-0}" = "1" ]; then
	[ -n "${LLVM_SRC:-}" ] || die "BUILD_ALIVE2_LLVM=1 requires LLVM_SRC"
	[ -f "$LLVM_SRC/llvm/CMakeLists.txt" ] || die "missing $LLVM_SRC/llvm/CMakeLists.txt"
	command -v python3 >/dev/null 2>&1 || die "missing python3"
	LLVM_BUILD_DIR="$WORK_DIR/llvm-rtti"
	mkdir -p "$LLVM_BUILD_DIR"
	set -- -G Ninja -S "$LLVM_SRC/llvm" -B "$LLVM_BUILD_DIR" \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_ENABLE_ASSERTIONS=OFF \
		-DLLVM_ENABLE_RTTI=ON \
		-DLLVM_ENABLE_EH=ON \
		-DLLVM_TARGETS_TO_BUILD="" \
		-DLLVM_INCLUDE_TOOLS=OFF \
		-DLLVM_INCLUDE_TESTS=OFF \
		-DLLVM_INCLUDE_BENCHMARKS=OFF \
		-DLLVM_INCLUDE_EXAMPLES=OFF \
		-DLLVM_INCLUDE_DOCS=OFF \
		-DLLVM_ENABLE_BINDINGS=OFF \
		-DLLVM_ENABLE_OCAMLDOC=OFF \
		-DLLVM_APPEND_VC_REV=OFF
	if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
		set -- "$@" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
	fi
	if command -v ld.lld >/dev/null 2>&1; then
		set -- "$@" -DLLVM_USE_LINKER=lld
	fi
	if command -v ccache >/dev/null 2>&1; then
		set -- "$@" -DLLVM_CCACHE_BUILD=ON
	fi
	cmake "$@" >&2 || die "llvm cmake configure failed"
	LLVM_CMAKE_DIR="$LLVM_BUILD_DIR/lib/cmake/llvm"
else
	if has_rtti_llvm "${LLVM_DIR:-}"; then
		LLVM_CMAKE_DIR=$LLVM_DIR
	elif [ -n "${LLVM_PREFIX:-}" ] && has_rtti_llvm "$LLVM_PREFIX/lib/cmake/llvm"; then
		LLVM_CMAKE_DIR="$LLVM_PREFIX/lib/cmake/llvm"
	elif command -v llvm-config >/dev/null 2>&1; then
		cand=$(llvm-config --cmakedir 2>/dev/null || true)
		if has_rtti_llvm "$cand"; then
			LLVM_CMAKE_DIR=$cand
		fi
	fi
	if [ -z "$LLVM_CMAKE_DIR" ]; then
		for cfg in $(find /usr/lib -maxdepth 5 -path '*/cmake/llvm/LLVMConfig.cmake' 2>/dev/null | sort -r); do
			cand=$(dirname "$cfg")
			if has_rtti_llvm "$cand"; then
				LLVM_CMAKE_DIR=$cand
				break
			fi
		done
	fi
fi

has_rtti_llvm "$LLVM_CMAKE_DIR" || die "RTTI LLVMConfig.cmake not found (set BUILD_ALIVE2_LLVM=1 LLVM_SRC=... or LLVM_DIR=...)"
LLVM_CMAKE_DIR=$(CDPATH='' cd -- "$LLVM_CMAKE_DIR" && pwd)

mkdir -p "$WORK_DIR"
SRC_DIR="$WORK_DIR/alive2-src"
BLD_DIR="$WORK_DIR/alive2-build"
rm -rf "$BLD_DIR"

if [ ! -d "$SRC_DIR/.git" ]; then
	set -- --depth 1
	if [ -n "$ALIVE2_REF" ]; then
		set -- "$@" --branch "$ALIVE2_REF"
	fi
	git clone "$@" "$ALIVE2_REPO" "$SRC_DIR" >&2 || die "clone $ALIVE2_REPO failed"
fi

set -- -G Ninja -S "$SRC_DIR" -B "$BLD_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_LLVM_UTILS=ON \
	-DLLVM_DIR="$LLVM_CMAKE_DIR"
if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
	set -- "$@" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
fi
if command -v ld.lld >/dev/null 2>&1; then
	set -- "$@" -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld
fi
if command -v ccache >/dev/null 2>&1; then
	set -- "$@" -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
fi

cmake "$@" >&2 || die "alive2 cmake configure failed"

if [ -n "$LLVM_BUILD_DIR" ]; then
	llvm_libs=$(ninja -C "$BLD_DIR" -t inputs alive-tv |
		sed -n 's|.*/lib/lib\(LLVM[A-Za-z0-9_]*\)\.a$|\1|p' | sort -u)
	[ -n "$llvm_libs" ] || die "no LLVM libraries found for alive-tv"
	# shellcheck disable=SC2086
	ninja -C "$LLVM_BUILD_DIR" -j "$JOBS" $llvm_libs >&2 || die "llvm rtti build failed"
fi

ninja -C "$BLD_DIR" -j "$JOBS" alive-tv >&2 || die "alive2 ninja build failed"
[ -x "$BLD_DIR/alive-tv" ] || die "alive-tv binary missing"

mkdir -p "$(dirname "$OUT_BIN")"
cp "$BLD_DIR/alive-tv" "$OUT_BIN"
chmod +x "$OUT_BIN"
printf '%s\n' "$OUT_BIN"
