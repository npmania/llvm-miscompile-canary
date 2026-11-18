#!/bin/sh
set -u

OUT_BIN=${1:-${ALIVE_TV_OUT:-/tmp/alive2-install/bin/alive-tv}}
WORK_DIR=${ALIVE2_WORK_DIR:-/tmp/alive2-build}
ALIVE2_REPO=${ALIVE2_REPO:-https://github.com/AliveToolkit/alive2.git}
ALIVE2_REF=${ALIVE2_REF:-main}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}

warn() {
	printf 'build-alive2: %s\n' "$*" >&2
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

if [ "$(uname -s)" != "Linux" ]; then
	warn "linux only"
	exit 0
fi

for cmd in cmake ninja re2c git; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		warn "missing $cmd"
		exit 0
	fi
done
if [ ! -f /usr/include/z3++.h ] && [ ! -f /usr/local/include/z3++.h ]; then
	warn "z3++.h not found"
	exit 0
fi

LLVM_CMAKE_DIR=""
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

if [ -z "$LLVM_CMAKE_DIR" ] && [ -n "${LLVM_SRC:-}" ] && [ "${BUILD_ALIVE2_LLVM:-0}" = "1" ]; then
	LLVM_BUILD_DIR="$WORK_DIR/llvm-rtti"
	mkdir -p "$LLVM_BUILD_DIR"
	set -- -G Ninja -S "$LLVM_SRC/llvm" -B "$LLVM_BUILD_DIR" \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_ENABLE_ASSERTIONS=ON \
		-DLLVM_ENABLE_RTTI=ON \
		-DLLVM_ENABLE_EH=ON \
		-DLLVM_TARGETS_TO_BUILD="X86;AArch64" \
		-DLLVM_INCLUDE_TESTS=OFF \
		-DLLVM_INCLUDE_BENCHMARKS=OFF \
		-DLLVM_INCLUDE_EXAMPLES=OFF \
		-DLLVM_ENABLE_BINDINGS=OFF
	command -v ld.lld >/dev/null 2>&1 && set -- "$@" -DLLVM_USE_LINKER=lld
	command -v ccache >/dev/null 2>&1 && set -- "$@" -DLLVM_CCACHE_BUILD=ON
	if cmake "$@" &&
		ninja -C "$LLVM_BUILD_DIR" -j "$JOBS" \
			LLVMSupport LLVMCore LLVMIRReader LLVMBitReader LLVMAnalysis \
			LLVMTransformUtils LLVMPasses LLVMTargetParser LLVMMC LLVMBinaryFormat; then
		LLVM_CMAKE_DIR="$LLVM_BUILD_DIR/lib/cmake/llvm"
	else
		warn "llvm rtti build failed"
		exit 0
	fi
fi

if ! has_rtti_llvm "$LLVM_CMAKE_DIR"; then
	warn "RTTI LLVMConfig.cmake not found (stripped snapshots omit LLVM dev headers; set LLVM_DIR or install llvm-dev)"
	exit 0
fi

mkdir -p "$WORK_DIR"
SRC_DIR="$WORK_DIR/alive2-src"
BLD_DIR="$WORK_DIR/alive2-build"
rm -rf "$BLD_DIR"

if [ ! -d "$SRC_DIR/.git" ]; then
	if ! git clone --depth 1 --branch "$ALIVE2_REF" "$ALIVE2_REPO" "$SRC_DIR" >/dev/null 2>&1; then
		warn "clone $ALIVE2_REPO failed"
		exit 0
	fi
fi

set -- -G Ninja -S "$SRC_DIR" -B "$BLD_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_TV=ON \
	-DLLVM_DIR="$LLVM_CMAKE_DIR"
if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
	set -- "$@" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
fi
command -v ccache >/dev/null 2>&1 && set -- "$@" -DCMAKE_CXX_COMPILER_LAUNCHER=ccache

if ! cmake "$@" >/dev/null 2>&1; then
	warn "cmake configure failed"
	exit 0
fi
if ! ninja -C "$BLD_DIR" -j "$JOBS" alive-tv >/dev/null 2>&1; then
	warn "ninja build failed"
	exit 0
fi
if [ ! -x "$BLD_DIR/alive-tv" ]; then
	warn "alive-tv binary missing"
	exit 0
fi

mkdir -p "$(dirname "$OUT_BIN")"
cp "$BLD_DIR/alive-tv" "$OUT_BIN"
chmod +x "$OUT_BIN"
printf '%s\n' "$OUT_BIN"
