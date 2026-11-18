#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

case "$(uname -s)" in
  Darwin) PLAT_DIR="$SRC_DIR/product-mini/platforms/darwin" ;;
  Linux)  PLAT_DIR="$SRC_DIR/product-mini/platforms/linux" ;;
  *)
    echo "unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
esac

set -- \
  -S "$PLAT_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="${CC:-cc}" \
  -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
  -DCMAKE_ASM_COMPILER="${CC:-cc}" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DWAMR_BUILD_INTERP=1 \
  -DWAMR_BUILD_FAST_INTERP=1 \
  -DWAMR_BUILD_AOT=1 \
  -DWAMR_BUILD_SIMD=0 \
  -DWAMR_BUILD_REF_TYPES=1 \
  -DWAMR_BUILD_BULK_MEMORY=1
if command -v ninja >/dev/null 2>&1; then set -- "$@" -G Ninja; fi
if [ -n "${AR:-}" ]; then set -- "$@" -DCMAKE_AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" -DCMAKE_RANLIB="$RANLIB"; fi

cmake "$@"
cmake --build "$BUILD_DIR" --target iwasm -j "$JOBS"

mkdir -p "$BUILD_DIR/wasm-tests"
python3 - "$BUILD_DIR/wasm-tests" <<'PY'
import os, struct, sys

out_dir = sys.argv[1]

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def sleb(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7f
        n >>= 7
        if (n == 0 and (b & 0x40) == 0) or (n == -1 and (b & 0x40) != 0):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)

def section(sec_id, payload):
    return bytes([sec_id]) + uleb(len(payload)) + payload

def make_single_run_wasm(locals_decl, body_ops):
    # Type 0: () -> ()
    type_sec = section(1, b"\x01\x60\x00\x00")
    func_sec = section(3, b"\x01\x00")
    mem_sec  = section(5, b"\x01\x00\x02")
    exp_payload = (
        b"\x02"
        + bytes([6]) + b"memory\x02\x00"
        + bytes([3]) + b"run\x00\x00"
    )
    exp_sec = section(7, exp_payload)
    fn_body = locals_decl + body_ops + b"\x0b"
    code_sec = section(10, b"\x01" + uleb(len(fn_body)) + fn_body)
    return b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + mem_sec + exp_sec + code_sec

def assert_eq_i32(expected):
    # stack has actual i32; compare ne expected -> if trap
    return b"\x41" + sleb(expected) + b"\x47\x04\x40\x00\x0b"

def assert_eq_i64(expected):
    return b"\x42" + sleb(expected) + b"\x52\x04\x40\x00\x0b"

# i32_bits: loop sum, bit rotations, clz, popcnt, unsigned rem
# sum_{i=1..100} ((i * 2654435761) & 0xffffffff) xor rotl(i, 7)
acc = 0
for i in range(1, 101):
    prod = (i * 0x13579bdf) & 0xffffffff
    rot = ((i << 7) | (i >> 25)) & 0xffffffff
    acc = (acc + (prod ^ rot)) & 0xffffffff
if acc >= 0x80000000:
    acc -= 0x100000000

i32_ops = (
    # locals: 0=i (i32), 1=acc (i32)
    b"\x41\x01\x21\x00"
    b"\x41\x00\x21\x01"
    b"\x03\x40"  # loop
      b"\x20\x01"
      b"\x20\x00\x41" + sleb(0x13579bdf) + b"\x6c"
      b"\x20\x00\x41\x07\x77"
      b"\x73\x6a\x21\x01"
      b"\x20\x00\x41\x01\x6a\x22\x00"
      b"\x41" + sleb(101) + b"\x49\x0d\x00"
    b"\x0b"
    b"\x20\x01" + assert_eq_i32(acc) +
    # popcnt(0x55555555) == 16, clz(0x00010000) == 15, rem_u(1000003, 97) == 72
    b"\x41" + sleb(0x55555555) + b"\x69" + assert_eq_i32(16) +
    b"\x41" + sleb(0x00010000) + b"\x67" + assert_eq_i32(15) +
    b"\x41" + sleb(1000003) + b"\x41" + sleb(97) + b"\x70" + assert_eq_i32(1000003 % 97)
)
open(os.path.join(out_dir, "i32_bits.wasm"), "wb").write(
    make_single_run_wasm(b"\x01\x02\x7f", i32_ops)
)

# i64_arith: 64-bit LCG and signed division
state = 0x123456789abcdef1
for _ in range(64):
    state = ((state * 6364136223846793005) + 1442695040888963407) & 0xffffffffffffffff
s_signed = state - (1 << 64) if state >= (1 << 63) else state
c_mul = 6364136223846793005
c_add = 1442695040888963407
i64_ops = (
    # locals: 0=i (i32), 1=state (i64)
    b"\x41\x00\x21\x00"
    b"\x42" + sleb(0x123456789abcdef1) + b"\x21\x01"
    b"\x03\x40"
      b"\x20\x01\x42" + sleb(c_mul) + b"\x7e\x42" + sleb(c_add) + b"\x7c\x21\x01"
      b"\x20\x00\x41\x01\x6a\x22\x00\x41" + sleb(64) + b"\x49\x0d\x00"
    b"\x0b"
    b"\x20\x01" + assert_eq_i64(s_signed) +
    # i64.div_s(-9223372036854775800, 7)
    b"\x42" + sleb(-9223372036854775800) + b"\x42\x07\x7f"
    + assert_eq_i64(-(9223372036854775800 // 7))
)
open(os.path.join(out_dir, "i64_arith.wasm"), "wb").write(
    make_single_run_wasm(b"\x02\x01\x7f\x01\x7e", i64_ops)
)

# f64_math: IEEE-754 f64 arithmetic, sqrt, ceil, floor, trunc
def f64c(v):
    return b"\x44" + struct.pack("<d", v)

f64_ops = (
    # sqrt(225.0) + floor(3.75) - ceil(-2.25) == 15 + 3 - (-2) == 20.0
    f64c(225.0) + b"\x9f" +
    f64c(3.75) + b"\x9c" + b"\xa0" +
    f64c(-2.25) + b"\x9b" + b"\xa1" +
    f64c(20.0) + b"\x62\x04\x40\x00\x0b" +
    # i64.trunc_f64_s(123456789.875) == 123456789
    f64c(123456789.875) + b"\xb0" + assert_eq_i64(123456789)
)
open(os.path.join(out_dir, "f64_math.wasm"), "wb").write(
    make_single_run_wasm(b"\x00", f64_ops)
)

# linear_mem: memory.fill, memory.copy, unaligned load/store, sign-extending loads
mem_ops = (
    # memory.fill(dst=16, val=0xa5, len=64)
    b"\x41\x10\x41" + sleb(0xa5) + b"\x41" + sleb(64) + b"\xfc\x0b\x00"
    # store i32 0xdeadbeef at unaligned offset 19
    b"\x41\x13\x41" + sleb(-559038737) + b"\x36\x00\x00"
    # memory.copy(dst=256, src=16, len=64)
    b"\x41" + sleb(256) + b"\x41\x10\x41" + sleb(64) + b"\xfc\x0a\x00\x00"
    # load i32 from 259 -> must equal 0xdeadbeef (-559038737)
    b"\x41" + sleb(259) + b"\x28\x00\x00" + assert_eq_i32(-559038737) +
    # i32.load8_s from 256 -> 0xa5 sign-extended == -91
    b"\x41" + sleb(256) + b"\x2c\x00\x00" + assert_eq_i32(-91)
)
open(os.path.join(out_dir, "linear_mem.wasm"), "wb").write(
    make_single_run_wasm(b"\x00", mem_ops)
)

# control_recursion: multi-function module with recursive fib(18) == 2584
type_sec = section(1, b"\x02\x60\x01\x7f\x01\x7f\x60\x00\x00")
func_sec = section(3, b"\x02\x00\x01")
mem_sec  = section(5, b"\x01\x00\x01")
exp_sec  = section(7, b"\x02\x06memory\x02\x00\x03run\x00\x01")
fib_body = (
    b"\x00"
    b"\x20\x00\x41\x02\x49\x04\x7f\x20\x00\x05"
    b"\x20\x00\x41\x01\x6b\x10\x00"
    b"\x20\x00\x41\x02\x6b\x10\x00\x6a\x0b\x0b"
)
run_body = b"\x00\x41\x12\x10\x00" + assert_eq_i32(2584) + b"\x0b"
code_sec = section(10, b"\x02" + uleb(len(fib_body)) + fib_body + uleb(len(run_body)) + run_body)
open(os.path.join(out_dir, "control_recursion.wasm"), "wb").write(
    b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + mem_sec + exp_sec + code_sec
)
PY
