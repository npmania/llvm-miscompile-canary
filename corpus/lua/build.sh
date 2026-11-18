#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"

EXTRA_LIBS="-lm"
if [ "$(uname -s)" = "Linux" ]; then
  EXTRA_LIBS="-lm -ldl"
fi

cat >"$BUILD_DIR/Makefile" <<EOF
CC = ${CC:-cc}
AR = ${AR:-ar}
RANLIB = ${RANLIB:-ranlib}
CFLAGS = -std=c99 -DLUA_USE_POSIX -DLUA_USE_DLOPEN -I"$SRC_DIR"
LIBS = $EXTRA_LIBS

CORE_O = lapi.o lauxlib.o lbaselib.o lcode.o lcorolib.o lctype.o ldblib.o \\
	ldebug.o ldo.o ldump.o lfunc.o lgc.o linit.o liolib.o llex.o lmathlib.o \\
	lmem.o loadlib.o lobject.o lopcodes.o loslib.o lparser.o lstate.o \\
	lstring.o lstrlib.o ltable.o ltablib.o ltm.o lundump.o lutf8lib.o lvm.o lzio.o

all: lua

%.o: $SRC_DIR/%.c
	\$(CC) \$(CFLAGS) -c \$< -o \$@

liblua.a: \$(CORE_O)
	rm -f \$@
	\$(AR) rc \$@ \$(CORE_O)
	\$(RANLIB) \$@

lua: lua.o liblua.a
	\$(CC) -o \$@ lua.o liblua.a \$(LIBS)
EOF

make -C "$BUILD_DIR" -j "$JOBS"
