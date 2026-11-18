#!/bin/sh
set -eu

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

set -- \
  --disable-amalgamation \
  --disable-shared \
  --enable-fts4 \
  --enable-fts5 \
  --enable-rtree \
  --disable-readline \
  --disable-editline \
  --disable-tcl \
  CC="${CC:-cc}"
if [ -n "${AR:-}" ]; then set -- "$@" AR="$AR"; fi
if [ -n "${RANLIB:-}" ]; then set -- "$@" RANLIB="$RANLIB"; fi

"$SRC_DIR/configure" "$@"
make -C "$BUILD_DIR" -j "$JOBS" sqlite3.h libsqlite3.a mptester

cat >"$BUILD_DIR/sql_runner.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

static int row_cb(void *unused, int ncol, char **vals, char **names) {
  (void)unused;
  (void)names;
  for (int i = 0; i < ncol; ++i) {
    if (i > 0) fputc('|', stdout);
    fputs(vals[i] ? vals[i] : "", stdout);
  }
  fputc('\n', stdout);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <db> <sql>\n", argv[0]);
    return 2;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open(argv[1], &db) != SQLITE_OK) {
    fprintf(stderr, "sqlite3_open failed: %s\n", sqlite3_errmsg(db));
    return 1;
  }
  char *err = NULL;
  int rc = sqlite3_exec(db, argv[2], row_cb, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_exec error (%d): %s\n", rc, err ? err : "");
    sqlite3_free(err);
    sqlite3_close(db);
    return 1;
  }
  sqlite3_close(db);
  return 0;
}
EOF

set -- -lm -lpthread -lz
if [ "$(uname -s)" = "Linux" ]; then set -- "$@" -ldl; fi

"${CC:-cc}" -I"$BUILD_DIR" -c "$BUILD_DIR/sql_runner.c" -o "$BUILD_DIR/sql_runner.o"
"${CC:-cc}" -o "$BUILD_DIR/sql_runner" "$BUILD_DIR/sql_runner.o" "$BUILD_DIR/libsqlite3.a" "$@"
