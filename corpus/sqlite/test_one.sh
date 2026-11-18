#!/bin/sh
set -eu

RUNNER="$BUILD_DIR/sql_runner"
MPTESTER="$BUILD_DIR/mptester"
WORK_TMP="$BUILD_DIR/sqlite-tmp-$$"
mkdir -p "$WORK_TMP"
trap 'rm -rf "$WORK_TMP"' EXIT

run_sql_expect() {
  sql="$1"
  want="$2"
  got=$("$RUNNER" ":memory:" "$sql")
  if [ "$got" != "$want" ]; then
    echo "sqlite output mismatch:" >&2
    echo "  got : $got" >&2
    echo "  want: $want" >&2
    exit 1
  fi
}

case "$1" in
  sql_btree_index)
    run_sql_expect "
      CREATE TABLE kv(k INTEGER PRIMARY KEY, v TEXT NOT NULL, score REAL);
      WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x < 500)
      INSERT INTO kv SELECT x, printf('val-%04d', (x*73)%500), (x*1.25) FROM seq;
      CREATE INDEX idx_kv_v ON kv(v, score);
      DELETE FROM kv WHERE k % 3 = 0;
      UPDATE kv SET score = score + 0.5 WHERE k % 5 = 0;
      PRAGMA integrity_check;
      SELECT count(*), cast(round(sum(score)*100) AS INTEGER) FROM kv WHERE v >= 'val-0100' AND v < 'val-0400';
    " 'ok
201|6272925'
    ;;
  sql_joins_agg)
    run_sql_expect "
      CREATE TABLE dept(id INT PRIMARY KEY, name TEXT);
      CREATE TABLE emp(id INT PRIMARY KEY, dept_id INT, salary INT);
      INSERT INTO dept VALUES (1,'eng'),(2,'ops'),(3,'res');
      WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 120)
      INSERT INTO emp SELECT i, (i%3)+1, 1000 + ((i*37)%250)*10 FROM s;
      SELECT d.name, count(*), sum(e.salary), min(e.salary), max(e.salary)
      FROM dept d JOIN emp e ON d.id = e.dept_id
      GROUP BY d.id, d.name ORDER BY d.id;
    " 'eng|40|95200|1240|3490
ops|40|85600|1050|3310
res|40|90400|1150|3400'
    ;;
  sql_window_cte)
    run_sql_expect "
      WITH RECURSIVE fib(n, a, b) AS (
        SELECT 0, 0, 1
        UNION ALL
        SELECT n+1, b, a+b FROM fib WHERE n < 20
      ),
      ranked AS (
        SELECT n, a,
               sum(a) OVER (ORDER BY n ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS mov3,
               dense_rank() OVER (ORDER BY a % 7) AS dr
        FROM fib
      )
      SELECT count(*), sum(mov3), max(dr) FROM ranked;
    " "21|35419|7"
    ;;
  sql_json_fts5)
    run_sql_expect "
      CREATE VIRTUAL TABLE docs USING fts5(title, body);
      INSERT INTO docs VALUES
        ('llvm optimizer', 'instcombine gvn loop vectorize scalar evolution'),
        ('backend codegen', 'register allocation instruction scheduling peephole'),
        ('middle end', 'loop unroll gvn sroa inline instcombine');
      SELECT count(*) FROM docs WHERE docs MATCH 'instcombine AND gvn';
      SELECT json_extract(json_object('a', json_array(10,20,30), 'ok', true), '$.a[1]');
    " '2
20'
    ;;
  sql_rtree_triggers)
    run_sql_expect "
      CREATE VIRTUAL TABLE boxes USING rtree(id, minX, maxX, minY, maxY);
      CREATE TABLE box_src(id INT PRIMARY KEY, minX REAL, maxX REAL, minY REAL, maxY REAL);
      CREATE TABLE audit(cnt INT);
      INSERT INTO audit VALUES (0);
      CREATE TRIGGER tr_box AFTER INSERT ON box_src BEGIN
        INSERT INTO boxes VALUES (NEW.id, NEW.minX, NEW.maxX, NEW.minY, NEW.maxY);
        UPDATE audit SET cnt = cnt + 1;
      END;
      INSERT INTO box_src VALUES (1, 0.0, 10.0, 0.0, 10.0), (2, 5.0, 15.0, 5.0, 15.0), (3, 20.0, 30.0, 20.0, 30.0);
      SELECT (SELECT cnt FROM audit), count(*) FROM boxes WHERE maxX >= 4.0 AND minX <= 12.0;
    " "3|2"
    ;;
  mptest_crash01)
    "$MPTESTER" "$WORK_TMP/mp1.db" "$SRC_DIR/mptest/crash01.test" --repeat 3 --journalmode WAL
    ;;
  mptest_multiwrite01)
    "$MPTESTER" "$WORK_TMP/mp2.db" "$SRC_DIR/mptest/multiwrite01.test" --repeat 3 --journalmode WAL
    ;;
  *)
    echo "unknown sqlite subtest: $1" >&2
    exit 1
    ;;
esac
