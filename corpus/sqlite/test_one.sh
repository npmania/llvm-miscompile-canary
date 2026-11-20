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
  sql_fts4)
    run_sql_expect "
      CREATE VIRTUAL TABLE docs4 USING fts4(title, body);
      INSERT INTO docs4(docid, title, body) VALUES
        (1, 'middle end', 'loop vectorize scalar evolution gvn'),
        (2, 'backend', 'register allocation instruction scheduling'),
        (3, 'optimizer', 'instcombine loop vectorize licm'),
        (4, 'cleanup', 'loop vectorize dce');
      DELETE FROM docs4 WHERE docid = 4;
      UPDATE docs4 SET body = 'loop vectorize instcombine licm' WHERE docid = 3;
      INSERT INTO docs4(docs4) VALUES('integrity-check');
      SELECT count(*) FROM docs4 WHERE docs4 MATCH '\"loop vectorize\"';
      SELECT docid, offsets(docs4) FROM docs4 WHERE docs4 MATCH '\"loop vectorize\"' AND docid = 3;
    " '2
3|1 0 0 4 1 1 5 9'
    ;;
  sql_upsert_returning)
    run_sql_expect "
      CREATE TABLE kv(k TEXT PRIMARY KEY, v INT NOT NULL, rev INT NOT NULL DEFAULT 1);
      INSERT INTO kv(k, v) VALUES ('a', 10), ('b', 20) RETURNING k, v, rev;
      INSERT INTO kv(k, v) VALUES ('a', 5), ('b', 35), ('c', 30)
        ON CONFLICT(k) DO UPDATE SET v = excluded.v, rev = kv.rev + 1 WHERE excluded.v > kv.v
        RETURNING k, v, rev;
      INSERT INTO kv(k, v) VALUES ('a', 99), ('d', 40)
        ON CONFLICT(k) DO NOTHING RETURNING k, v;
      UPDATE kv SET v = v + 1 WHERE v >= 30 RETURNING k, v;
      DELETE FROM kv WHERE k = 'a' RETURNING k, v, rev;
    " 'a|10|1
b|20|1
b|35|2
c|30|1
d|40
b|36
c|31
d|41
a|10|1'
    ;;
  sql_strict_without_rowid_gen)
    run_sql_expect "
      CREATE TABLE metrics(
        grp TEXT NOT NULL,
        id INT NOT NULL,
        a INT NOT NULL,
        b INT NOT NULL,
        tot INT GENERATED ALWAYS AS (a + b) STORED,
        diff INT GENERATED ALWAYS AS (a - b) VIRTUAL,
        PRIMARY KEY (grp, id)
      ) STRICT, WITHOUT ROWID;
      WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 30)
      INSERT INTO metrics(grp, id, a, b)
      SELECT CASE i % 3 WHEN 0 THEN 'g0' WHEN 1 THEN 'g1' ELSE 'g2' END, i, i * 7, (i * 5) % 19 FROM s;
      CREATE INDEX idx_metrics_tot ON metrics(tot DESC, grp ASC);
      PRAGMA integrity_check;
      SELECT grp, count(*), sum(tot), sum(diff) FROM metrics GROUP BY grp ORDER BY grp;
      SELECT grp, id, tot, diff FROM metrics ORDER BY tot DESC, grp ASC LIMIT 3;
    " 'ok
g0|10|1258|1052
g1|10|1094|936
g2|10|1176|994
g0|30|227|193
g2|29|215|191
g1|28|203|189'
    ;;
  sql_subqueries_setops)
    run_sql_expect "
      CREATE TABLE lhs(k INT PRIMARY KEY, v INT);
      CREATE TABLE rhs(k INT PRIMARY KEY, w INT);
      INSERT INTO lhs VALUES (1, 10), (2, NULL), (3, 30), (4, 40);
      INSERT INTO rhs VALUES (2, 200), (3, 300), (5, 500);
      SELECT coalesce(l.k, r.k), l.v, r.w
      FROM lhs l FULL OUTER JOIN rhs r ON l.k = r.k
      ORDER BY l.v NULLS FIRST, coalesce(l.k, r.k);
      SELECT count(*) FROM lhs l WHERE EXISTS (SELECT 1 FROM rhs r WHERE r.k = l.k AND r.w >= 250);
      SELECT count(*) FROM lhs WHERE k IN (SELECT k FROM rhs);
      SELECT k FROM lhs UNION SELECT k FROM rhs ORDER BY k;
      SELECT k FROM lhs INTERSECT SELECT k FROM rhs ORDER BY k;
      SELECT k FROM lhs EXCEPT SELECT k FROM rhs ORDER BY k;
    " '2||200
5||500
1|10|
3|30|300
4|40|
1
2
1
2
3
4
5
2
3
1
4'
    ;;
  sql_savepoints_rollback)
    run_sql_expect "
      PRAGMA foreign_keys = ON;
      CREATE TABLE parent(id INT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name) > 0));
      CREATE TABLE child(id INT PRIMARY KEY, pid INT NOT NULL REFERENCES parent(id) ON DELETE CASCADE, val INT CHECK(val >= 0));
      INSERT INTO parent VALUES (1, 'p1'), (2, 'p2'), (3, 'p3');
      INSERT INTO child VALUES (10, 1, 5), (11, 1, 7), (20, 2, 9), (30, 3, 11);
      SAVEPOINT sp1;
        INSERT INTO parent VALUES (4, 'p4');
        INSERT INTO child VALUES (40, 4, 13);
        SAVEPOINT sp2;
          DELETE FROM parent WHERE id = 1;
          UPDATE child SET val = val + 100 WHERE pid = 2;
        ROLLBACK TO sp2;
        RELEASE sp2;
        DELETE FROM parent WHERE id = 3;
      RELEASE sp1;
      VACUUM;
      PRAGMA foreign_key_check;
      PRAGMA integrity_check;
      SELECT (SELECT count(*) FROM parent), (SELECT count(*) FROM child), (SELECT sum(val) FROM child);
    " 'ok
3|4|34'
    ;;
  sql_agg_filter_having)
    run_sql_expect "
      CREATE TABLE obs(grp TEXT, v INT, active INT);
      INSERT INTO obs VALUES
        ('a', 10, 1), ('a', 30, 1), ('a', 20, 1), ('a', 90, 0), ('a', 20, 1),
        ('b', 5, 1), ('b', 15, 1), ('b', 25, 1), ('b', 35, 1), ('b', 45, 1),
        ('c', 100, 0);
      SELECT grp,
             count(*) FILTER (WHERE active = 1),
             count(DISTINCT v) FILTER (WHERE active = 1),
             sum(v) FILTER (WHERE active = 1),
             cast(median(v) AS INT),
             group_concat(v, ',' ORDER BY v DESC)
      FROM obs
      GROUP BY grp
      HAVING count(*) FILTER (WHERE active = 1) >= 3
      ORDER BY grp;
    " 'a|4|3|80|20|90,30,20,20,10
b|5|5|125|25|45,35,25,15,5'
    ;;
  sql_jsonb_blob_expr)
    run_sql_expect "
      CREATE TABLE jb(id INT PRIMARY KEY, doc BLOB);
      INSERT INTO jb VALUES (1, jsonb_object('k', jsonb_array(3, 1, 4), 'flag', true, 'drop', 99));
      UPDATE jb SET doc = jsonb_remove(jsonb_set(doc, '$.k[1]', 5, '$.added', 'ok'), '$.drop') WHERE id = 1;
      SELECT json(doc) FROM jb WHERE id = 1;
      SELECT key, value, type FROM jb, json_each(jb.doc, '$.k') ORDER BY key;
      SELECT hex(unhex('4C4C564D')), length(zeroblob(16)), hex(zeroblob(4));
    " '{"k":[3,5,4],"flag":1,"added":"ok"}
0|3|integer
1|5|integer
2|4|integer
4C4C564D|16|00000000'
    ;;
  mptest_crash01)
    "$MPTESTER" "$WORK_TMP/mp1.db" "$SRC_DIR/mptest/crash01.test" --repeat 3 --journalmode WAL
    ;;
  mptest_multiwrite01)
    "$MPTESTER" "$WORK_TMP/mp2.db" "$SRC_DIR/mptest/multiwrite01.test" --repeat 3 --journalmode WAL
    ;;
  mptest_config01)
    "$MPTESTER" "$WORK_TMP/mp3.db" "$SRC_DIR/mptest/config01.test" --repeat 1
    ;;
  mptest_config02)
    "$MPTESTER" "$WORK_TMP/mp4.db" "$SRC_DIR/mptest/config02.test" --repeat 1
    ;;
  *)
    echo "unknown sqlite subtest: $1" >&2
    exit 1
    ;;
esac
