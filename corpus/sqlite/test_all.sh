#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
failed=0
for t in \
  sql_btree_index \
  sql_joins_agg \
  sql_window_cte \
  sql_json_fts5 \
  sql_rtree_triggers \
  sql_fts4 \
  sql_upsert_returning \
  sql_strict_without_rowid_gen \
  sql_subqueries_setops \
  sql_savepoints_rollback \
  sql_agg_filter_having \
  sql_jsonb_blob_expr \
  mptest_crash01 \
  mptest_multiwrite01 \
  mptest_config01 \
  mptest_config02
do
  if ! "$script_dir/test_one.sh" "$t" >/dev/null; then
    echo "FAIL_ID: $t"
    failed=1
  fi
done

exit "$failed"
