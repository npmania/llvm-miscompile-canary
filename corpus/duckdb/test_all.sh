#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)

set -- \
  "test/sql/aggregate/aggregates/test_avg.test" \
  "test/sql/aggregate/aggregates/test_count.test" \
  "test/sql/aggregate/aggregates/test_kahan_sum.test" \
  "test/sql/aggregate/aggregates/test_approx_quantile.test" \
  "test/sql/filter/test_constant_comparisons.test" \
  "test/sql/join/inner/equality_join_limits.test" \
  "test/sql/join/inner/join_cross_product.test" \
  "test/sql/join/inner/list_join.test" \
  "test/sql/window/test_basic_window.test" \
  "test/sql/window/test_dense_rank.test" \
  "test/sql/cte/cte_bc.test" \
  "test/sql/optimizer/expression/test_comparison_simplification.test" \
  "test/sql/optimizer/expression/test_conjunction_optimization.test" \
  "test/sql/optimizer/expression/test_cse.test" \
  "test/sql/optimizer/plan/plan_struct_projection_pushdown.test" \
  "Basic appender tests"

failed=0
for tc do
  if ! "$script_dir/test_one.sh" "$tc" >/dev/null 2>&1; then
    echo "FAIL_ID: $tc"
    failed=1
  fi
done

exit "$failed"
