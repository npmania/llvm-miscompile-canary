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
  "Basic appender tests" \
  "test/sql/types/decimal/decimal_arithmetic.test" \
  "test/sql/types/hugeint/hugeint_multiply.test" \
  "test/sql/types/hugeint/test_hugeint_bitwise.test" \
  "test/sql/types/bit/test_bit_bitwise_operations.test" \
  "test/sql/types/nested/struct/test_struct.test" \
  "test/sql/cast/string_to_integer_decimal_cast.test" \
  "test/sql/overflow/bigint_overflow.test" \
  "test/sql/order/test_order_by.test" \
  "test/sql/order/test_nulls_first.test" \
  "test/sql/topn/test_top_n.test" \
  "test/sql/subquery/scalar/test_correlated_subquery.test" \
  "test/sql/subquery/any_all/test_correlated_any_all.test" \
  "test/sql/subquery/exists/test_correlated_exists.test" \
  "test/sql/setops/test_setops.test" \
  "test/sql/join/left_outer/test_left_join_filter_pushdown.test" \
  "test/sql/join/semianti/antijoin.test" \
  "test/sql/join/asof/test_asof_join_integers.test" \
  "test/sql/function/string/regex_extract.test" \
  "test/sql/function/numeric/test_floor_ceil.test" \
  "test/sql/aggregate/grouping_sets/rollup.test"

failed=0
for tc do
  if ! "$script_dir/test_one.sh" "$tc" >/dev/null 2>&1; then
    echo "FAIL_ID: $tc"
    failed=1
  fi
done

exit "$failed"
