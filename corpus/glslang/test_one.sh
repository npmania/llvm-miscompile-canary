#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"
exe="$BUILD_DIR/StandAlone/glslang"
base_dir="$SRC_DIR/Test/baseResults"
tmp_dir="${TMPDIR:-/tmp}/lmc-glslang-$$"
mkdir -p "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

stage_files() {
  for f in "$@"; do
    cp "$SRC_DIR/Test/$f" "$tmp_dir/$f"
  done
}

run_glslang() {
  rc=0
  (cd "$tmp_dir" && "$exe" "$@") >"$tmp_dir/out.txt" 2>&1 || rc=$?
  case "$rc" in
    [0-6]) return 0 ;;
    *)
      cat "$tmp_dir/out.txt" >&2
      return 1
      ;;
  esac
}

case "$test_id" in
  reflection.vert)
    stage_files reflection.vert
    run_glslang -l -q -C reflection.vert
    diff -b "$base_dir/reflection.vert.out" "$tmp_dir/out.txt"
    ;;
  reflection.frag)
    stage_files reflection.frag
    run_glslang -l -q -C reflection.frag
    diff -b "$base_dir/reflection.frag.out" "$tmp_dir/out.txt"
    ;;
  reflection.linked)
    stage_files reflection.linked.vert reflection.linked.frag
    run_glslang -l -q -C reflection.linked.vert reflection.linked.frag
    diff -b "$base_dir/reflection.linked.out" "$tmp_dir/out.txt"
    ;;
  badMacroArgs.frag)
    stage_files badMacroArgs.frag
    run_glslang badMacroArgs.frag
    diff -b "$base_dir/badMacroArgs.frag.out" "$tmp_dir/out.txt"
    ;;
  glsl.-D-U.frag)
    stage_files glsl.-D-U.frag
    run_glslang -DUNDEFED -UIN_SHADER -DFOO=200 -i -l --U UNDEFED --define-macro 'MUL=FOO*2' glsl.-D-U.frag
    diff -b "$base_dir/glsl.-D-U.frag.out" "$tmp_dir/out.txt"
    ;;
  glsl.entryPointRename.vert)
    stage_files glsl.entryPointRename.vert
    run_glslang -H -e foo --source-entrypoint main glsl.entryPointRename.vert
    diff -b "$base_dir/glsl.entryPointRename.vert.out" "$tmp_dir/out.txt"
    ;;
  glsl.autosampledtextures.frag)
    stage_files glsl.autosampledtextures.frag
    run_glslang --auto-sampled-textures -H -Od -S frag glsl.autosampledtextures.frag
    diff -b "$base_dir/glsl.autosampledtextures.frag.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.vert)
    stage_files glsl.versionOverride.vert
    run_glslang --glsl-version 410 -V -S vert glsl.versionOverride.vert
    diff -b "$base_dir/glsl.versionOverride.vert.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.frag)
    stage_files glsl.versionOverride.frag
    run_glslang --glsl-version 420 -V -S frag glsl.versionOverride.frag
    diff -b "$base_dir/glsl.versionOverride.frag.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.geom)
    stage_files glsl.versionOverride.geom
    run_glslang --glsl-version 430 -V -S geom glsl.versionOverride.geom
    diff -b "$base_dir/glsl.versionOverride.geom.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.tesc)
    stage_files glsl.versionOverride.tesc
    run_glslang --glsl-version 440 -V -S tesc glsl.versionOverride.tesc
    diff -b "$base_dir/glsl.versionOverride.tesc.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.tese)
    stage_files glsl.versionOverride.tese
    run_glslang --glsl-version 450 -V -S tese glsl.versionOverride.tese
    diff -b "$base_dir/glsl.versionOverride.tese.out" "$tmp_dir/out.txt"
    ;;
  glsl.versionOverride.comp)
    stage_files glsl.versionOverride.comp
    run_glslang --glsl-version 460 -V -S comp glsl.versionOverride.comp
    diff -b "$base_dir/glsl.versionOverride.comp.out" "$tmp_dir/out.txt"
    ;;
  spv.noLocation.vert)
    stage_files spv.noLocation.vert
    run_glslang -V -C spv.noLocation.vert
    diff -b "$base_dir/spv.noLocation.vert.out" "$tmp_dir/out.txt"
    ;;
  spv.noBuiltInLoc.vert)
    stage_files spv.noBuiltInLoc.vert
    run_glslang -G -H --aml spv.noBuiltInLoc.vert
    diff -b "$base_dir/spv.noBuiltInLoc.vert.out" "$tmp_dir/out.txt"
    ;;
  spv.400.frag.nanclamp)
    stage_files spv.400.frag
    run_glslang --nan-clamp -H --aml --amb spv.400.frag
    diff -b "$base_dir/spv.400.frag.nanclamp.out" "$tmp_dir/out.txt"
    ;;
  hlsl.y-negate-1.vert)
    stage_files hlsl.y-negate-1.vert
    run_glslang -H -e main -V -D -Od -H -i --iy hlsl.y-negate-1.vert
    diff -b "$base_dir/hlsl.y-negate-1.vert.out" "$tmp_dir/out.txt"
    ;;
  hlsl.w-recip.frag)
    stage_files hlsl.w-recip.frag
    run_glslang -H -e main -V -D -Od -H -i --hlsl-dx-position-w hlsl.w-recip.frag
    diff -b "$base_dir/hlsl.w-recip.frag.out" "$tmp_dir/out.txt"
    ;;
  hlsl.noSemantic.functionality1.comp)
    stage_files hlsl.noSemantic.functionality1.comp
    run_glslang -H -e main -D -Od -fhlsl_functionality1 hlsl.noSemantic.functionality1.comp
    diff -b "$base_dir/hlsl.noSemantic.functionality1.comp.out" "$tmp_dir/out.txt"
    ;;
  link.crossStageOptimization)
    stage_files link.crossStageOptimization.vert link.crossStageOptimization.frag
    run_glslang -V -H --amb --aml -l --lto link.crossStageOptimization.vert link.crossStageOptimization.frag
    diff -b "$base_dir/link.crossStageOptimization.out" "$tmp_dir/out.txt"
    ;;
  *)
    echo "Unknown glslang test id: $test_id" >&2
    exit 2
    ;;
esac
