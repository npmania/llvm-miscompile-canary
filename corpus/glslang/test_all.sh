#!/bin/sh
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
status=0
for s in \
  reflection.vert \
  reflection.frag \
  reflection.linked \
  badMacroArgs.frag \
  glsl.-D-U.frag \
  glsl.entryPointRename.vert \
  glsl.autosampledtextures.frag \
  glsl.versionOverride.vert \
  glsl.versionOverride.frag \
  glsl.versionOverride.geom \
  glsl.versionOverride.tesc \
  glsl.versionOverride.tese \
  glsl.versionOverride.comp \
  spv.noLocation.vert \
  spv.noBuiltInLoc.vert \
  spv.400.frag.nanclamp \
  hlsl.y-negate-1.vert \
  hlsl.w-recip.frag \
  hlsl.noSemantic.functionality1.comp \
  link.crossStageOptimization
do
  if ! "$script_dir/test_one.sh" "$s"; then
    echo "FAIL_ID: $s"
    status=1
  fi
done

exit "$status"
