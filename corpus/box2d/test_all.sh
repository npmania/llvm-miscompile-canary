#!/bin/sh
set -eu

status=0
for s in \
  TableTest \
  BitSetTest \
  ChainTest \
  CollisionTest \
  ContainerTest \
  DeterminismTest \
  DistanceTest \
  DynamicTreeTest \
  IdTest \
  InvalidInputTest \
  LargeWorldTest \
  MathTest \
  MoverTest \
  RecordingKeyframeTest \
  RecordingOutlinerTest \
  RecordingQueryScrubTest \
  RecordingScrubTest \
  RecordingSIMDWidthTest \
  RecordingTest \
  ReStepRaceTest \
  RestitutionTest \
  ShapeTest \
  SnapshotTest \
  SortTest \
  ThreadTest \
  WorldTest
do
  if ! "$BUILD_DIR/bin/test" "$s" >/dev/null; then
    echo "FAIL_ID: $s"
    status=1
  fi
done

exit "$status"
