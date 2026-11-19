#!/bin/sh
set -eu

test_id="${1:?usage: test_one.sh <test_id>}"

# resolve transitive ctest DEPENDS so producers run before dependent tests
plan=$(python3 - "$BUILD_DIR" "$test_id" <<'PY'
import json, subprocess, sys

build_dir, target = sys.argv[1], sys.argv[2]
raw = subprocess.check_output(
    ["ctest", "--test-dir", build_dir, "--show-only=json-v1"],
    text=True,
)
deps = {}
for t in json.loads(raw).get("tests", []):
    d = []
    for p in t.get("properties", []):
        if p.get("name") == "DEPENDS":
            v = p.get("value", [])
            d.extend([v] if isinstance(v, str) else v)
    deps[t["name"]] = d

seen = set()
order = []
def walk(name):
    if name in seen:
        return
    seen.add(name)
    for dep in deps.get(name, ()):
        walk(dep)
    order.append(name)

walk(target)
for name in order:
    print(name)
PY
)

printf '%s\n' "$plan" | while IFS= read -r t; do
  [ -n "$t" ] || continue
  escaped=$(printf '%s' "$t" | sed 's/[][\\.^$*+?()|{}]/\\&/g')
  ctest --test-dir "$BUILD_DIR" --output-on-failure --no-tests=error -R "^${escaped}$"
done
