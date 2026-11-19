#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REMOTE=${REMOTE:-origin}
DOMAIN=llvm-miscompile-canary.glendalab.com
do_push=0

if [ "${1:-}" = "--push" ]; then
	do_push=1
elif [ "$#" -gt 0 ]; then
	printf 'usage: %s [--push]\n' "$0" >&2
	exit 1
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/lmc-init-branches.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

create_orphan_branch() {
	branch=$1
	msg=$2
	stage_dir=$3

	if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/${branch}"; then
		return 0
	fi

	idx="${tmpdir}/index-${branch}"
	rm -f "$idx"

	(
		cd "$stage_dir"
		find . -type f | LC_ALL=C sort | while IFS= read -r rel; do
			rel=${rel#./}
			blob=$(git -C "$REPO_ROOT" hash-object -w "${stage_dir}/${rel}")
			GIT_INDEX_FILE="$idx" git -C "$REPO_ROOT" update-index --add --cacheinfo "100644,${blob},${rel}"
		done
	)

	tree=$(GIT_INDEX_FILE="$idx" git -C "$REPO_ROOT" write-tree)
	commit=$(git -C "$REPO_ROOT" commit-tree "$tree" -m "$msg")
	git -C "$REPO_ROOT" update-ref "refs/heads/${branch}" "$commit"
}

data_stage="${tmpdir}/data"
mkdir -p "${data_stage}/sweeps" "${data_stage}/incidents"
printf '{}\n' >"${data_stage}/state.json"
: >"${data_stage}/sweeps/.gitkeep"
: >"${data_stage}/incidents/.gitkeep"
create_orphan_branch data "init data branch" "$data_stage"

pages_stage="${tmpdir}/gh-pages"
mkdir -p "$pages_stage"
printf '%s\n' "$DOMAIN" >"${pages_stage}/CNAME"
: >"${pages_stage}/.nojekyll"
cat >"${pages_stage}/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>llvm-miscompile-canary</title>
  <style>:root{color-scheme:light dark}body{margin:0;padding:14px 20px;font:13px/1.45 system-ui,-apple-system,sans-serif}h1{font-size:15px;margin:0 0 8px}</style>
</head>
<body>
  <main>
    <h1>llvm-miscompile-canary</h1>
    <p>No sweeps yet.</p>
  </main>
</body>
</html>
EOF
create_orphan_branch gh-pages "init gh-pages branch" "$pages_stage"

if [ "$do_push" -eq 1 ]; then
	git -C "$REPO_ROOT" push -u "$REMOTE" data gh-pages
fi
