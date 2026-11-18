#!/bin/sh
set -eu

cmd=${1:-}
branch=${2:-}
dir=${3:-}
msg=${4:-}

case "$cmd" in
checkout)
	remote="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
	git init "$dir"
	git -C "$dir" remote add origin "$remote"
	if git -C "$dir" fetch --depth=1 origin "refs/heads/${branch}:refs/heads/${branch}" 2>/dev/null; then
		git -C "$dir" checkout "$branch"
	else
		git -C "$dir" checkout --orphan "$branch"
	fi
	;;
push)
	git -C "$dir" config user.name "github-actions[bot]"
	git -C "$dir" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
	git -C "$dir" add -A
	if ! git -C "$dir" diff --cached --quiet; then
		git -C "$dir" commit -m "$msg"
		git -C "$dir" push origin "HEAD:refs/heads/${branch}"
	fi
	;;
*)
	printf 'usage: %s checkout <branch> <dir> | push <branch> <dir> <msg>\n' "$0" >&2
	exit 1
	;;
esac
