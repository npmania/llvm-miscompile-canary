#!/bin/sh
set -eu

cmd=${1:-}
branch=${2:-}
dir=${3:-}
msg=${4:-}

case "$cmd" in
checkout)
	remote="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
	rc=0
	git ls-remote --exit-code --heads "$remote" "refs/heads/${branch}" >/dev/null || rc=$?
	case "$rc" in
	0)
		git init "$dir"
		git -C "$dir" remote add origin "$remote"
		git -C "$dir" fetch --depth=1 origin "refs/heads/${branch}:refs/heads/${branch}"
		git -C "$dir" checkout "$branch"
		;;
	2)
		git init "$dir"
		git -C "$dir" remote add origin "$remote"
		git -C "$dir" checkout --orphan "$branch"
		;;
	*)
		exit "$rc"
		;;
	esac
	;;
push)
	git -C "$dir" config user.name "Darkglare"
	git -C "$dir" config user.email "361901347+darkglare-bot@users.noreply.github.com"
	git -C "$dir" add -A
	if ! git -C "$dir" diff --cached --quiet; then
		git -C "$dir" commit -m "$msg"
		i=1
		while true; do
			if git -C "$dir" push origin "HEAD:refs/heads/${branch}"; then
				break
			fi
			if [ "$i" -ge 3 ]; then
				exit 1
			fi
			sleep $((i * 5))
			i=$((i + 1))
		done
	fi
	;;
*)
	printf 'usage: %s checkout <branch> <dir> | push <branch> <dir> <msg>\n' "$0" >&2
	exit 1
	;;
esac
