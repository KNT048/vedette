#!/bin/bash
# Test of orphan-reaper.sh with throwaway process trees (macOS and Linux, bash 3.2).
# Every reaper run is limited with VEDETTE_REAPER_ONLY to this test's temp dir, so a real
# orphan on the developer's machine is never touched. Also run by `make verify-go-static`.
set -u
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
mkdir -p "$dir/node_modules/.bin"
printf '#!/bin/sh\nsleep 300 &\nwait\n' >"$dir/node_modules/.bin/vite"
# `pnpm dev`: a wrapper that runs vite as a child
printf '#!/bin/sh\n"$(dirname "$0")/node_modules/.bin/vite"\n' >"$dir/pnpm"
chmod +x "$dir/node_modules/.bin/vite" "$dir/pnpm"
fail=0
cleanup() {
	local p
	for p in $(pgrep -f "$dir" 2>/dev/null); do
		pkill -KILL -P "$p" 2>/dev/null
		kill -KILL "$p" 2>/dev/null
	done
	rm -rf "$dir"
}
trap cleanup EXIT

ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# tree pids: the wrapper, vite and its sleep
tree_pids() {
	local p c
	for p in $(pgrep -f "$dir" 2>/dev/null); do
		echo "$p"
		for c in $(pgrep -P "$p" 2>/dev/null); do echo "$c"; done
	done | sort -u
}
wait_tree() {
	local i=0
	while [ $i -lt 100 ]; do
		[ "$(pgrep -f "$dir" | wc -l | tr -d ' ')" -ge 2 ] && [ "$(tree_pids | wc -l | tr -d ' ')" -ge 3 ] && return 0
		sleep 0.05
		i=$((i + 1))
	done
	return 1
}
reap() {
	VEDETTE_REAPER_ONLY="$dir" VEDETTE_REAPER_SERVER_MIN=0 VEDETTE_REAPER_ISSUES=0 \
		VEDETTE_REAPER_NOTIFY=0 VEDETTE_REAPER_LOG="$dir/log" bash "$here/orphan-reaper.sh" "$@"
}
alive_any() {
	local p
	for p in "$@"; do kill -0 "$p" 2>/dev/null && return 0; done
	return 1
}

# 1. miss reproduced: `pnpm dev` wrapper reparented to init, its vite child keeps running
sh -c '"$0/pnpm" dev </dev/null >/dev/null 2>&1 &' "$dir"
if ! wait_tree; then bad "tree did not start"; exit 1; fi
pids=$(tree_pids | tr '\n' ' ')
root=$(pgrep -f "$dir/pnpm" | head -1)
rp=$(ps -o ppid= -p "$root" | tr -d ' ')
if [ "$rp" != "1" ]; then
	echo "skip orphan test: wrapper parent is $rp, not init (subreaper environment)"
else
	# shellcheck disable=SC2086
	reap
	i=0
	# shellcheck disable=SC2086
	while alive_any $pids && [ $i -lt 100 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	# shellcheck disable=SC2086
	if alive_any $pids; then bad "orphaned pnpm dev tree still alive"; else ok "orphaned pnpm dev tree stopped"; fi
	grep -q 'stopped .* processes' "$dir/log" 2>/dev/null && grep -q 'orphaned dev server' "$dir/log" && ok "log line written" || bad "log line missing"
fi
cleanup_tree() { pkill -KILL -f "$dir" 2>/dev/null; }
cleanup_tree

# 2. negative: a live tree whose root has a living, non-init parent is never touched
"$dir/pnpm" dev </dev/null >/dev/null 2>&1 &
live=$!
if ! wait_tree; then bad "live tree did not start"; exit 1; fi
pids=$(tree_pids | tr '\n' ' ')
reap
sleep 1
# shellcheck disable=SC2086
for p in $pids; do kill -0 "$p" 2>/dev/null || bad "live tree member $p was killed"; done
[ $fail = 0 ] && ok "live tree untouched"
# shellcheck disable=SC2086
kill $pids $live 2>/dev/null
[ $fail = 0 ] || exit 1
