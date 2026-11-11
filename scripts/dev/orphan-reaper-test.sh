#!/bin/bash
# Test of orphan-reaper.sh on throwaway process trees (macOS and Linux, bash 3.2).
# Safe by construction: the reaper only runs with --dry-run (it kills nothing), and the test
# signals only PIDs its own fixtures wrote to pid files in a private temp dir — never anything
# found by name. VEDETTE_REAPER_ONLY also limits the reaper's report to that dir.
# Also run by `make verify-go-static`.
set -u
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
mkdir -p "$dir/node_modules/.bin"
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# fixtures; each process writes its own pid (and its sleep's) to $dir/<name>.pid
cat >"$dir/node_modules/.bin/vite" <<'XEOF2'
#!/bin/sh
d=$(cd "$(dirname "$0")/../.." && pwd)
echo $$ >"$d/vite-$1.pid"
sleep 300 &
echo $! >"$d/sleep-$1.pid"
wait
XEOF2
# `pnpm dev`: a launcher that runs vite as a child
printf '#!/bin/sh\nd=$(cd "$(dirname "$0")" && pwd)\necho $$ >"$d/root-$1.pid"\n"$d/node_modules/.bin/vite" "$1"\n' >"$dir/pnpm"
# a generic script (stands in for an agent, tmux pane or watch loop) that runs vite
printf '#!/bin/sh\nd=$(cd "$(dirname "$0")" && pwd)\necho $$ >"$d/root-$1.pid"\n"$d/node_modules/.bin/vite" "$1"\n' >"$dir/generic.sh"
# a generic script that only sleeps
printf '#!/bin/sh\nd=$(cd "$(dirname "$0")" && pwd)\necho $$ >"$d/root-$1.pid"\nsleep 300 &\necho $! >"$d/sleep-$1.pid"\nwait\n' >"$dir/watch.sh"
chmod +x "$dir/node_modules/.bin/vite" "$dir/pnpm" "$dir/generic.sh" "$dir/watch.sh"

cleanup() {
	local f p
	for f in "$dir"/*.pid; do
		[ -f "$f" ] || continue
		p=$(cat "$f")
		case "$p" in '' | *[!0-9]*) continue ;; esac
		kill -KILL "$p" 2>/dev/null
	done
	rm -rf "$dir"
}
trap cleanup EXIT

# start NAME CMD...: orphaned (parent exits, init adopts it) when NAME starts with "o-"
start() {
	local name=$1 script=$2 i=0
	case "$name" in
	o-*) sh -c '"$0" "$1" </dev/null >/dev/null 2>&1 &' "$script" "$name" ;;
	*) "$script" "$name" </dev/null >/dev/null 2>&1 & ;;
	esac
	while [ $i -lt 100 ]; do
		[ -f "$dir/sleep-$name.pid" ] && [ -s "$dir/sleep-$name.pid" ] && return 0
		sleep 0.05
		i=$((i + 1))
	done
	bad "fixture $name did not start"
	return 1
}
pid() { cat "$dir/$1.pid"; }
report() {
	VEDETTE_REAPER_ONLY="$dir" VEDETTE_REAPER_SERVER_MIN=0 VEDETTE_REAPER_ISSUES=0 \
		VEDETTE_REAPER_NOTIFY=0 VEDETTE_REAPER_LOG="$dir/log" bash "${REAPER:-$here/orphan-reaper.sh}" --dry-run 2>&1
}

start o-pnpm "$dir/pnpm" || exit 1 # orphaned pnpm dev -> vite -> sleep
start live "$dir/pnpm" || exit 1 # same tree, parent (this test) alive
start live-gen "$dir/generic.sh" || exit 1 # vite under a live generic script
start o-gen "$dir/generic.sh" || exit 1 # vite under an ORPHANED generic script
start o-watch "$dir/watch.sh" || exit 1 # orphaned generic loop with a sleep

if [ "$(ps -o ppid= -p "$(pid root-o-pnpm)" | tr -d ' ')" != "1" ]; then
	echo "skip: the orphan's parent is not init (subreaper environment)"
	exit 0
fi
out=$(report)
tree=$(echo "$out" | grep '^tree pids:')
echo "$out" | grep -q "^$(pid root-o-pnpm) | orphaned dev server" && ok "orphaned pnpm dev root reported" || bad "orphaned pnpm dev root not reported"
for n in vite-o-pnpm sleep-o-pnpm; do
	case " $tree " in *" $(pid $n) "*) ok "$n in the tree" ;; *) bad "$n missing from the tree" ;; esac
done
# nothing else may be reported: live trees, generic scripts, a plain sleep
for n in root-live vite-live sleep-live root-live-gen vite-live-gen root-o-gen vite-o-gen sleep-o-gen root-o-watch sleep-o-watch; do
	case " $tree " in *" $(pid $n) "*) bad "$n would be stopped" ;; *) ;; esac
done
[ $fail = 0 ] && ok "live trees, generic scripts and a plain sleep are left alone"
exit $fail
