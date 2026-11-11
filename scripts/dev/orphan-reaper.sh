#!/bin/bash
# orphan-reaper — stops orphaned dev/test processes that overload the developer's machine
# (kien, 2026-11-09). Runs every 10 minutes from launchd (macOS) or a systemd user timer /
# cron (Linux): `make reaper-install`. Assumes macOS or Linux; bash 3.2 compatible.
#
# "Orphan" = the TREE is orphaned: from a matching process we walk up through the wrappers
# started for it (pnpm, npm, node, sh... — `pnpm dev` runs vite as a child) to the tree root;
# the tree is an orphan when the root's parent is PID 1 or a systemd --user manager, i.e. the
# shell or agent that started it is gone, so nobody reads its result. The whole tree is stopped
# (children first). Rules (only processes of the current user; age rules judge the root):
#   - test runners (Playwright runner, headless Chromium, vitest, `go test` binaries,
#     golangci-lint, govulncheck): stopped at once;
#   - dev servers (vite dev/preview): stopped when older than VEDETTE_REAPER_SERVER_MIN
#     minutes (default 120). An idle server costs memory, not CPU, and an agent may still be
#     using it, so load does not shorten this.
# Each stop: SIGTERM to the tree, SIGKILL after 5 s. Logged; macOS also shows a notification.
# `--dry-run` only prints what it would stop. VEDETTE_REAPER_ONLY=<regex> (tests only) limits
# victims to trees whose root command line matches it.
set -uf # -f: command lines are split into words below and must never be globbed
# launchd starts jobs with a minimal PATH; gh lives under Homebrew on macOS.
PATH="$PATH:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"

dry=0
[ "${1:-}" = "--dry-run" ] && dry=1
server_min=${VEDETTE_REAPER_SERVER_MIN:-120}
log=${VEDETTE_REAPER_LOG:-$HOME/Library/Logs/vedette-orphan-reaper.log}
[ "$(uname)" = "Linux" ] && log=${VEDETTE_REAPER_LOG:-$HOME/.local/state/vedette-orphan-reaper.log}
mkdir -p "$(dirname "$log")"

if [ "$(uname)" = "Darwin" ]; then
	ncpu=$(sysctl -n hw.ncpu)
	load5=$(sysctl -n vm.loadavg | awk '{print $3}')
else
	ncpu=$(nproc)
	load5=$(awk '{print $2}' /proc/loadavg)
fi

runner='playwright/test/cli\.js|chrome-headless-shell|ms-playwright/chromium|/vitest(\.mjs)?( |$)|vitest/dist|/go-build[0-9]+/b[0-9]+/[^ ]*\.test( |$)|golangci-lint|govulncheck'
server='/vite/bin/vite\.js|/\.bin/vite( |$)|pnpm exec vite'

# etime ([[dd-]hh:]mm:ss) -> minutes
minutes() {
	echo "$1" | awk -F'[-:]' '{
		if (NF == 4) print $1 * 1440 + $2 * 60 + $3
		else if (NF == 3) print $1 * 60 + $2
		else print $1 + 0
	}'
}

# etime -> seconds
secs() {
	echo "$1" | awk -F'[-:]' '{
		if (NF == 4) print $1 * 86400 + $2 * 3600 + $3 * 60 + $4
		else if (NF == 3) print $1 * 3600 + $2 * 60 + $3
		else print $1 * 60 + $2
	}'
}

descendants() {
	local c
	for c in $(pgrep -P "$1" 2>/dev/null); do
		descendants "$c"
		echo "$c"
	done
}

# New GitHub issues for this developer (kien, 2026-11-09: a teammate's request must never wait).
# Notifies once per new open issue with VEDETTE_ISSUE_LABEL (default owner:kien) in VEDETTE_REPO
# (default KNT048/vedette). Needs `gh` signed in; silently skipped otherwise or with VEDETTE_REAPER_ISSUES=0.
check_issues() {
	[ "${VEDETTE_REAPER_ISSUES:-1}" = "1" ] || return 0
	command -v gh >/dev/null 2>&1 || return 0
	local repo label seen list new
	repo=${VEDETTE_REPO:-KNT048/vedette}
	label=${VEDETTE_ISSUE_LABEL:-owner:kien}
	seen="$(dirname "$log")/vedette-issues-seen.txt"
	touch "$seen"
	# perl alarm = a timeout that exists on stock macOS (no coreutils `timeout` there).
	list=$(perl -e 'alarm 20; exec @ARGV' gh issue list -R "$repo" --state open --label "$label" \
		--json number,title --jq '.[] | "\(.number)\t\(.title)"' 2>/dev/null) || return 0
	new=""
	while IFS="$(printf '\t')" read -r num title; do
		[ -n "$num" ] || continue
		grep -qx "$num" "$seen" && continue
		echo "$num" >>"$seen"
		new="$new #$num $title;"
		echo "$(date '+%Y-%m-%d %H:%M:%S') new issue #$num ($label): $title" >>"$log"
	done <<ISSUES
$list
ISSUES
	if [ -n "$new" ] && [ "$(uname)" = "Darwin" ] && [ "${VEDETTE_REAPER_NOTIFY:-1}" = "1" ]; then
		osascript -e "display notification \"$(echo "$new" | tr -d '\042\134' | cut -c1-200)\" with title \"Vedette: new issue for you\"" >/dev/null 2>&1 || true
	fi
}

snap=$(ps -ww -U "$(id -u)" -o pid=,ppid=,etime=,command=)
only=${VEDETTE_REAPER_ONLY:-}

# line of process $1 from the snapshot
pline() { echo "$snap" | awk -v p="$1" '$1 == p { print; exit }'; }

# wrapper = a runner/shell started for the tree (not a login shell, whose argv0 starts with "-")
is_wrapper() {
	local a0=${1%% *}
	case "${a0##*/}" in
	pnpm | npm | npx | yarn | node | sh | bash | dash | zsh | env | tsx) return 0 ;;
	esac
	return 1
}

victims=""
reasons=""
while read -r pid ppid etime cmd; do
	reason=""
	if echo "$cmd" | grep -Eq "$runner"; then
		reason="orphaned test runner"
	elif echo "$cmd" | grep -Eq "$server"; then
		reason="orphaned dev server"
	fi
	[ -n "$reason" ] || continue
	# walk up to the tree root (depth-limited)
	root=$pid rppid=$ppid retime=$etime rcmd=$cmd
	depth=0
	while [ "$rppid" -gt 1 ] && [ $depth -lt 12 ]; do
		line=$(pline "$rppid")
		[ -n "$line" ] || break
		# shellcheck disable=SC2086
		set -- $line
		wpid=$1 wppid=$2 wetime=$3
		shift 3
		wcmd=$*
		is_wrapper "$wcmd" || break
		# started for this tree: a long-lived daemon that merely spawned the child is not a wrapper
		[ $(($(secs "$wetime") - $(secs "$retime"))) -le 60 ] || break
		root=$wpid rppid=$wppid retime=$wetime rcmd=$wcmd
		depth=$((depth + 1))
	done
	if [ "$rppid" != "1" ]; then
		# a systemd --user manager is init for the user's orphans on Linux
		pl=$(pline "$rppid")
		[ -n "$pl" ] || continue
		echo "$pl" | grep -Eq '(^|/)systemd --user' || continue
	fi
	[ -z "$only" ] || echo "$rcmd" | grep -Eq "$only" || continue
	if [ "$reason" = "orphaned dev server" ]; then
		age=$(minutes "$retime")
		[ "$age" -ge "$server_min" ] || continue
		reason="orphaned dev server running ${age} min"
	fi
	case " $victims " in *" $root "*) continue ;; esac
	victims="$victims $root"
	reasons="$reasons
$root | $reason | $(echo "$rcmd" | cut -c1-160)"
done <<EOF
$snap
EOF

[ "$dry" = "1" ] || check_issues

[ -n "$victims" ] || exit 0

stamp=$(date '+%Y-%m-%d %H:%M:%S')
if [ "$dry" = "1" ]; then
	echo "would stop (load5 $load5, $ncpu CPUs):$reasons"
	exit 0
fi

all=""
for p in $victims; do
	# the snapshot may be old (check_issues waits on the network): skip a root whose pid was reused
	cur=$(ps -ww -p "$p" -o ppid=,command= 2>/dev/null) || continue
	[ "$(echo "$cur" | awk '{print $1}')" = "$(pline "$p" | awk '{print $2}')" ] || continue
	all="$all $(descendants "$p" | tr '\n' ' ') $p"
done
all=$(echo "$all" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' ')
# shellcheck disable=SC2086 # word splitting of the PID list is intended
kill -TERM $all 2>/dev/null
i=0
while [ $i -lt 5 ]; do
	alive=""
	for p in $all; do kill -0 "$p" 2>/dev/null && alive="$alive $p"; done
	[ -n "$alive" ] || break
	sleep 1
	i=$((i + 1))
done
# shellcheck disable=SC2086
[ -n "${alive:-}" ] && kill -KILL $alive 2>/dev/null

count=$(echo "$all" | wc -w | tr -d ' ')
{
	echo "$stamp stopped $count processes (load5 $load5, $ncpu CPUs):$reasons"
} >>"$log"
# Keep the log small.
if [ "$(wc -c <"$log")" -gt 1048576 ]; then
	tail -n 2000 "$log" >"$log.tmp" && mv "$log.tmp" "$log"
fi
if [ "$(uname)" = "Darwin" ] && [ "${VEDETTE_REAPER_NOTIFY:-1}" = "1" ]; then
	osascript -e "display notification \"Stopped $count orphaned test/dev processes (load $load5). Log: $log\" with title \"Vedette orphan reaper\"" >/dev/null 2>&1 || true
fi
