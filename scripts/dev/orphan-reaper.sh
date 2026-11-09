#!/bin/bash
# orphan-reaper — stops orphaned dev/test processes that overload the developer's machine
# (kien, 2026-11-09). Runs every 10 minutes from launchd (macOS) or a systemd user timer /
# cron (Linux): `make reaper-install`. Assumes macOS or Linux; bash 3.2 compatible.
#
# "Orphan" = parent is PID 1: the shell or agent that started it is gone, so nobody reads
# its result. Rules (only processes of the current user):
#   - test runners (Playwright runner, headless Chromium, vitest, `go test` binaries,
#     golangci-lint, govulncheck): stopped at once;
#   - dev servers (vite dev/preview): stopped when older than VEDETTE_REAPER_SERVER_MIN
#     minutes (default 120). An idle server costs memory, not CPU, and an agent may still be
#     using it, so load does not shorten this.
# Each stop: SIGTERM to the process and its children, SIGKILL after 5 s. Logged; macOS
# also shows a notification. `--dry-run` only prints what it would stop.
set -u

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

descendants() {
	local c
	for c in $(pgrep -P "$1" 2>/dev/null); do
		descendants "$c"
		echo "$c"
	done
}

victims=""
reasons=""
while read -r pid ppid etime cmd; do
	[ "$ppid" = "1" ] || continue
	reason=""
	if echo "$cmd" | grep -Eq "$runner"; then
		reason="orphaned test runner"
	elif echo "$cmd" | grep -Eq "$server"; then
		age=$(minutes "$etime")
		if [ "$age" -ge "$server_min" ]; then
			reason="orphaned dev server running ${age} min"
		fi
	fi
	[ -n "$reason" ] || continue
	victims="$victims $pid"
	reasons="$reasons
$pid | $reason | $(echo "$cmd" | cut -c1-160)"
done <<EOF
$(ps -U "$(id -u)" -o pid=,ppid=,etime=,command=)
EOF

[ -n "$victims" ] || exit 0

stamp=$(date '+%Y-%m-%d %H:%M:%S')
if [ "$dry" = "1" ]; then
	echo "would stop (load5 $load5, $ncpu CPUs):$reasons"
	exit 0
fi

all=""
for p in $victims; do
	all="$all $(descendants "$p" | tr '\n' ' ') $p"
done
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
