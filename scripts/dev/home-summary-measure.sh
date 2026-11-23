#!/usr/bin/env bash
# What Home costs on a real box (a test box). Measures, on the box's own API:
#   - GET /findings/overview (the one read of Home and the nav badges): N calls, p50 / p95 / max ms and bytes; the first call of the run is shown
#     apart (cold when nothing read it in the last 60 s); COLD=k adds k calls 61 s apart (past the cache TTL: one computation each);
#   - the three lists Home would otherwise fetch to count (GET /findings, /inventory/devices, /notify/incidents), same N, for comparison;
#   - the RSS of the core process before and after the calls (only when run on the box itself: CORE_PID, else `pgrep -xo vedette`).
# Page load: web/e2e/qa/home-load.mjs (Playwright, from any machine that reaches the box).
#
# Usage (on the box, or anywhere for the API part):
#   BASE=https://127.0.0.1:8443 EMAIL=admin@example.com N=50 scripts/dev/home-summary-measure.sh   # the password is asked, or PASSWORD=…
# A viewer account is enough. Nothing is written on the box except the sign-in itself (a session and its audit row).
set -euo pipefail

BASE=${BASE:-https://127.0.0.1:8443}
N=${N:-50}
COLD=${COLD:-0}
: "${EMAIL:?set EMAIL (a viewer account is enough)}"
if [ -z "${PASSWORD:-}" ]; then
	read -rsp "Password for $EMAIL: " PASSWORD
	echo
fi
api="$BASE/api/v1"
work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT
jar="$work/jar"

# The password goes on stdin, never on the command line (ps shows argv); JSON-escaped (backslash, then quote).
json_str() { local v=${1//\\/\\\\}; printf '%s' "${v//\"/\\\"}"; }
printf '{"email":"%s","password":"%s"}' "$(json_str "$EMAIL")" "$(json_str "$PASSWORD")" |
	curl -ksS -m 20 -c "$jar" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "$api/auth/login" >"$work/code"
[ "$(cat "$work/code")" = 200 ] || { echo "sign-in failed: HTTP $(cat "$work/code")" >&2; exit 1; }

rss() { # kB of the core process, or "-" when it is not on this machine
	local pid=${CORE_PID:-$(pgrep -xo vedette 2>/dev/null || true)}
	if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then awk '/^VmRSS:/{print $2}' "/proc/$pid/status"; else echo -; fi
}

# one GET: "<ms> <bytes> <http code>"
get() {
	curl -ksS -m 30 -b "$jar" -o /dev/null -w '%{time_total} %{size_download} %{http_code}\n' "$api$1" | awk '{printf "%.1f %d %s\n", $1 * 1000, $2, $3}'
}

# N calls of one path → "path  p50  p95  max  bytes  non-200"
measure() {
	local path=$1 out="$work/samples"
	: >"$out"
	for _ in $(seq 1 "$N"); do get "$path" >>"$out"; done
	sort -n -k1,1 "$out" | awk -v p="$path" '
		{ ms[NR] = $1; b = $2; if ($3 != 200) bad++ }
		END {
			i50 = int((NR + 1) * 0.50); i95 = int((NR + 1) * 0.95); if (i95 > NR) i95 = NR; if (i95 < 1) i95 = 1; if (i50 < 1) i50 = 1
			printf "| %-22s | %7.1f | %7.1f | %7.1f | %8d | %d |\n", p, ms[i50], ms[i95], ms[NR], b, bad + 0
		}'
}

rss_before=$(rss)
first=$(get /findings/overview)
echo "Home overview, first call of this run: $(echo "$first" | awk '{printf "%s ms, %s bytes, HTTP %s", $1, $2, $3}')"
echo
echo "N=$N calls each, $BASE"
echo
echo "| GET                    | p50 ms  | p95 ms  | max ms  | bytes    | non-200 |"
echo "|------------------------|---------|---------|---------|----------|---------|"
measure /findings/overview
measure /findings
measure /inventory/devices
measure /notify/incidents
rss_after=$(rss)
if [ "$COLD" -gt 0 ]; then
	echo
	echo "Cold (past the 60 s cache, one computation each):"
	for i in $(seq 1 "$COLD"); do
		sleep 61
		echo "  $i: $(get /findings/overview | awk '{printf "%s ms, %s bytes", $1, $2}')"
	done
fi
echo
echo "Core RSS: before ${rss_before} kB, after ${rss_after} kB (\"-\": the core process is not on this machine; set CORE_PID)"
