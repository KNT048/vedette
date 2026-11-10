#!/usr/bin/env bash
# make webui-csp-check (D-149): build core with -tags webui (after make webui-dist), run it on a free loopback port with a temp data folder,
# do the first-run setup through the real API, and drive the interface in headless Chromium (web/scripts/csp-check.mjs); fail on any CSP violation.
# Heavy job (Chromium): one at a time. Linux or macOS. Needs the Chromium of Playwright (`pnpm --dir web e2e:install`).
# On every exit path: the core process and the browser's process group are killed, the temp folder and the generated web/dist and
# internal/webui/dist are removed (rules/build-artifacts.md).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
test -s internal/webui/dist/index.html || { echo "webui-csp-check: internal/webui/dist is missing: run make webui-dist" >&2; exit 1; }
tmp=$(mktemp -d)
pid=
chk=
cleanup() {
	[ -z "$chk" ] || kill -- "-$chk" 2>/dev/null || true # the node script and the Chromium it started
	[ -z "$pid" ] || kill "$pid" 2>/dev/null || true
	[ -z "$pid" ] || wait "$pid" 2>/dev/null || true
	rm -rf "$tmp" web/dist internal/webui/dist
}
trap cleanup EXIT
go build -tags webui -trimpath -o "$tmp/vedette" ./cmd/vedette
port=$((20000 + RANDOM % 20000))
while (echo >"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do port=$((port + 1)); done # a free loopback port
"$tmp/vedette" -db "$tmp/v.db" -key "$tmp/v.key" -honeypot-dir "$tmp/hp" -host-socket "" -listen "127.0.0.1:$port" >"$tmp/core.log" 2>&1 &
pid=$!
for _ in $(seq 1 30); do
	curl -fs --max-time 2 "http://127.0.0.1:$port/" >/dev/null 2>&1 && break
	kill -0 "$pid" 2>/dev/null || { cat "$tmp/core.log" >&2; echo "webui-csp-check: core exited" >&2; exit 1; }
	sleep 1
done
curl -fs --max-time 2 "http://127.0.0.1:$port/" | grep -q '<div id="root"></div>' || { echo "webui-csp-check: GET / is not the interface" >&2; exit 1; }
code=$(grep -o '"setup_code":"[^"]*"' "$tmp/core.log" | head -1 | cut -d'"' -f4)
[ -n "$code" ] || { cat "$tmp/core.log" >&2; echo "webui-csp-check: the core log has no setup code" >&2; exit 1; }
setsid pnpm --dir web exec node scripts/csp-check.mjs "http://127.0.0.1:$port" "$code" &
chk=$!
wait "$chk"
