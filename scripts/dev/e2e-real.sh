#!/usr/bin/env bash
# make e2e-real (WP-30, D-170): the browser specs of web/e2e-real/ against the REAL backend with the release GUI embedded in it.
#   1. make webui-dist (the release SPA, mock layer off), 2. go test -c -tags webui of cmd/vedette (the box is TestE2EBox, a test so that
#   later slices can put loopback fakes in the same process), 3. start the box on a temp folder, wait for its ready.json,
#   4. Playwright (desktop) against it, 5. stop everything and remove the temp folder, web/dist and internal/webui/dist on every exit path.
# Variables: SPECS="e2e-real/auth.spec.ts ..." (default: all), E2E_WORKERS (default 2 with 8+ CPUs, else 1),
#            HOLD=1 keeps the box up after the run: then rerun one spec with the two variables the script prints, plus `--no-deps`.
# Heavy job (Chromium + a Go build): two at once at most (rules/local-checks.md). Linux or macOS. Kept out of CI and `make check` (D-63, D-64).
# Two runs at once are safe: the box listens on a random port, everything the run writes is in its own temp folder or its own
# web/test-results/real-<pid> folder, and the one shared place, web/dist and internal/webui/dist (the build, plus pnpm install), is taken
# under a lock only while the GUI is built and compiled into the test binary.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

case "$(uname -s)" in Linux | Darwin) ;; *) echo "e2e-real: Linux or macOS only (on Windows use WSL2)" >&2; exit 1 ;; esac
ncpu=$(getconf _NPROCESSORS_ONLN)
t0=$SECONDS
lap() { printf 'e2e-real: %-34s %4ds\n' "$1" "$((SECONDS - t0))"; t0=$SECONDS; }

# Preflight (rules/local-checks.md): not on a loaded machine (load5 above 2 x CPUs: wait, at most 30 minutes). The two-heavy-jobs limit is the
# machine-wide semaphore of the caller (mac-heavy.sh); runs do not look at each other any more.
for i in $(seq 0 30); do
	load5=$(LC_ALL=C uptime | sed 's/,/ /g; s/.*load averages*: *//' | awk '{print $2}')
	awk -v l="$load5" -v n="$ncpu" 'BEGIN { exit !(l > 2 * n) }' || break
	[ "$i" -lt 30 ] || { echo "e2e-real: load5 $load5 stayed above $((2 * ncpu)) for 30 minutes" >&2; exit 1; }
	echo "e2e-real: load5 $load5 is above $((2 * ncpu)): waiting 60 s ($i/30)" >&2
	sleep 60
done

tmp=$(mktemp -d)
box=
pw=
hold=${HOLD:-}
lock="${TMPDIR:-/tmp}/vedette-e2e-real-build.lock.$(printf '%s' "$PWD" | cksum | cut -d' ' -f1)" # one lock per checkout: dist lives in it
locked=
unlock() { [ -z "$locked" ] || { rm -rf web/dist internal/webui/dist "$lock"; locked=; }; }
out="web/test-results/real-$$" # this run's traces; the shared name would be emptied by the other run
cleanup() {
	rc=$?
	[ -z "$pw" ] || kill -- "-$pw" 2>/dev/null || true # Playwright and the Chromium it started
	if [ -n "$box" ]; then
		kill -TERM -- "-$box" 2>/dev/null || true # the box stops itself on SIGTERM
		for _ in $(seq 1 15); do kill -0 "$box" 2>/dev/null || break; sleep 1; done
		kill -KILL -- "-$box" 2>/dev/null || true
		wait "$box" 2>/dev/null || true
	fi
	# a failed run keeps the box log (the temp folder is removed below): next to the traces, gitignored, removed by make clean
	if [ "$rc" -ne 0 ] && [ -s "$tmp/box/box.log" ]; then
		mkdir -p "$out" && cp "$tmp/box/box.log" "$out/box.log" || true
	fi
	[ "$rc" -ne 0 ] || rm -rf "$out"
	unlock
	rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# One build at a time per checkout: web/dist and internal/webui/dist are fixed paths (mkdir is the atomic lock; a lock older than 30 min is stale).
for _ in $(seq 1 600); do
	mkdir "$lock" 2>/dev/null && { locked=1; break; }
	[ -z "$(find "$lock" -maxdepth 0 -mmin +30 2>/dev/null)" ] || rm -rf "$lock"
	sleep 3
done
[ -n "$locked" ] || { echo "e2e-real: could not take the build lock $lock in 30 minutes" >&2; exit 1; }
# (a satisfied lockfile makes the install a no-op, so the other run's Playwright is not disturbed)
pnpm --dir web install --frozen-lockfile --prefer-offline
pnpm --dir web exec playwright install chromium # idempotent; needs the network the first time only
lap "install (pnpm, chromium)"

make webui-dist
lap "webui-dist (tsc + vite)"
# No -trimpath: opstest finds its fixtures through runtime.Caller. Never into the repository root.
go test -c -tags webui -o "$tmp/box.test" ./cmd/vedette
unlock # the GUI is inside the test binary now (rules/build-artifacts.md); the other run may build
lap "go test -c -tags webui"

mkdir -p "$tmp/box" && chmod 700 "$tmp/box"
# Job control puts each background job in its own process group (Linux and macOS), so cleanup can stop a whole tree.
set -m
(cd cmd/vedette && umask 022 && TMPDIR="$tmp" VEDETTE_E2E_HOST=1 VEDETTE_E2E_DIR="$tmp/box" exec "$tmp/box.test" -test.run '^TestE2EBox$' -test.timeout 0 >"$tmp/box.out" 2>&1) &
box=$!
set +m
for _ in $(seq 1 120); do
	[ -s "$tmp/box/ready.json" ] && break
	kill -0 "$box" 2>/dev/null || { cat "$tmp/box.out" >&2; echo "e2e-real: the box exited before it was ready" >&2; exit 1; }
	sleep 0.5
done
if ! [ -s "$tmp/box/ready.json" ]; then
	echo "e2e-real: the box was not ready in 60 s; tail of box.log:" >&2
	tail -n 40 "$tmp/box/box.log" >&2 || true
	exit 1
fi
lap "box ready"

# The QA password is random per run and lives in the environment only (never argv: ps shows argv).
password=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)
[ "${#password}" -eq 24 ] || { echo "e2e-real: could not read /dev/urandom" >&2; exit 1; }
workers=${E2E_WORKERS:-$([ "$ncpu" -ge 8 ] && echo 2 || echo 1)}
export E2E_BOX="$tmp/box/ready.json" E2E_PASSWORD="$password" E2E_WORKERS="$workers" E2E_OUT="$PWD/$out"

# Two passes (a red parallel test must not skip the global specs and the restore logic in them): pass 1 is setup, seed and parallel; pass 2 is
# the global project alone (--no-deps, the seeded storageState files are in the run folder). The exit code is non-zero when either failed.
status=0
for pass in "--project=parallel" "--project=global --no-deps"; do
	set -m
	# shellcheck disable=SC2086 # SPECS is a list of paths, pass is two words
	pnpm --dir web exec playwright test -c playwright.real.config.ts $pass --pass-with-no-tests ${SPECS:-} &
	pw=$!
	set +m
	wait "$pw" || status=1
	pw=
done
lap "playwright"

if [ -n "$hold" ]; then
	echo "e2e-real: HOLD=1, the box is still up (Ctrl-C stops it). In another terminal, from web/:" >&2
	echo "  E2E_BOX=$E2E_BOX E2E_PASSWORD=<see $tmp/password> E2E_WORKERS=1 pnpm exec playwright test -c playwright.real.config.ts <spec> --no-deps" >&2
	(umask 077 && printf '%s' "$password" >"$tmp/password")
	wait "$box" || true
fi
exit "$status"
