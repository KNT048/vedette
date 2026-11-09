#!/usr/bin/env bash
# make dev-api — Go backend (127.0.0.1:8080) + Vite (http://localhost:5173) with the modules in $REAL served by the
# backend and every other module by the mock. Ctrl-C (or either process dying) stops both, children included.
# Assumes macOS or Linux. State lives in .dev/ (git-ignored): vedette.db, vedette.key (created on first start).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
real=${REAL:-core}
port=${WEB_PORT:-5173}
mkdir -p .dev/bin
chmod 700 .dev
pnpm --dir web install --frozen-lockfile
# Built binary instead of `go run`: the process we signal is the server itself, not a go wrapper with an orphanable child.
go build -o .dev/bin/vedette ./cmd/vedette

set -m # each background job gets its own process group, so one kill reaches its whole tree
pids=()
stop() {
	trap '' INT TERM EXIT
	for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
	sleep 1
	for p in "${pids[@]}"; do kill -KILL -- "-$p" 2>/dev/null || true; done
}
trap stop INT TERM EXIT

.dev/bin/vedette -db .dev/vedette.db -key .dev/vedette.key -listen 127.0.0.1:8080 &
pids+=($!)
VITE_API_REAL="$real" pnpm --dir web dev --port "$port" &
pids+=($!)
echo "dev-api: backend http://127.0.0.1:8080, app http://localhost:$port, real modules: $real"
# bash 3.2 on macOS has no `wait -n`: poll until either process is gone
while kill -0 "${pids[0]}" 2>/dev/null && kill -0 "${pids[1]}" 2>/dev/null; do sleep 1; done
