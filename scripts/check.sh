#!/usr/bin/env bash
# make check — kiểm nhanh, chỉ phần đã đổi so với origin/main (D-62, rules/local-checks.md).
# Đổi file dùng chung (dependency, cấu hình build, web/src/lib, mocks, Makefile…) → chạy `make verify` đầy đủ.
# Giả định OS: macOS hoặc Linux. Windows: chạy trong WSL2 (Makefile chặn Windows gốc).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

base_ref=${CHECK_BASE:-origin/main}
git fetch -q origin main 2>/dev/null || echo "check: could not fetch origin/main; comparing with the local copy"
base=$(git merge-base "$base_ref" HEAD)
changed=$({ git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)

if [ -z "$changed" ]; then
	echo "check: nothing changed against $base_ref"
	exit 0
fi
has() { printf '%s\n' "$changed" | grep -Eq "$1"; }

shared='^(go\.mod|go\.sum|tools/|Makefile|scripts/|\.golangci\.yml|sqlc\.yaml|web/package\.json|web/pnpm-lock\.yaml|web/(vite|vitest|playwright)\.config|web/tsconfig|web/src/lib/|web/src/mocks/|web/src/test/|web/src/(main|App)\.tsx)'
if has "$shared"; then
	echo "check: shared files changed, running the full gate (make verify)"
	exec make verify
fi

ran=0
go_paths='\.go$|^modules/[^/]+/(migrations/|testdata/|MANIFEST\.yaml)|^core/store/queries/|^api/openapi\.json$'
if has "$go_paths"; then
	ran=1
	echo "check: Go"
	go build ./...
	go vet ./...
	if has '^api/openapi\.json$|^core/api/apigen/|^modules/[^/]+/migrations/|^core/store/queries/'; then
		make generate-check
	fi
	# The Go test cache re-runs only packages whose code, dependencies or test files changed.
	go test -race ./...
	go test -race -tags releasetestkeys ./internal/release/... # build with the throwaway release keys (keys_testonly.go)
	make contract lint-go
fi

if has '^web/'; then
	ran=1
	echo "check: web"
	pnpm --dir web install --frozen-lockfile --prefer-offline
	pnpm --dir web exec tsc -b
	pnpm --dir web lint
	# Only the tests that import a changed file (Vite's module graph).
	pnpm --dir web exec vitest run --changed "$base" --passWithNoTests
	if has '^web/src/features/[^/]+/contract\.ts$|^web/scripts/openapi'; then
		make openapi-check
	fi
	# E2E: the spec of each touched feature, plus specs that changed themselves; desktop only.
	specs=""
	for m in $(printf '%s\n' "$changed" | sed -n 's|^web/src/features/\([^/]*\)/.*|\1|p' | sort -u); do
		[ -f "web/e2e/qa/$m.spec.ts" ] && specs="$specs e2e/qa/$m.spec.ts"
	done
	for f in $(printf '%s\n' "$changed" | sed -n 's|^web/\(e2e/.*\.spec\.ts\)$|\1|p'); do
		[ -f "web/$f" ] && specs="$specs $f"
	done
	if [ -n "$specs" ]; then
		# shellcheck disable=SC2086 # word splitting of the spec list is intended
		pnpm --dir web exec playwright test $specs --project=desktop
	fi
fi

if [ "$ran" = 0 ]; then
	echo "check: docs only, no code to check"
fi
make clean
