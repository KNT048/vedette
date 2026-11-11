#!/usr/bin/env bash
# make check — kiểm nhanh, chỉ phần đã đổi so với origin/main (D-62, rules/local-checks.md).
# Kể cả khi đổi file dùng chung (D-199): bộ đầy đủ chạy trên CI, và merge queue chạy lại nó trên bản ghép với main
# trước khi merge (D-245). Go test chỉ chạy gói có file đổi và gói import trực tiếp chúng (D-251).
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

ran=0
go_paths='\.go$|^(go\.mod|go\.sum|tools/|\.golangci\.yml|sqlc\.yaml)|^modules/[^/]+/(migrations/|testdata/|MANIFEST\.yaml)|^core/store/queries/|^api/openapi\.json$'
if has "$go_paths"; then
	ran=1
	echo "check: Go"
	go build ./...
	go vet ./...
	if has '^api/openapi\.json$|^core/api/apigen/|^modules/[^/]+/migrations/|^core/store/queries/'; then
		make generate-check
	fi
	# Packages with a changed file (migrations, testdata, queries and the API spec count for their package tree),
	# plus the packages that import them directly. CI and the merge queue run every package (D-251).
	dirs=$( {
		printf '%s\n' "$changed" | grep '\.go$' | xargs -n1 dirname 2>/dev/null
		printf '%s\n' "$changed" | sed -En 's#^(modules/[^/]+)/(migrations|testdata)/.*#\1/...#p; s#^(modules/[^/]+)/MANIFEST\.yaml$#\1/...#p'
		has '^core/store/queries/' && echo 'core/store/...'
		has '^api/openapi\.json$' && echo 'core/api/...'
		true # the group's status is its last command's: a false `has` would end the script here (set -e, pipefail)
	} | sort -u)
	pkgs=$(for d in $dirs; do if [ -d "${d%/...}" ]; then go list "./$d" 2>/dev/null || true; fi; done | sort -u)
	if [ -n "$pkgs" ]; then
		rdeps=$(go list -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./... |
			awk -v want="$(printf "%s " $pkgs)" 'BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1 }
				{ for (i = 2; i <= NF; i++) if ($i in w) { print $1; break } }')
		# shellcheck disable=SC2086 # word splitting of the package list is intended
		go test -race $(printf '%s\n' $pkgs $rdeps | sort -u)
	fi
	if has '^(internal/release|modules/host|scripts/release)/'; then
		go test -race -tags releasetestkeys ./internal/release/... # build with the throwaway release keys (keys_testonly.go)
		go test -race -tags releasetestkeys -run 'Pull|Embedded|CommittedVectors' ./modules/host/ # the host's real-vector end-to-end test needs them too
	fi
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

if has '^scripts/dev/'; then
	ran=1
	bash scripts/dev/orphan-reaper-test.sh
fi

if [ "$ran" = 0 ]; then
	if has '^(Makefile|scripts/|\.github/)'; then echo "check: build/CI files only; CI runs the full suite"
	else echo "check: docs only, no code to check"; fi
fi
make clean
