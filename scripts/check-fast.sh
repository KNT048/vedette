#!/usr/bin/env bash
# make check-fast — the pre-push gate (D-370): only what changed against origin/main, no -race, no reverse dependencies, no
# Playwright, no test of scripts/ci/skip-tests.txt, so it needs no heavy-job slot and takes minutes. CI runs every package, the
# merge queue on the merged tree (D-245, D-365), -race on main and daily, the skip list daily (D-376), and is the merge gate. `make check` (scripts/check.sh) stays for reproducing a red CI locally.
# Assumes macOS or Linux (the Makefile refuses native Windows; use WSL2).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

base_ref=${CHECK_BASE:-origin/main}
git fetch -q origin main 2>/dev/null || echo "check-fast: could not fetch origin/main; comparing with the local copy"
base=$(git merge-base "$base_ref" HEAD)
changed=$({ git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
if [ -z "$changed" ]; then
	echo "check-fast: nothing changed against $base_ref"
	exit 0
fi
has() { printf '%s\n' "$changed" | grep -Eq "$1"; }
start=$SECONDS
ran=0

go_paths='\.go$|^(go\.mod|go\.sum|tools/|\.golangci\.yml|sqlc\.yaml)|^modules/[^/]+/(migrations/|testdata/|MANIFEST\.yaml)|^core/store/queries/|^api/openapi\.json$'
if has "$go_paths"; then
	ran=1
	echo "check-fast: Go"
	# The tests of scripts/ci/skip-tests.txt (slow, quarantined flaky) never run here; CI's daily run has them (D-376).
	skip=$(go run ./scripts/ci skip)
	skip=${skip:-^$} # an empty list: -skip '^$' skips nothing
	go build ./...
	go vet ./... # every package: build skips _test.go files, and another package's tests may use what changed (cached, cheap)
	# The packages with a changed file (migrations, testdata, queries and the API spec count for their package tree).
	dirs=$( {
		printf '%s\n' "$changed" | grep '\.go$' | xargs -n1 dirname 2>/dev/null
		printf '%s\n' "$changed" | sed -En 's#^(modules/[^/]+)/(migrations|testdata)/.*#\1/...#p; s#^(modules/[^/]+)/MANIFEST\.yaml$#\1/...#p'
		has '^core/store/queries/' && echo 'core/store/...'
		has '^api/openapi\.json$' && echo 'core/api/...'
		true # the group's status is its last command's: a false `has` would end the script here (set -e, pipefail)
	} | sort -u)
	pkgs=$(for d in $dirs; do if [ -d "${d%/...}" ]; then go list "./$d" 2>/dev/null || true; fi; done | sort -u)
	if has '^api/openapi\.json$|^core/api/apigen/|^modules/[^/]+/migrations/|^core/store/queries/'; then
		make generate-check
	fi
	if [ -n "$pkgs" ]; then
		# Only issues on lines this branch changed; the whole set of linters, as CI runs them (CI lints the whole repository).
		# golangci-lint takes directories, not import paths.
		pdirs=""
		# shellcheck disable=SC2086 # word splitting of the package list is intended
		for d in $(go list -f '{{.Dir}}' $pkgs); do pdirs="$pdirs ./${d#"$PWD"/}"; done
		# shellcheck disable=SC2086
		go tool -modfile=tools/go.mod golangci-lint run --new-from-rev="$base" $pdirs
		# The changed packages' own tests, contract tests included (TestContract…), without -race: CI runs -race on every package.
		# shellcheck disable=SC2086
		go test -skip "$skip" $pkgs
	fi
	if has '^(internal/release|modules/host|scripts/release)/'; then
		go test -tags releasetestkeys ./internal/release/... # the throwaway release keys (keys_testonly.go)
		go test -tags releasetestkeys -run 'Pull|Embedded|CommittedVectors' ./modules/host/ # the host's real-vector test needs them too
	fi
	if has '^(modules|core)/'; then
		# every module's TestContract…: a core change can break another module's invariant (`make contract` minus the skip list)
		go test ./modules/... -run Contract -skip "$skip"
	fi
fi

if has '^web/'; then
	ran=1
	echo "check-fast: web"
	pnpm --dir web install --frozen-lockfile --prefer-offline
	pnpm --dir web exec tsc -b
	pnpm --dir web lint
	# Only the tests that import a changed file (Vite's module graph).
	pnpm --dir web exec vitest run --changed "$base" --passWithNoTests
	if has '^web/src/features/[^/]+/contract\.ts$|^web/scripts/openapi'; then
		make openapi-check
	fi
fi

if has '^scripts/dev/'; then
	ran=1
	bash scripts/dev/orphan-reaper-test.sh
fi

if [ "$ran" = 0 ]; then
	if has '^(Makefile|scripts/|\.github/)'; then echo "check-fast: build/CI files only; CI runs the full suite"
	else echo "check-fast: docs only, no code to check"; fi
fi
echo "check-fast: done in $((SECONDS - start)) s (CI is the merge gate: every package; -race on main and daily)"
make clean
