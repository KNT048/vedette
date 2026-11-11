package main

import (
	"fmt"
	"slices"
	"testing"
)

func TestDecide(t *testing.T) {
	t.Parallel()
	all := Outputs{Go: true, Web: true, Vuln: true}
	for name, c := range map[string]struct {
		event   string
		changed []string
		diffOK  bool
		want    Outputs
	}{
		"docs only":               {"pull_request", []string{"docs/DECISIONS.md", "docs/plans/x.md"}, true, Outputs{}},
		".ai only":                {"pull_request", []string{".ai/tasks/kien.md", "docs/project-map/lessons.md"}, true, Outputs{}},
		"root markdown":           {"pull_request", []string{"README.md", "SECURITY.md"}, true, Outputs{}},
		"notices (notices-check)": {"pull_request", []string{"THIRD_PARTY_NOTICES.md"}, true, Outputs{Go: true, Vuln: true}},
		"docs a test reads":       {"pull_request", []string{"docs/API_CONVENTIONS.md"}, true, Outputs{Go: true, Vuln: true}},
		"docs spec a test reads":  {"pull_request", []string{"docs/specs/host-api.md"}, true, Outputs{Go: true, Vuln: true}},
		"go only":                 {"pull_request", []string{"core/chain/chain.go", "modules/host/x_test.go"}, true, Outputs{Go: true, Vuln: true}},
		"web only":                {"pull_request", []string{"web/src/features/ai/AiSettings.tsx", "web/pnpm-lock.yaml"}, true, Outputs{Web: true}},
		"web production deps":     {"pull_request", []string{"web/package.json"}, true, all}, // notices-check reads it (go job)
		"web file go reads":       {"pull_request", []string{"web/src/features/core/testdata/keys/ed25519"}, true, all},
		"audit labels file":       {"pull_request", []string{"web/src/locales/en/core.json"}, true, all},
		"openapi":                 {"pull_request", []string{"api/openapi.json"}, true, all},
		"shared data":             {"pull_request", []string{"content/catalog/curated.json"}, true, all},
		"Makefile":                {"pull_request", []string{"Makefile"}, true, all},
		"scripts":                 {"pull_request", []string{"scripts/check.sh"}, true, all},
		"workflow itself":         {"pull_request", []string{".github/workflows/ci.yml"}, true, all},
		"go.mod":                  {"pull_request", []string{"go.mod"}, true, Outputs{Go: true, Vuln: true}},
		"unknown top-level":       {"pull_request", []string{"newdir/file.txt"}, true, all},
		"unknown next to docs":    {"pull_request", []string{"docs/x.md", "brand-new-file"}, true, all},
		// --no-renames turns a rename into delete + add: both ends count.
		"rename web to docs": {"pull_request", []string{"web/src/a.ts", "docs/a.md"}, true, Outputs{Web: true}},
		"rename go to web":   {"pull_request", []string{"core/a.go", "web/src/a.ts"}, true, Outputs{Go: true, Web: true, Vuln: true}},
		"deleted go file":    {"pull_request", []string{"modules/old/old.go"}, true, Outputs{Go: true, Vuln: true}},
		"empty diff":         {"pull_request", nil, true, all},
		"diff failed":        {"pull_request", nil, false, all},
		"push docs only":     {"push", []string{"docs/DECISIONS.md"}, true, all},
		"dispatch":           {"workflow_dispatch", nil, false, all},
		"unknown event":      {"merge_group", []string{"docs/a.md"}, true, all},
		"schedule":           {"schedule", []string{"core/a.go"}, true, Outputs{Vuln: true, Audit: true}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := Decide(c.event, c.changed, c.diffOK); got != c.want {
				t.Errorf("Decide(%q, %v) = %+v, want %+v", c.event, c.changed, got, c.want)
			}
		})
	}
}

func TestShardIsStableDisjointAndComplete(t *testing.T) {
	t.Parallel()
	var pkgs []pkg
	for i := range 40 {
		pkgs = append(pkgs, pkg{fmt.Sprintf("p/%02d", i), int64(i%7) * 1000})
	}
	for _, n := range []int{1, 2, 3, 5} {
		var all []string
		for i := 1; i <= n; i++ {
			s := Shard(pkgs, i, n)
			if !slices.Equal(s, Shard(slices.Clone(pkgs), i, n)) {
				t.Fatalf("n=%d shard %d is not stable", n, i)
			}
			all = append(all, s...)
		}
		slices.Sort(all)
		if len(all) != len(pkgs) || len(slices.Compact(slices.Clone(all))) != len(pkgs) {
			t.Fatalf("n=%d: shards hold %d entries for %d packages (duplicates or gaps)", n, len(all), len(pkgs))
		}
	}
}

func TestShardBalancesByWeight(t *testing.T) {
	t.Parallel()
	pkgs := []pkg{{"a", 100}, {"b", 100}, {"c", 100}, {"d", 1}, {"e", 1}, {"f", 1}}
	for i := 1; i <= 3; i++ {
		if got := Shard(pkgs, i, 3); len(got) != 2 {
			t.Errorf("shard %d = %v, want one heavy and one light package", i, got)
		}
	}
}
