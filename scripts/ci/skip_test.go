package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The guard of skip-tests.txt (D-376): every line parses, a flaky line has an issue and is at most 7 days old, and every listed
// test still exists in its package, so a renamed or deleted test cannot leave a stale line behind.
func TestSkipListIsValidAndCurrent(t *testing.T) {
	t.Parallel()
	entries, err := skipEntries(skipTestsTXT)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	for _, e := range entries {
		if e.expired(today) {
			t.Errorf("%s: quarantined since %s, over %d days: fix the test or delete the line", e.name, e.added.Format(time.DateOnly), flakyDays)
		}
		if e.added.After(today.Add(24 * time.Hour)) {
			t.Errorf("%s: added date %s is in the future", e.name, e.added.Format(time.DateOnly))
		}
		files, _ := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(e.pkg), "*_test.go"))
		found := false
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: test, the repo's own test files
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "func "+e.name+"(") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no func %s( in %s/*_test.go: delete or fix the line", e.name, e.name, e.pkg)
		}
	}
}

func TestSkipListRejectsBadLines(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"slow TestA modules/a 2026-11-12",                                          // no reason
		"fast TestA modules/a why 2026-11-12",                                      // kind
		"slow TestA(x) modules/a why 2026-11-12",                                   // name
		"slow TestA ../a why 2026-11-12",                                           // package
		"slow TestA modules/a why 12/11/2026",                                      // date
		"flaky TestA modules/a it flakes 2026-11-12",                               // no issue
		"flaky TestA modules/a https://example.com/1 2026-11-12",                   // not our issue
		"slow TestA modules/a why 2026-11-12\nslow TestA modules/b why 2026-11-12", // twice
	} {
		if _, err := skipEntries(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	txt := "# c\nslow TestA modules/a slow: 9 s wall time; daily run 2026-11-12\n" +
		"flaky TestB modules/b https://github.com/KNT048/vedette/issues/7 2026-11-01\n" +
		"flaky TestC modules/c https://github.com/KNT048/vedette/issues/8 2026-11-10\n"
	var out, warn strings.Builder
	if err := printSkip(txt, time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), &out, &warn); err != nil {
		t.Fatal(err)
	}
	if out.String() != "^(TestA|TestC)$\n" || !strings.Contains(warn.String(), "TestB") {
		t.Fatalf("pattern %q, warning %q: want TestA and TestC skipped, the expired TestB back in", out.String(), warn.String())
	}
}
