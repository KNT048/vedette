package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// repoPackageDirs are the repo-relative directories that hold Go files.
func repoPackageDirs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range walk(t, ".go") {
		seen[filepath.ToSlash(filepath.Dir(f))] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

// A test that reads other packages' source runs on a pull request only if its package is listed in guardPackages.
func TestEveryCrossPackageReaderIsAGuard(t *testing.T) {
	t.Parallel()
	dirs := repoPackageDirs(t)
	found, err := sourceScanners(repoRoot, dirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range slices.Sorted(maps.Keys(found)) {
		if !slices.Contains(guardPackages, d) {
			t.Errorf("%s has a test that reads other packages (%v) but is not in guardPackages (classify.go): a pull request that changes what it reads would not run it", d, found[d][:min(3, len(found[d]))])
		}
	}
	for _, g := range guardPackages {
		if !slices.Contains(dirs, g) {
			t.Errorf("guardPackages names %q, which holds no Go package: remove it", g)
		}
	}
	// The scan must not pass because it found nothing, and it must see the tests the list was written for.
	for _, want := range []string{"modules/core", "core/server", "core/api/apijson", "core/orgtime"} {
		if _, ok := found[want]; !ok {
			t.Errorf("guard is blind: the scan does not see %s", want)
		}
	}
}

// The scan finds a tree walk in a package nobody listed, and ignores a test that reads only its own directory.
func TestSourceScanFindsAFixtureWalker(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("core/a/a.go", "package a\n")
	write("modules/x/x.go", "package x\n")
	write("modules/x/walk_test.go", "package x\nimport (\"io/fs\"; \"path/filepath\"; \"testing\")\nfunc TestW(t *testing.T) { _ = filepath.WalkDir(\"../..\", func(string, fs.DirEntry, error) error { return nil }) }\n")
	write("modules/y/y.go", "package y\n")
	write("modules/y/own_test.go", "package y\nimport (\"path/filepath\"; \"testing\")\nfunc TestO(t *testing.T) { _, _ = filepath.Glob(\"*.go\"); _ = \"../etc\"; _ = \"..\" }\n")
	write("modules/z/z.go", "package z\n")
	write("modules/z/join_test.go", "package z\nimport (\"os\"; \"path/filepath\"; \"testing\")\nfunc TestJ(t *testing.T) { _, _ = os.ReadDir(filepath.Join(\"..\", \"..\", \"core\", \"a\")) }\n")
	got, err := sourceScanners(root, []string{"core/a", "modules/x", "modules/y", "modules/z"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"modules/x", "modules/z"}; !slices.Equal(slices.Sorted(maps.Keys(got)), want) {
		t.Errorf("scanners = %v, want %v", got, want)
	}
}

// A change in modules/response reaches the guards that read it, though neither imports it.
func TestAffectedAlwaysAddsTheGuards(t *testing.T) {
	t.Parallel()
	const m = modulePath + "/"
	dirs := map[string]string{"modules/response": m + "modules/response"}
	for _, g := range guardPackages {
		dirs[g] = m + g
	}
	got, all := Affected([]string{"modules/response/audit.go"}, dirs, nil)
	if all {
		t.Fatal("a .go file inside a package must not run every package")
	}
	for _, want := range []string{m + "modules/response", m + "modules/core", m + "core/server", m + "core/api/apijson"} {
		if !got[want] {
			t.Errorf("Affected misses %s: %v", want, slices.Sorted(maps.Keys(got)))
		}
	}
	if only, _ := Affected([]string{"docs/ROADMAP.md", "web/src/a.ts"}, dirs, nil); len(only) != 0 {
		t.Errorf("a change no Go test reads must run no package, got %v", slices.Sorted(maps.Keys(only)))
	}
}
