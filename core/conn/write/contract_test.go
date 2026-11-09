package write_test

import (
	"go/build"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const (
	module     = "github.com/knt048/vedette"
	writerPath = module + "/core/conn/write"
)

// FORBID-1 (response), D-93 (1): the writer is the only way to change a device through a connection, and only the binary may import it
// (tests may, to drive it). Like the host contract (D-87), the walk reads the source tree: no package but cmd/vedette imports the writer
// in its production code, and inside cmd/vedette one file does (the executor of response). The import graph of response and of core
// does not reach it either, so no module can call it by way of a dependency.
func TestContract_FORBID1_OnlyTheBinaryImportsTheWriter(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	fset := gotoken.NewFileSet()
	var importers []string
	scanned := 0
	tops := map[string]bool{}
	// Every directory of the repository that holds Go files, not a list that a new top-level directory would escape (L4).
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (strings.HasPrefix(n, ".") || n == "node_modules" || n == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned++
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		tops[strings.SplitN(rel, "/", 2)[0]] = true
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == writerPath {
				importers = append(importers, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"core", "modules", "cmd", "host", "internal", "content", "scripts"} {
		if !tops[want] {
			t.Fatalf("the scan did not reach %s: %v", want, tops)
		}
	}
	if scanned < 200 {
		t.Fatalf("the scan saw %d files: the walk is broken", scanned)
	}
	if len(importers) != 1 || importers[0] != "cmd/vedette/response.go" {
		t.Fatalf("production files that import the writer: %v; only cmd/vedette/response.go may", importers)
	}
}

// The graph of imports: nothing a module or core is built from reaches the writer, and the binary does.
func TestContract_FORBID1_NoDependencyReachesTheWriter(t *testing.T) {
	t.Parallel()
	ctx := build.Default
	reach := func(start string) map[string]bool {
		seen := map[string]bool{}
		var walk func(pkg string)
		walk = func(pkg string) {
			if seen[pkg] || !strings.HasPrefix(pkg, module) {
				return
			}
			seen[pkg] = true
			bp, err := ctx.ImportDir(filepath.Join("..", "..", "..", strings.TrimPrefix(pkg, module)), 0)
			if err != nil {
				t.Fatalf("%s: %v", pkg, err)
			}
			for _, imp := range bp.Imports {
				walk(imp)
			}
		}
		walk(start)
		return seen
	}
	for _, pkg := range []string{module + "/modules/response", module + "/core/conn", module + "/modules/core", module + "/modules/ai", module + "/core/server"} {
		g := reach(pkg)
		if len(g) < 3 {
			t.Fatalf("%s: walked only %d packages", pkg, len(g))
		}
		if g[writerPath] {
			t.Errorf("%s depends on the writer", pkg)
		}
	}
	if !reach(module + "/cmd/vedette")[writerPath] {
		t.Fatal("the binary does not reach the writer: the check above would pass vacuously")
	}
}
