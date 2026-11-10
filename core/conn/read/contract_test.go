package read_test

import (
	"go/build"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	module     = "github.com/knt048/vedette"
	writerPath = module + "/core/conn/write"
	readerPath = module + "/core/conn/read"
	internalIn = module + "/core/conn/internal"
)

// importsOf lists the files under dir (relative to the repository root) that import something for which match is true, tests
// included when withTests is set. It reads the source tree, as the writer's contract test does.
func importsOf(t *testing.T, dir string, withTests bool, match func(string) bool) (hits []string, scanned int) {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	fset := gotoken.NewFileSet()
	err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || (!withTests && strings.HasSuffix(p, "_test.go")) {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned++
		for _, imp := range f.Imports {
			if path := strings.Trim(imp.Path.Value, `"`); match(path) {
				rel, _ := filepath.Rel(root, p)
				hits = append(hits, filepath.ToSlash(rel)+" -> "+path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits, scanned
}

// ai INV-14, FORBID-5, D-41: the `ai` module reaches a device only through this reader. No file of it, a test included, imports the
// writer or anything under core/conn/internal (the vault, the dialer), and its import graph does not reach the writer.
func TestContract_AIImportsNeitherTheWriterNorTheInternals(t *testing.T) {
	t.Parallel()
	hits, scanned := importsOf(t, "modules/ai", true, func(p string) bool {
		return p == writerPath || strings.HasPrefix(p, writerPath+"/") || p == internalIn || strings.HasPrefix(p, internalIn+"/")
	})
	if scanned < 5 {
		t.Fatalf("the scan saw %d files of modules/ai: the walk is broken", scanned)
	}
	if len(hits) > 0 {
		t.Fatalf("modules/ai imports what only the binary may hold: %v", hits)
	}
	// Of core/conn the module may import this reader and nothing else: not core/conn itself (its Service holds the credential and the
	// dialer behind methods), not conntest, not cliban.
	others, _ := importsOf(t, "modules/ai", true, func(p string) bool {
		return (p == module+"/core/conn" || strings.HasPrefix(p, module+"/core/conn/")) && p != readerPath
	})
	if len(others) > 0 {
		t.Fatalf("modules/ai imports a core/conn package that is not the reader: %v", others)
	}
}

// ai does not name what holds the credential, the dialer or the connection's turn, nor the Service itself (M3).
func TestContract_AIDoesNotNameTheServiceOrItsKeyedMethods(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`OpenCredential|WriteAccess|LockConn|conn\.Service|conn\.New\b`)
	root := filepath.Join("..", "..", "..", "modules", "ai")
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // a path of the walk over our own source tree
		if err != nil {
			return err
		}
		scanned++
		if m := re.Find(b); m != nil {
			t.Errorf("%s names %s", p, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 5 {
		t.Fatalf("the scan saw %d files of modules/ai", scanned)
	}
}

func TestContract_NothingThatAIReachesReachesTheWriter(t *testing.T) {
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
	for _, pkg := range []string{module + "/modules/ai", readerPath} {
		g := reach(pkg)
		if len(g) < 3 {
			t.Fatalf("%s: walked only %d packages", pkg, len(g))
		}
		if g[writerPath] {
			t.Errorf("%s depends on the writer", pkg)
		}
	}
	if !reach(readerPath)[module+"/core/conn"] {
		t.Fatal("the reader does not reach core/conn: the check above would pass vacuously")
	}
}

// Who may import the reader: the binary, which wires it, and the ai module, which uses it. Not core, not response, not the host.
func TestContract_OnlyAIAndTheBinaryImportTheReader(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"core", "modules", "cmd", "host", "internal"} {
		hits, scanned := importsOf(t, dir, false, func(p string) bool { return p == readerPath })
		if scanned == 0 {
			t.Fatalf("the scan saw nothing under %s", dir)
		}
		for _, h := range hits {
			if !strings.HasPrefix(h, "cmd/vedette/") && !strings.HasPrefix(h, "modules/ai/") {
				t.Errorf("%s: only cmd/vedette and modules/ai may import the reader", h)
			}
		}
	}
}
