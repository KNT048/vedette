package nucleiargv

import (
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// L6: the sensor binary links this package (D-125 (2), D-114 (2)). Checked on the whole dependency graph (the same
// walk go list -deps does, with go/build, because os/exec is SYS-1's): standard library only, and never a process,
// the network, a database or unsafe of its own.
func TestLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	t.Parallel()
	assertLeaf(t, nil)
}

// forbiddenDeps may not be anywhere in the graph. Not syscall: fmt imports os, which imports it. unsafe is checked on
// the package's own imports (the runtime uses it).
var forbiddenDeps = []string{"os/exec", "net", "net/http", "database/sql", "plugin"}

// localDirs are the module packages a leaf may use, by directory relative to modules/scan/<leaf>.
var localDirs = map[string]string{
	"github.com/knt048/vedette/internal/jsonstrict":     "../../../internal/jsonstrict",
	"github.com/knt048/vedette/modules/scan/nucleiargv": "../nucleiargv",
}

func assertLeaf(t *testing.T, allowed []string) {
	t.Helper()
	seen := map[string]bool{}
	var walk func(dir string)
	walk = func(dir string) {
		p, err := build.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, imp := range p.Imports {
			if seen[imp] {
				continue
			}
			seen[imp] = true
			if slices.Contains(forbiddenDeps, imp) {
				t.Errorf("depends on %s", imp)
			}
			if d, ok := localDirs[imp]; ok && slices.Contains(allowed, imp) {
				walk(d)
				continue
			}
			q, err := build.Import(imp, p.Dir, 0)
			if err != nil || !q.Goroot {
				t.Errorf("depends on %s, which is not the standard library", imp)
				continue
			}
			walk(q.Dir)
		}
	}
	walk(".")
	if len(seen) < 5 {
		t.Fatalf("walked only %d packages", len(seen))
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p := strings.Trim(im.Path.Value, `"`); p == "unsafe" || p == "os/exec" {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
