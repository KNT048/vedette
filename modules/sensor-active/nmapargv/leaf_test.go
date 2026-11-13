package nmapargv

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The sensor binary links this package, so its non-test files may import the standard library only: no
// core/store, no database, no other Vedette package (D-113) but core/localnet, which is standard library only itself
// (its own test, D-461). A standard-library path has no dot in its first element.
func TestIsALeaf(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") && p != "github.com/knt048/vedette/core/localnet" {
				t.Errorf("%s imports %q: only the standard library is allowed in nmapargv", f, p)
			}
		}
	}
}
