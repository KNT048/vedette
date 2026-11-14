package nmapargv

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The sensor binary links this package, so its non-test files may import the standard library only: no
// core/store, no database, no other Vedette package (D-113) but core/localnet, core/egressip and modules/scan/commonports, which
// are standard library only themselves (their own tests, D-461, D-514). A standard-library path has no dot in its first element.
var allowedImports = []string{"github.com/knt048/vedette/core/localnet", "github.com/knt048/vedette/core/egressip", "github.com/knt048/vedette/modules/scan/commonports"}

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
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") && !slices.Contains(allowedImports, p) {
				t.Errorf("%s imports %q: only the standard library is allowed in nmapargv", f, p)
			}
		}
	}
}
