package nucleiargv

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The sensor binary links this package (D-125 (2), D-114 (2)): standard library only.
func TestLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	t.Parallel()
	assertLeaf(t, nil)
}

func assertLeaf(t *testing.T, allowed []string) {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && !contains(allowed, p) || p == "database/sql" {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if n == 0 {
		t.Fatal("no source file")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
