package pack

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The worker reads the same index (D-125 (2), D-114 (2)): standard library, internal/jsonstrict and nucleiargv.
func TestLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	t.Parallel()
	assertLeaf(t, []string{"github.com/knt048/vedette/internal/jsonstrict", "github.com/knt048/vedette/modules/scan/nucleiargv"})
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
