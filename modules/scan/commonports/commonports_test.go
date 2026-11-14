package commonports

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The list is fixed and documented (D-229): no port twice, ascending (nmap's -p names them in this order, D-514), about a hundred,
// every number a TCP port.
func TestList(t *testing.T) {
	t.Parallel()
	n := Numbers()
	if len(n) < 80 || len(n) > 110 || !slices.IsSorted(n) || len(slices.Compact(slices.Clone(n))) != len(n) {
		t.Fatalf("%d ports, sorted %v, distinct %d", len(n), slices.IsSorted(n), len(slices.Compact(slices.Clone(n))))
	}
	for _, p := range List {
		if p.Number < 1 || p.Number > 65535 || p.Service == "" {
			t.Errorf("bad entry %+v", p)
		}
	}
}

// The sensor binary links this package through nmapargv: it imports nothing.
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
		if len(af.Imports) != 0 {
			t.Errorf("%s imports something: commonports imports nothing", f)
		}
	}
}
