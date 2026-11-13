package localnet

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// nmapargv and nucleiargv import this package, and the sensor binary links them (D-113, D-125 (2)): its non-test files may import
// net/netip and slices only (no net, no process, no other Vedette package), so their leaf tests can let it through.
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
			if p, _ := strconv.Unquote(im.Path.Value); p != "net/netip" && p != "slices" {
				t.Errorf("%s imports %q: only net/netip and slices are allowed in localnet", f, p)
			}
		}
	}
}
