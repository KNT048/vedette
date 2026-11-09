package sensorlink_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sensor binary links this package (SP-5 checks go list -deps of cmd/vedette-sensor): it must stay standard library plus
// internal/jsonstrict, never the database, the secrets store or core/pki.
func TestOnlyStdlibAndJSONStrict(t *testing.T) {
	t.Parallel()
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
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && p != "github.com/knt048/vedette/internal/jsonstrict" {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if n < 6 {
		t.Fatalf("saw %d source files", n)
	}
	if _, err := os.Stat("server.go"); err != nil {
		t.Fatal(err)
	}
}
