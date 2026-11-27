package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// identifyCodeAt is the identification code identifyRules was last set for: the generation, then a hash of the code (comments left
// out). Update it with the generation, after deciding whether the change can give a stored reading another product or train.
const identifyCodeAt = "4:de4f72c9d0c801c1"

// identificationCode is a hash of the code that decides a reading's product and train: every non-test Go file of core/productid,
// and identify, trainOf and installInstance in this package. Comments and layout do not count.
func identificationCode(t *testing.T) string {
	t.Helper()
	h := sha256.New()
	fset := token.NewFileSet()
	add := func(node any) {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, node); err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(b.Bytes())
		_, _ = h.Write([]byte{0})
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "core", "productid", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	n := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution) // no comments
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write([]byte(filepath.Base(name)))
		add(f)
		n++
	}
	if n == 0 {
		t.Fatal("no file of core/productid")
	}
	funcs := map[string]string{"lines.go": "identify", "entries.go": "trainOf", "software.go": "installInstance"}
	for _, file := range slices.Sorted(maps.Keys(funcs)) {
		f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(f.Decls, func(d ast.Decl) bool {
			fn, ok := d.(*ast.FuncDecl)
			return ok && fn.Recv == nil && fn.Name.Name == funcs[file]
		})
		if i < 0 {
			t.Fatalf("no func %s in %s", funcs[file], file)
		}
		add(f.Decls[i])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// A change of the code that identifies a reading must decide whether stored lines are identified again: the catalogue revision
// covers the catalogue's data, identifyRules the code. This fails on any change of that code until identifyCodeAt is updated, so the
// question is asked when the code changes, not found on a box later.
func TestIdentifyRulesFollowTheIdentificationCode(t *testing.T) {
	t.Parallel()
	if got := identifyRules + ":" + identificationCode(t); got != identifyCodeAt {
		t.Fatalf("the identification code changed (now %q, recorded %q). If the change can give a stored reading another product or "+
			"train, raise identifyRules in reidentify.go so the next start identifies the stored lines again; then set identifyCodeAt to "+
			"the generation and the new hash.", got, identifyCodeAt)
	}
}
