package apijson_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// otherConverters are the places that still turn their values into generated types with a JSON round trip of their own; each must
// keep its slices non-nil by itself until it moves to Into. Request decoding is not a response.
var otherConverters = []string{
	"modules/core/handlers_schedules.go: decode", // a request into the service's input, not a response
	"modules/inventory/handlers.go: convert",     // to move to Into with its module
	"modules/notify/handlers.go: convert",        // to move to Into with its module
	"modules/reports/handlers.go: body",          // a request into the module's types, not a response
	"core/api/apijson/apijson.go: Into",          // Into itself
}

// Count test of the class "a response with a nil list answers 500": every function in the server code that encodes a value with
// encoding/json and decodes it again into another type (a generated response type) goes through Into, which writes nil slices
// and maps as empty ones. Before: 16 such functions of their own (GET /detection/alerts answered 500 on an empty list); after: 0
// outside the listed exceptions.
func TestEveryJSONRoundTripGoesThroughInto(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, dir := range []string{"modules", "cmd", "core"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "oas" || d.Name() == "testdata" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if ok && fn.Body != nil && roundTrip(fn) && !slices.Contains(otherConverters, rel+": "+fn.Name.Name) {
					found = append(found, rel+": "+fn.Name.Name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) > 0 {
		t.Fatalf("%d JSON round trips into another type outside apijson.Into (a nil slice there answers null where the schema says array):\n%s",
			len(found), strings.Join(found, "\n"))
	}
}

// roundTrip says fn calls json.Marshal and then decodes JSON into a value: an UnmarshalJSON call, or json.Unmarshal in a generic
// function (the shape of a converter into "any generated type").
func roundTrip(fn *ast.FuncDecl) bool {
	var marshal, unmarshalJSON, unmarshal bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, _ := sel.X.(*ast.Ident)
		switch {
		case pkg != nil && pkg.Name == "json" && sel.Sel.Name == "Marshal":
			marshal = true
		case pkg != nil && pkg.Name == "json" && sel.Sel.Name == "Unmarshal":
			unmarshal = true
		case sel.Sel.Name == "UnmarshalJSON":
			unmarshalJSON = true
		}
		return true
	})
	generic := fn.Type.TypeParams != nil && len(fn.Type.TypeParams.List) > 0
	return marshal && (unmarshalJSON || (generic && unmarshal))
}
