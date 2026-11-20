package inventory

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

// Every reader of a device's software reads the one line (inv_software): the list, the device page, the export, the names, the
// search, "Do you have it?", the assistant's and MCP's device data. What each source read (inv_software_reading) is read only where
// the line is decided or shown as such: the resolver and the write paths that run it (a function that takes the write transaction),
// the matcher's input (MatchInput: an older second install is matched too), the line read model (softwareline.go: the other readings
// of a line, a person's entry), the self-check, and the export classification of every column. A reader anywhere else would rebuild
// "which version does this device run" its own way. The guard counts such declarations in every Go file of the repository.
func TestGuard_SoftwareReadingsAreReadOnlyThroughTheLine(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	allowed := map[string]bool{ // file, or file:declaration
		"modules/inventory/resolve.go":              true,
		"modules/inventory/softwareline.go":         true,
		"modules/inventory/selfcheck.go":            true,
		"modules/inventory/retention.go":            true, // prunes readings: a write job
		"modules/inventory/wiring.go:matchSoftware": true, // MatchInput
		"modules/core/export_policy.go":             true,
	}
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "node_modules" || n == ".git" || n == "web" || n == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if allowed[rel] {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			name, tx := declName(decl)
			if readsReadings(decl, tx) && !allowed[rel+":"+name] {
				bad = append(bad, rel+":"+name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(bad)
	t.Logf("readers of inv_software_reading outside the line: %d %v", len(bad), bad)
	if len(bad) > 0 {
		t.Fatalf("read the software line (softwareline.go, MatchInput) instead of the readings: %v", bad)
	}
}

// readsReadings says whether a declaration holds a string that names the readings table outside a function that takes the write
// transaction (a write path: the resolver runs in it), the declaration's own or a function literal in it (s.write(func(tx *sql.Tx...))).
func readsReadings(n ast.Node, inTx bool) bool {
	found := false
	ast.Inspect(n, func(c ast.Node) bool {
		switch c := c.(type) {
		case *ast.FuncLit:
			if c != n {
				found = found || readsReadings(c.Body, inTx || takesTx(c.Type))
				return false
			}
		case *ast.BasicLit:
			if !inTx && c.Kind == token.STRING && strings.Contains(c.Value, "inv_software_reading") {
				found = true
			}
		}
		return !found
	})
	return found
}

// takesTx says whether a function takes a *sql.Tx.
func takesTx(ft *ast.FuncType) bool {
	for _, p := range ft.Params.List {
		if s, ok := p.Type.(*ast.StarExpr); ok {
			if sel, ok := s.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Tx" {
				return true
			}
		}
	}
	return false
}

// declName is a declaration's name (a function, or the first name of a const or var block) and whether it is a function that takes
// the write transaction.
func declName(decl ast.Decl) (name string, tx bool) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name, takesTx(d.Type)
	case *ast.GenDecl:
		for _, sp := range d.Specs {
			if v, ok := sp.(*ast.ValueSpec); ok && len(v.Names) > 0 {
				return v.Names[0].Name, false
			}
		}
	}
	return "?", false
}
