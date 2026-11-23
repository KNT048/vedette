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

// Every reader of a device's software reads the one line (inv_software, INV-50): the list, the device page, the export, the names,
// the search, "Do you have it?", the assistant's and MCP's device data. What each source read (inv_software_reading) is read only
// where the line is decided or shown as such: the resolver and the named write paths that run it, the matcher's input
// (MatchInput: an older second install is matched too), the line read model (softwareline.go: the other readings of a line, a
// person's entry, the sources that feed a device), the self-check, and the export classification of every column. A reader anywhere
// else would rebuild "which version does this device run" its own way, and so would a reader that lists a device's software from
// MatchInput instead of the line. The guard counts such declarations in every Go file of the repository: a declaration that names
// the readings table, that uses a constant of the inventory that does (readingSourcesSQL), or that calls MatchInput.

// readingsFiles may read the readings anywhere in them: the resolver, the line read model, the self-check, the export classification.
var readingsFiles = map[string]bool{
	"modules/inventory/resolve.go":      true,
	"modules/inventory/softwareline.go": true,
	"modules/inventory/selfcheck.go":    true,
	"modules/core/export_policy.go":     true,
}

// readingsDecls are the write paths that read and write the readings (the resolver runs in each), MatchInput's reading, and the
// one reader of which sources feed a device; each by name, so a new function in the same file is a new decision.
var readingsDecls = map[string]bool{
	"modules/inventory/wiring.go:matchSoftware":         true, // MatchInput
	"modules/inventory/devicesquery.go:deviceSources":   true, // which sources feed a device (readingSourcesSQL), no version
	"modules/inventory/lines.go:readingsOf":             true,
	"modules/inventory/lines.go:settleLine":             true,
	"modules/inventory/lines.go:putReading":             true,
	"modules/inventory/software.go:replaceSoftwareTx":   true,
	"modules/inventory/statedos.go:syncStatedOS":        true,
	"modules/inventory/entries.go:editEntryTx":          true,
	"modules/inventory/entries.go:RemoveSoftware":       true,
	"modules/inventory/join.go:foldSoftware":            true,
	"modules/inventory/retention.go:pruneAgentSoftware": true, // drops readings of agents gone silent: a write job
	"modules/inventory/manual.go:dropAgentData":         true, // the agent switch turned off: the agents' readings go
	// one device, many addresses: what a scan read at an address follows the address (merge, split, an address that goes)
	"modules/inventory/join.go:moveAddresses":       true,
	"modules/inventory/addresses.go:unbindAddress":  true,
	"modules/inventory/mergesplit.go:moveInterface": true,
	"modules/inventory/mergesplit.go:MergePreview":  true, // counts the readings a merge moves, no version
	// a person's merge keeps which readings the merged device brought, and the split that undoes it gives them back
	"modules/inventory/mergedfrom.go:rememberMerged":   true,
	"modules/inventory/mergedfrom.go:giveBackSoftware": true,
	// a catalogue update: every reading is identified again from what its source sent and moves to its line (a write path)
	"modules/inventory/reidentify.go:deviceSoftware":  true,
	"modules/inventory/reidentify.go:applyIdentities": true,
	// a self-check (read-only, vedette selfcheck): a finding's matched version must be one its line runs, and the matcher also matches
	// a line's other live readings (an older second install), so the check reads them as the matcher's input does
	"modules/findings/selfcheck.go:catalogueInvariants": true,
}

// matchInputCallers may call MatchInput: the matcher itself, its adapter in the wiring, the report's fixes (the matcher's own fix
// rules over its input), and the declared OS of a device (it asks the matcher's rule which declared row is the OS).
func matchInputCaller(rel, name string) bool {
	return strings.HasPrefix(rel, "modules/findings/") || rel == "cmd/vedette/wiring.go" || rel == "cmd/vedette/reports.go" && name == "Fixes" ||
		rel == "modules/inventory/declared.go" && name == "declaredChoice" || rel == "modules/inventory/wiring.go" && name == "MatchInput"
}

// linePredicates are constants of the line model other readers may use: guessLine says whether a line's value is only nmap's guess
// (no version, no match key); it reads no reading's version.
var linePredicates = map[string]bool{"guessLine": true}

func TestGuard_SoftwareReadingsAreReadOnlyThroughTheLine(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	files := map[string]*ast.File{}
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
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := range readingsDecls { // an allowance names a declaration that exists: a renamed write path is a new decision
		file, name, _ := strings.Cut(k, ":")
		if f := files[file]; f == nil || !slices.ContainsFunc(f.Decls, func(d ast.Decl) bool { return declName(d) == name }) {
			t.Errorf("readingsDecls names %s, which does not exist", k)
		}
	}
	bad := oneLineGuard(files)
	t.Logf("readers of inv_software_reading or of the matcher's input outside the line: %d %v", len(bad), bad)
	if len(bad) > 0 {
		t.Fatalf("read the software line (softwareline.go) instead of the readings or MatchInput: %v", bad)
	}
}

// The guard catches the shapes a new reader would take inside the inventory: a query that reuses a readings constant of the line
// model, a read-only query in a function that takes the write transaction, a new function in a write path's file, and a reader of
// MatchInput; the named write paths and the declared OS stay allowed.
func TestGuard_CatchesNewReaders(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package inventory\n"+src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	files := map[string]*ast.File{
		"modules/inventory/softwareline.go": parse("const readingSourcesSQL = `SELECT 1 FROM inv_software_reading`\nconst guessLine = `(SELECT 1 FROM inv_software_reading)`\nvar shownLine = `x` + guessLine\n"),
		"modules/inventory/reads.go": parse("func reuse(q querier) { q.QueryContext(ctx, readingSourcesSQL) }\n" +
			"func readInTx(tx *sql.Tx) { tx.QueryContext(ctx, `SELECT version FROM inv_software_reading`) }\n" +
			"func listShown(q querier) { q.QueryContext(ctx, `SELECT 1 FROM inv_software s WHERE ` + shownLine) }\n" +
			"func viaMatcher(s *Service) { s.MatchInput(ctx, id) }\n"),
		"modules/inventory/lines.go":    parse("func settleLine(tx *sql.Tx) { tx.QueryContext(ctx, `SELECT 1 FROM inv_software_reading`) }\nfunc newInLines(tx *sql.Tx) { tx.QueryContext(ctx, `SELECT 1 FROM inv_software_reading`) }\n"),
		"modules/inventory/declared.go": parse("func (s *Service) declaredChoice() { s.MatchInput(ctx, id) }\n"),
	}
	got := oneLineGuard(files)
	want := []string{"modules/inventory/lines.go:newInLines", "modules/inventory/reads.go:readInTx", "modules/inventory/reads.go:reuse", "modules/inventory/reads.go:viaMatcher"}
	if !slices.Equal(got, want) {
		t.Fatalf("guard found %v, want %v", got, want)
	}
}

// oneLineGuard lists the declarations (file:name) that read the readings or call MatchInput outside the allowed places.
func oneLineGuard(files map[string]*ast.File) []string {
	tainted := readingConstants(files)
	var bad []string
	for rel, f := range files {
		inv := strings.HasPrefix(rel, "modules/inventory/")
		for _, decl := range f.Decls {
			name := declName(decl)
			reads := !readingsFiles[rel] && !readingsDecls[rel+":"+name] && mentionsReadings(decl, inv, tainted)
			if reads || callsMatchInput(decl) && !matchInputCaller(rel, name) {
				bad = append(bad, rel+":"+name)
			}
		}
	}
	slices.Sort(bad)
	return bad
}

// readingConstants are the package-level constants and variables of the inventory whose text names the readings table, directly or
// through another of them; the line predicates are not.
func readingConstants(files map[string]*ast.File) map[string]bool {
	values := map[string]ast.Node{}
	for rel, f := range files {
		if !strings.HasPrefix(rel, "modules/inventory/") {
			continue
		}
		for _, decl := range f.Decls {
			if g, ok := decl.(*ast.GenDecl); ok {
				for _, sp := range g.Specs {
					if v, ok := sp.(*ast.ValueSpec); ok {
						for _, n := range v.Names {
							values[n.Name] = v
						}
					}
				}
			}
		}
	}
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, v := range values {
			if !tainted[name] && !linePredicates[name] && mentionsReadings(v, true, tainted) {
				tainted[name], changed = true, true
			}
		}
	}
	return tainted
}

// mentionsReadings says whether a node holds a string naming the readings table or (in the inventory) uses a tainted constant.
func mentionsReadings(n ast.Node, inv bool, tainted map[string]bool) bool {
	found := false
	ast.Inspect(n, func(c ast.Node) bool {
		switch c := c.(type) {
		case *ast.BasicLit:
			found = found || c.Kind == token.STRING && strings.Contains(c.Value, "inv_software_reading")
		case *ast.Ident:
			found = found || inv && tainted[c.Name]
		}
		return !found
	})
	return found
}

// callsMatchInput says whether a declaration calls MatchInput or its transaction form matchInput.
func callsMatchInput(decl ast.Decl) bool {
	found := false
	ast.Inspect(decl, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "MatchInput" || sel.Sel.Name == "matchInput") {
			found = true
		}
		return !found
	})
	return found
}

// declName is a declaration's name: a function, or the first name of a const or var block.
func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		for _, sp := range d.Specs {
			if v, ok := sp.(*ast.ValueSpec); ok && len(v.Names) > 0 {
				return v.Names[0].Name
			}
		}
	}
	return "?"
}
