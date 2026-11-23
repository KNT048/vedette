package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// freeTextField is a Go field that holds free text a person or the code wrote for people: a note (TriggerNote too), an evidence
// sentence, an event's detail.
var freeTextField = regexp.MustCompile(`^(?:\w*Note|Notes|Evidence|Detail|Details)$`)

// freeTextSQL is SQL that decides from a free-text column (note, trigger_note, notes, evidence, detail): a LIKE, a GLOB, an
// equality or an IN list against a literal, or instr/substr of one. It is matched on each whole string literal, so a condition split
// across the lines of a query is seen.
var freeTextSQL = regexp.MustCompile(`(?i)\b\w*(?:note|notes|evidence|detail|details)\s+(?:NOT\s+)?(?:LIKE|GLOB|IN\s*\(\s*')|` +
	`\b\w*(?:note|notes|evidence|detail|details)\s*(?:=|==|<>|!=)\s*'|\b(?:instr|substr)\s*\(\s*[\w.]*(?:note|notes|evidence|detail|details)\b`)

// textTests are the calls that decide from a string: a string test of package strings or bytes, or a regular expression's match.
var textTests = []string{"HasPrefix", "HasSuffix", "Contains", "ContainsAny", "ContainsRune", "EqualFold", "Index", "IndexAny",
	"LastIndex", "Cut", "CutPrefix", "CutSuffix", "Count", "MatchString", "Match", "FindString", "FindStringSubmatch", "FindStringIndex",
	"FindAllString"}

// textCopies are the calls whose result is still the text of their argument (a case or space change, a pointer read).
var textCopies = []string{"ToLower", "ToUpper", "TrimSpace", "Trim", "TrimPrefix", "TrimSuffix", "TrimLeft", "TrimRight", "string",
	"deref", "Deref", "derefString", "String"}

// freeTextUse is one place that decides from free text: its line, the declaration it is in, and what it does.
type freeTextUse struct {
	line int
	decl string
	what string
}

// freeTextUses are the places in one Go source file that decide from free text: in Go, a string test or regular-expression match of
// a free-text field (directly, through a case or space change, or through a local variable that holds it), a comparison or switch
// of one against a string literal; in SQL, a string literal with a condition on a free-text column.
func freeTextUses(path string, src []byte) ([]freeTextUse, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var uses []freeTextUse
	for _, d := range f.Decls {
		name := declName(d)
		held := map[string]bool{} // local variables that hold free text
		var text func(e ast.Expr) bool
		text = func(e ast.Expr) bool {
			switch x := e.(type) {
			case *ast.SelectorExpr:
				return freeTextField.MatchString(x.Sel.Name)
			case *ast.Ident:
				return held[x.Name]
			case *ast.ParenExpr:
				return text(x.X)
			case *ast.StarExpr:
				return text(x.X)
			case *ast.CallExpr:
				return slices.Contains(textCopies, funcName(x.Fun)) && len(x.Args) > 0 && text(x.Args[0])
			}
			return false
		}
		// What a variable holds is learnt until nothing changes, so a copy of a copy is held too.
		for changed := true; changed; {
			changed = false
			hold := func(lhs []ast.Expr, rhs []ast.Expr) {
				for i, l := range lhs {
					id, ok := l.(*ast.Ident)
					if !ok || held[id.Name] || id.Name == "_" {
						continue
					}
					if (len(rhs) == len(lhs) && text(rhs[i])) || (len(rhs) == 1 && len(lhs) > 1 && i == 0 && text(rhs[0])) {
						held[id.Name], changed = true, true
					}
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.AssignStmt:
					hold(x.Lhs, x.Rhs)
				case *ast.ValueSpec:
					lhs := make([]ast.Expr, len(x.Names))
					for i, id := range x.Names {
						lhs[i] = id
					}
					hold(lhs, x.Values)
				}
				return true
			})
		}
		report := func(n ast.Node, what string) {
			uses = append(uses, freeTextUse{line: fset.Position(n.Pos()).Line, decl: name, what: what})
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, err := strconv.Unquote(x.Value); err == nil && freeTextSQL.MatchString(s) {
						report(x, "SQL condition on a free-text column: "+freeTextSQL.FindString(s))
					}
				}
			case *ast.CallExpr:
				if fn := funcName(x.Fun); slices.Contains(textTests, fn) && slices.ContainsFunc(x.Args, text) {
					report(x, fn+" of free text")
				}
			case *ast.BinaryExpr:
				if (x.Op == token.EQL || x.Op == token.NEQ) && (text(x.X) && stringLit(x.Y) || text(x.Y) && stringLit(x.X)) {
					report(x, "free text compared with a literal")
				}
			case *ast.SwitchStmt:
				if x.Tag != nil && text(x.Tag) {
					report(x, "switch on free text")
				}
			}
			return true
		})
	}
	return uses, nil
}

// declName is the name of a top-level declaration: a function's (Type.Method for a method), or the first name of a const, var or type.
func declName(d ast.Decl) string {
	switch x := d.(type) {
	case *ast.FuncDecl:
		if x.Recv != nil && len(x.Recv.List) > 0 {
			t := x.Recv.List[0].Type
			if s, ok := t.(*ast.StarExpr); ok {
				t = s.X
			}
			if id, ok := t.(*ast.Ident); ok {
				return id.Name + "." + x.Name.Name
			}
		}
		return x.Name.Name
	case *ast.GenDecl:
		for _, s := range x.Specs {
			switch sp := s.(type) {
			case *ast.ValueSpec:
				return sp.Names[0].Name
			case *ast.TypeSpec:
				return sp.Name.Name
			}
		}
	}
	return ""
}

// funcName is the name a call calls: strings.HasPrefix → HasPrefix, re.MatchString → MatchString, string → string.
func funcName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// stringLit says e is a string literal with text: a test against "" asks whether there is any text, not what it says.
func stringLit(e ast.Expr) bool {
	l, ok := e.(*ast.BasicLit)
	return ok && l.Kind == token.STRING && l.Value != `""` && l.Value != "``"
}

// Guard: no code decides from the text of a note, an evidence sentence or an event's detail. What a decision needs is a column or a
// field of its own (a state, a resolution, a via, a software line), so a reworded sentence never changes what the box does. The uses
// named here are the ones left, each with its reason (file -> the declaration that holds the use); any other fails, and an allowance
// whose use is gone fails too.
func TestGuard_NoDecisionReadsFreeText(t *testing.T) {
	t.Parallel()
	allowed := map[string]string{
		// The response module (not shown in this release) tells a person's rejection from a cancellation by the note the server writes
		// ("Rejected by <name>"); it moves to a column of its own with the module.
		"modules/response/ai.go": "byPersonSQL",
	}
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	for _, dir := range []string{"cmd", "core", "modules", "host", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "core/api/oas/") { // generated from the API description: no decisions
				return nil
			}
			b, err := os.ReadFile(p) //nolint:gosec // a source file of this repository found by the walk
			if err != nil {
				return err
			}
			uses, err := freeTextUses(p, b)
			if err != nil {
				return err
			}
			for _, u := range uses {
				if allowed[rel] == u.decl {
					used[rel] = true
					continue
				}
				t.Errorf("%s:%d (%s) decides from free text: %s", rel, u.line, u.decl, u.what)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for rel := range allowed {
		if !used[rel] {
			t.Errorf("%s no longer reads free text: remove it from the allow-list", rel)
		}
	}
}

// The guard sees a decision however it is written: a call split across lines, a value read through a local variable or a case
// change, a pointer, a switch, a query condition on its own line or on trigger_note; and it leaves alone a free-text field that is
// only stored or shown.
func TestGuard_FreeTextUsesSeesEveryForm(t *testing.T) {
	t.Parallel()
	caught := map[string]string{
		"split call":        "if strings.HasPrefix(\n\t\tf.Note,\n\t\t\"Rejected\") {\n\t\treturn\n\t}",
		"local variable":    "n := f.Note\n\tif strings.Contains(n, \"x\") {\n\t\treturn\n\t}",
		"copy of a copy":    "n := strings.ToLower(f.TriggerNote)\n\tm := n\n\t_ = m == \"manual\"",
		"pointer":           "if *f.Note == \"x\" {\n\t\treturn\n\t}",
		"regexp":            "_ = re.MatchString(ev.Detail)",
		"switch":            "switch f.Evidence {\n\tcase \"a\":\n\t}",
		"var declaration":   "var n string = f.Notes\n\t_ = strings.EqualFold(n, \"x\")",
		"multi-line query":  "_ = `SELECT id FROM core_run\n\t\tWHERE trigger_note\n\t\tLIKE 'auto%'`",
		"query on evidence": "_ = \"SELECT 1 FROM t WHERE instr(evidence, 'agent') > 0\"",
		"query IN list":     "_ = `SELECT 1 FROM t WHERE detail IN ('a', 'b')`",
	}
	for name, body := range caught {
		uses, err := freeTextUses("x.go", []byte("package x\n\nfunc f() {\n\t"+body+"\n}\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(uses) == 0 {
			t.Errorf("%s: not caught:\n%s", name, body)
		}
	}
	left := map[string]string{
		"stored":         "f.Note = &note\n\trow := T{Note: \"x\"}\n\t_ = row",
		"shown":          "fmt.Println(f.Note, len(f.Detail))",
		"other field":    "_ = strings.HasPrefix(f.Name, \"x\")",
		"nil check":      "_ = f.Evidence != nil && f.Evidence.Agent",
		"any text":       "if f.Note != \"\" && *g.Detail != `` {\n\t\treturn\n\t}",
		"written by SQL": "_ = `UPDATE t SET note = ?, detail = NULL WHERE id = ?`",
	}
	for name, body := range left {
		uses, err := freeTextUses("x.go", []byte("package x\n\nfunc f() {\n\t"+body+"\n}\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(uses) > 0 {
			t.Errorf("%s: caught though it decides nothing: %+v", name, uses)
		}
	}
}
