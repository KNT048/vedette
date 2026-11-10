package host_test

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// INV-14 (D-87): every operation on core's tree goes through an os.Root handle and a descriptor;
// the host never names a path inside core's tree. The scanner type-checks host/ops (stdlib
// go/types, no new dependency) and enforces three rules:
//
//  1. The field Config.CoreData is read only in openCore, checkChain, checkCoreAtStart and
//     NewWithDeps (which only validates the value); nothing else can build a path in core's tree.
//  2. coredata.go, where the handle lives, calls no path-based function of os, syscall,
//     golang.org/x/sys/unix, path or path/filepath, outside openCore and checkChain (the walk
//     that decides whether the tree is trusted at all, and the first open of its root).
//  3. Any other function that holds a *os.Root or a *coreTree calls none either, and Chmod,
//     Chown, Lchown and Chtimes on any *os.Root are forbidden everywhere (documented racy by name:
//     chmod and chown on a descriptor).
var (
	inv14PathFuncs = map[string][]string{
		"os": {"Rename", "Open", "OpenFile", "Stat", "Lstat", "Remove", "RemoveAll", "Chmod", "Chown", "Lchown", "Chtimes",
			"Readlink", "Symlink", "Link", "Truncate", "Mkdir", "MkdirAll", "ReadDir", "ReadFile", "WriteFile", "Create",
			"CreateTemp", "MkdirTemp", "OpenInRoot", "Mkfifo"},
		"syscall":               syscallPathFuncs,
		"golang.org/x/sys/unix": syscallPathFuncs,
		"path/filepath":         {"EvalSymlinks", "Walk", "WalkDir", "Glob", "Abs"},
		"path":                  {"Join"},
	}
	syscallPathFuncs = []string{"Open", "Openat", "Creat", "Chmod", "Chown", "Lchown", "Fchownat", "Fchmodat", "Rename", "Renameat",
		"Mkdir", "Mkdirat", "Mkfifo", "Mknod", "Unlink", "Unlinkat", "Rmdir", "Stat", "Lstat", "Statfs", "Symlink", "Link",
		"Readlink", "Truncate", "Utimes", "UtimesNano", "Access", "Chdir", "Chroot"}
	inv14RootRacy = []string{"Chmod", "Chown", "Lchown", "Chtimes"}
	// ensureCoreData (the bootstrap, D-142) makes core_data only when it is absent, before core has ever run: it
	// reads no entry of core's tree, and what it makes is closed to everyone but core (0700) and checked by checkChain at the next command.
	inv14CoreFns = []string{"openCore", "checkChain", "checkCoreAtStart", "NewWithDeps", "ensureCoreData", "fillFor"}
	inv14PathFns = []string{"openCore", "checkChain", "checkParents"}
)

// inv14Violations type-checks one package and returns what breaks the three rules.
func inv14Violations(t *testing.T, fset *token.FileSet, files []*ast.File) []string {
	t.Helper()
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(error) {}} // an import that cannot load still yields a package path
	_, _ = conf.Check("ops", fset, files, info)

	isHandle := func(typ types.Type) bool {
		if typ == nil {
			return false
		}
		s := strings.TrimPrefix(typ.String(), "*")
		return s == "os.Root" || strings.HasSuffix(s, ".coreTree")
	}
	var out []string
	add := func(pos token.Pos, format string, a ...any) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(pos), fmt.Sprintf(format, a...)))
	}
	for _, f := range files {
		file := filepath.Base(fset.Position(f.Pos()).Filename)
		for _, decl := range f.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			name := ""
			if isFunc {
				name = fn.Name.Name
			}
			// holds a handle: a receiver, parameter or any expression of type *os.Root / *coreTree
			holds := false
			ast.Inspect(decl, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok && isHandle(info.Types[e].Type) {
					holds = true
				}
				return true
			})
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if v, ok := info.Uses[x].(*types.Var); ok && v.IsField() && v.Name() == "CoreData" && !slices.Contains(inv14CoreFns, name) {
						add(x.Pos(), "%s reads Config.CoreData; only %s may", name, strings.Join(inv14CoreFns, ", "))
					}
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if s := info.Selections[sel]; s != nil && isHandle(s.Recv()) && strings.TrimPrefix(s.Recv().String(), "*") == "os.Root" && slices.Contains(inv14RootRacy, sel.Sel.Name) {
						add(sel.Pos(), "Root.%s is racy by name: chmod and chown on a descriptor", sel.Sel.Name)
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					pn, ok := info.Uses[id].(*types.PkgName)
					if !ok || !slices.Contains(inv14PathFuncs[pn.Imported().Path()], sel.Sel.Name) {
						return true
					}
					if (file == "coredata.go" && !slices.Contains(inv14PathFns, name)) || (holds && !slices.Contains(inv14PathFns, name)) {
						add(sel.Pos(), "%s calls %s.%s, a path-based call, where core's tree is handled", name, pn.Imported().Path(), sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	return out
}

func TestContract_INV14_NoPathBasedOperationsOnCoresTreeInHostOps(t *testing.T) {
	t.Parallel()
	dir := "../../host/ops"
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range bp.GoFiles { // GoFiles has no _test.go and none from opstest
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) < 10 {
		t.Fatalf("only %d host/ops files checked", len(files))
	}
	for _, v := range inv14Violations(t, fset, files) {
		t.Error(v)
	}
}

// The scanner must catch each of these 13 ways of operating on core's tree by path (the old
// scanner knew nine os.* names and a literal x.root.Chmod): each is put in a function of a stand-in
// coredata.go that declares the handle types, and each must report at least one violation.
func TestContract_INV14_ScannerCatchesPathBasedCallsOnCoresTree(t *testing.T) {
	t.Parallel()
	forms := map[string]string{
		"os.Open on a concatenated path":   `_, _ = os.Open(o.cfg.CoreData + "/vedette.db")`,
		"os.OpenFile via path.Join":        `_, _ = os.OpenFile(path.Join(dir, "vedette.db"), os.O_RDONLY, 0)`,
		"os.Rename":                        `_ = os.Rename(tmp, dst)`,
		"os.RemoveAll":                     `_ = os.RemoveAll(dst)`,
		"os.ReadDir":                       `_, _ = os.ReadDir(dir)`,
		"os.Stat (follows symlinks)":       `_, _ = os.Stat(dst)`,
		"os.ReadFile":                      `_, _ = os.ReadFile(dst)`,
		"syscall.Chmod":                    `_ = syscall.Chmod(dst, 0o600)`,
		"unix.Fchownat by name":            `_ = unix.Fchownat(fd, "vedette.db", 1, 1, 0)`,
		"Root.Chmod through a local alias": `_ = r.Chmod("vedette.db", 0o600)`,
		"Root.Chown on a returned root":    `_ = t.handle().Chown("vedette.db", 1, 1)`,
		"filepath.EvalSymlinks":            `_, _ = filepath.EvalSymlinks(dst)`,
		"statfs on core_data":              `_ = o.checkRestoreSpace(o.cfg.CoreData, 1)`,
	}
	const prelude = `package ops

import (
	"os"
	"path"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type Config struct{ CoreData string }
type Ops struct{ cfg Config }
type coreTree struct{ root *os.Root }

func (t *coreTree) handle() *os.Root                      { return t.root }
func (o *Ops) checkRestoreSpace(string, int64) error      { return nil }

var (
	r              *os.Root
	tmp, dst, dir  string
	fd             int
)

func (o *Ops) f(t *coreTree) {
`
	for what, stmt := range forms {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "coredata.go", prelude+"\t"+stmt+"\n}\n", parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if len(inv14Violations(t, fset, []*ast.File{f})) == 0 {
			t.Errorf("INV-14 scanner reports nothing for: %s", what)
		}
	}
	// And the allowed shapes stay allowed: descriptor and handle calls report nothing.
	ok := prelude + "\t_, _ = t.root.Open(\"vedette.db\")\n\t_ = t.root.Rename(\"a\", \"b\")\n\t_ = syscall.Close(fd)\n}\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "coredata.go", ok, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if v := inv14Violations(t, fset, []*ast.File{f}); len(v) != 0 {
		t.Errorf("handle and descriptor calls were reported: %v", v)
	}
}
