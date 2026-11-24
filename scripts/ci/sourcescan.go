package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// enumerators are the calls that turn a directory path into "every file under it": a test file that calls one of them
// on a path outside its own package reads source it cannot name.
var enumerators = []string{"WalkDir", "Walk", "Glob", "ReadDir", "ParseDir", "ImportDir", "DirFS"}

// sourceScanners finds the packages whose test files enumerate the Go source of other packages: a file that calls one of
// enumerators and holds a relative literal (a string starting with "..", or a filepath.Join run of literals that does)
// that resolves, against the package directory, to the repository root, a directory above the package, a directory holding
// other Go packages, or a .go file of another package. root is the repository root on disk, pkgDirs the repo-relative
// directories of the Go packages. Literals are all the scan sees: a root computed at run time is invisible to it, which is
// why guardPackages is written by hand and checked against this scan, never generated from it. The result maps a package
// directory to the literals that gave it away.
func sourceScanners(root string, pkgDirs []string) (map[string][]string, error) {
	out := map[string][]string{}
	// reachesSource reports whether target (repo relative) holds Go source of a package other than own.
	reachesSource := func(own, target string) bool {
		if target == own || strings.HasPrefix(target, own+"/") {
			return false
		}
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(target)))
		if err != nil {
			return false
		}
		if !st.IsDir() {
			return strings.HasSuffix(target, ".go")
		}
		return slices.ContainsFunc(pkgDirs, func(d string) bool {
			return d != own && !strings.HasPrefix(d, own+"/") && (target == "." || d == target || strings.HasPrefix(d, target+"/"))
		})
	}
	for _, own := range pkgDirs {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(own), "*_test.go"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			src, err := os.ReadFile(f) //nolint:gosec // G304: the repo's own test files
			if err != nil {
				return nil, err
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
			if err != nil {
				return nil, err
			}
			enumerates := false
			var hits []string
			ast.Inspect(file, func(n ast.Node) bool {
				var lits []string
				switch x := n.(type) {
				case *ast.BasicLit:
					if s, ok := strLit(x); ok {
						lits = append(lits, s)
					}
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						break
					}
					enumerates = enumerates || slices.Contains(enumerators, sel.Sel.Name)
					if sel.Sel.Name != "Join" {
						break
					}
					var parts []string
					for _, a := range x.Args {
						bl, ok := a.(*ast.BasicLit)
						if !ok {
							break
						}
						s, ok := strLit(bl)
						if !ok {
							break
						}
						parts = append(parts, s)
					}
					if len(parts) > 1 {
						lits = append(lits, path.Join(parts...))
					}
				}
				for _, lit := range lits {
					lit = filepath.ToSlash(lit)
					if !strings.HasPrefix(lit, "..") || strings.Trim(lit, "/") == ".." {
						continue // a lone ".." is the usual escape-attempt input of a path-safety test, not a read
					}
					if t := path.Join(own, lit); !strings.HasPrefix(t, "..") && reachesSource(own, t) {
						hits = append(hits, lit)
					}
				}
				return true
			})
			if enumerates {
				out[own] = append(out[own], hits...)
			}
		}
	}
	for k, v := range out {
		if len(v) == 0 {
			delete(out, k)
		}
	}
	return out, nil
}

func strLit(b *ast.BasicLit) (string, bool) {
	if b.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(b.Value)
	return s, err == nil
}
