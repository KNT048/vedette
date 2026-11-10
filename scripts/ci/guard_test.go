package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The guard (D-140). classify.go lets a pull request skip a suite when it only touches paths "no test reads".
// This test finds every repo path that Go code (string literals, filepath.Join runs, //go:embed) or web code
// (relative "../" strings) reads, and fails when one is classified as not affecting that side. So a test that
// starts reading docs/, .ai/ or web/ files breaks verify-go in the same PR (which touches Go, so it runs).
const repoRoot = "../.."

type read struct{ from, lit, path string }

func exists(rel string) (isDir, ok bool) {
	st, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(rel))) //nolint:gosec // G703: test, paths come from the repo's own sources
	if err != nil {
		return false, false
	}
	return st.IsDir(), true
}

// resolve maps a literal found in a file of directory dir (repo-relative) to an existing repo path.
func resolve(dir, lit string) (string, bool) {
	for _, c := range []string{path.Join(dir, lit), path.Clean(lit)} {
		if c == "." || strings.HasPrefix(c, "..") {
			continue
		}
		if isDir, ok := exists(c); ok {
			if isDir {
				c += "/"
			}
			return c, true
		}
	}
	return "", false
}

func walk(t *testing.T, ext ...string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repoRoot, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", ".dev", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if slices.Contains(ext, filepath.Ext(p)) {
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func goReads(t *testing.T) []read {
	t.Helper()
	var out []read
	fset := token.NewFileSet()
	for _, f := range walk(t, ".go") {
		if strings.HasPrefix(f, "scripts/ci/") {
			continue // the classifier and this guard name paths without reading them
		}
		src, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		dir := path.Dir(f)
		add := func(lit string) {
			if lit == "" || strings.ContainsAny(lit, " \t\n") || !strings.Contains(lit, "/") {
				return
			}
			if p, ok := resolve(dir, lit); ok {
				out = append(out, read{f, lit, p})
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if pats, ok := strings.CutPrefix(c.Text, "//go:embed "); ok {
					for _, pat := range strings.Fields(pats) {
						m, _ := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(dir), pat))
						for _, x := range m {
							rel, _ := filepath.Rel(repoRoot, x)
							out = append(out, read{f, "go:embed " + pat, filepath.ToSlash(rel)})
						}
					}
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// filepath.Join("..", "..", "docs", name): the leading run of literals is the path.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Join" {
					var parts []string
					for _, a := range x.Args {
						bl, ok := a.(*ast.BasicLit)
						if !ok || bl.Kind != token.STRING {
							break
						}
						s, _ := strconv.Unquote(bl.Value)
						parts = append(parts, s)
					}
					if len(parts) > 1 {
						joined := path.Join(parts...)
						if p, ok := resolve(dir, joined); ok {
							out = append(out, read{f, "Join(" + strings.Join(parts, ",") + ")", p})
						}
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					s, _ := strconv.Unquote(x.Value)
					add(s)
				}
			}
			return true
		})
	}
	return out
}

var webRel = regexp.MustCompile("['\"`](\\.\\./[^'\"`\\s*{]*)['\"`]")

func webReads(t *testing.T) []read {
	t.Helper()
	var out []read
	for _, f := range walk(t, ".ts", ".tsx", ".mts", ".mjs", ".js", ".cjs") {
		if !strings.HasPrefix(f, "web/") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range webRel.FindAllStringSubmatch(string(src), -1) {
			if p, ok := resolve(path.Dir(f), m[1]); ok {
				out = append(out, read{f, m[1], p})
			}
		}
	}
	return out
}

func TestNoTestReadsAPathThatSkipsItsSuite(t *testing.T) {
	t.Parallel()
	goR, webR := goReads(t), webReads(t)
	var sawDoc, sawWebFromGo, sawContentFromWeb bool
	for _, r := range goR {
		sawDoc = sawDoc || r.path == "docs/API_CONVENTIONS.md"
		sawWebFromGo = sawWebFromGo || strings.HasPrefix(r.path, "web/")
		if !Classify(r.path).Go {
			t.Errorf("%s reads %q (%s), which a pull request may change without running go: fix the rule in classify.go", r.from, r.lit, r.path)
		}
	}
	for _, r := range webR {
		sawContentFromWeb = sawContentFromWeb || strings.HasPrefix(r.path, "content/")
		if !Classify(r.path).Web {
			t.Errorf("%s reads %q (%s), which a pull request may change without running web: fix the rule in classify.go", r.from, r.lit, r.path)
		}
	}
	// The guard must not pass because it found nothing.
	if !sawDoc || !sawWebFromGo || !sawContentFromWeb {
		t.Errorf("guard is blind: doc read seen=%t, Go reading web/ seen=%t, web reading content/ seen=%t", sawDoc, sawWebFromGo, sawContentFromWeb)
	}
}

func TestEveryNoneRuleNamesARealPath(t *testing.T) {
	t.Parallel()
	for _, r := range rules {
		if r.r != (Result{}) {
			continue
		}
		if _, ok := exists(strings.TrimSuffix(r.prefix, "/")); !ok {
			t.Errorf("skip rule %q matches nothing in the repo: remove it or fix the path", r.prefix)
		}
	}
}
