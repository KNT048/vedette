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

// D-365: the go-test matrix of ci.yml is exactly shards 1..SHARDS of the Makefile, only main saves the Go test cache (pull requests
// and merge_group refs only restore it), and nothing but the daily schedule turns the cache off (-count, -shuffle).
func TestTheWorkflowMatchesTheShardsAndTheCache(t *testing.T) {
	t.Parallel()
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot, p)) //nolint:gosec // G304: the repo's own files
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mk, wf := read("Makefile"), read(".github/workflows/ci.yml")
	m := regexp.MustCompile(`(?m)^SHARDS \?= (\d+)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("Makefile has no SHARDS ?= N")
	}
	n, _ := strconv.Atoi(m[1])
	var want []string
	for i := 1; i <= n; i++ {
		want = append(want, strconv.Itoa(i))
	}
	if !strings.Contains(wf, "shard: ["+strings.Join(want, ", ")+"]") || !strings.Contains(wf, "of "+m[1]+"\n") {
		t.Errorf("ci.yml's go-test matrix or step name is not shards 1..%d of the Makefile", n)
	}
	code := regexp.MustCompile(`(?m)\s+#.*$`).ReplaceAllString(wf, "") // comments out, so prose cannot satisfy or trip a check
	steps := regexp.MustCompile(`\n {6}- `).Split(code, -1)            // a step of a job starts at "      - "
	field := func(step, name string) string {                          // a step's "name:" value, a block (path: |) included
		m := regexp.MustCompile(`(?m)^ +` + name + `: (.*(?:\n {12,}.*)*)`).FindStringSubmatch(step)
		if m == nil {
			return ""
		}
		return strings.TrimSpace(m[1])
	}
	// D-365, D-372: every actions/cache cache is a restore step and a save step, and only main saves (a pull request or a merge_group ref
	// would fill the repository's 10 GB with copies nobody else may read, pushing out main's).
	var restore, save []string
	for _, s := range steps {
		switch {
		case strings.Contains(s, "actions/cache/restore@"):
			restore = append(restore, s)
		case strings.Contains(s, "actions/cache/save@"):
			save = append(save, s)
		case strings.Contains(s, "actions/cache@"):
			t.Errorf("a restore-and-save actions/cache step saves on every run, pull requests included:\n%s", s)
		}
	}
	saved := map[string]string{} // key -> path
	for _, s := range save {
		if got := field(s, "if"); got != "github.ref == 'refs/heads/main' && (github.event_name == 'push' || github.event_name == 'schedule')" {
			t.Errorf("a cache must be saved on main only (push or schedule), not when %q:\n%s", got, s)
		}
		k := field(s, "key")
		if _, twice := saved[k]; twice || k == "" {
			t.Errorf("cache key %q is saved twice or is empty", k)
		}
		saved[k] = field(s, "path")
	}
	var prefixes []string
	for k := range saved {
		prefix, _, _ := strings.Cut(k, "-${{")
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)
	if want := []string{"go-lint", "go-static", "go-test"}; !slices.Equal(prefixes, want) || len(restore) != 3 {
		t.Fatalf("want the caches %v, one restore step each, got %v and %d restore steps", want, prefixes, len(restore))
	}
	for _, r := range restore {
		k := field(r, "key")
		p, ok := saved[k]
		if !ok || p != field(r, "path") {
			t.Errorf("restore step of key %q has no save step of the same key and path:\n%s", k, r)
		}
		if rk := field(r, "restore-keys"); !strings.HasSuffix(rk, "-") || !strings.HasPrefix(k, rk) {
			t.Errorf("restore-keys %q of key %q is not a prefix of it", rk, k)
		}
	}
	job := code[strings.Index(code, "\n  go-test:")+1:]
	job = job[:regexp.MustCompile(`\n  [a-z]`).FindStringIndex(job)[0]] // up to the next job
	if !regexp.MustCompile(`setup-go@[0-9a-f]{40}[^\n]*\n(?: {8}.*\n)*? {10}cache: false`).MatchString(job) {
		t.Error("go-test's setup-go must not keep a cache of its own (cache: false): a pull request would save it")
	}
	// The required check `go` (D-245) passes only if every Go job it needs passed: it must need and check each go-* job.
	var goJobs []string
	for _, m := range regexp.MustCompile(`(?m)^  (go-[a-z-]+):$`).FindAllStringSubmatch(code, -1) {
		goJobs = append(goJobs, m[1])
	}
	agg := code[strings.Index(code, "\n  go:\n")+1:]
	agg = agg[:regexp.MustCompile(`\n  [a-z]`).FindStringIndex(agg)[0]]
	needs := regexp.MustCompile(`needs: \[([^\]]*)\]`).FindStringSubmatch(agg)
	if len(goJobs) < 4 || needs == nil {
		t.Fatalf("guard is blind: go-* jobs %v, aggregator needs %v", goJobs, needs)
	}
	env := map[string]string{} // the aggregator's env: NAME -> value
	for _, m := range regexp.MustCompile(`(?m)^ {10}([A-Z_]+): (.*)$`).FindAllStringSubmatch(agg, -1) {
		env[m[1]] = strings.TrimSpace(m[2])
	}
	for _, j := range goJobs {
		jb := code[strings.Index(code, "\n  "+j+":\n")+1:]
		jb = jb[:regexp.MustCompile(`\n  [a-z]`).FindStringIndex(jb)[0]]
		cond := regexp.MustCompile(`(?m)^    if: (.*)$`).FindStringSubmatch(jb)
		c := regexp.MustCompile(`(?m)^ +check ` + j + ` "\$([A-Z_]+)" "\$([A-Z_]+)"$`).FindStringSubmatch(agg)
		switch {
		case !slices.Contains(strings.Split(strings.ReplaceAll(needs[1], " ", ""), ","), j) || c == nil:
			t.Errorf("the go aggregator does not need and check job %s", j)
		case env[c[2]] != "${{ needs."+j+".result }}":
			t.Errorf("the go aggregator checks %s against %s = %q, not its own result", j, c[2], env[c[2]])
		case cond == nil || env[c[1]] != "${{ "+cond[1]+" }}":
			t.Errorf("the go aggregator wants %s when %s = %q, but the job runs if %v", j, c[1], env[c[1]], cond)
		}
	}
	for _, name := range []string{"go-static", "go-lint"} {
		j := code[strings.Index(code, "\n  "+name+":")+1:]
		j = j[:regexp.MustCompile(`\n  [a-z]`).FindStringIndex(j)[0]]
		if !regexp.MustCompile(`setup-go@[0-9a-f]{40}[^\n]*\n(?: {8}.*\n)*? {10}cache: false`).MatchString(j) {
			t.Errorf("%s's setup-go must not keep a cache of its own (cache: false): it shares go-static's (D-372)", name)
		}
	}
	if strings.Contains(code, "GOFLAGS") {
		t.Error("ci.yml sets GOFLAGS: flags there reach go test unseen by this guard")
	}
	if got := len(regexp.MustCompile(`-count=|-shuffle`).FindAllString(code, -1)); got != 2 ||
		!strings.Contains(code, "GOTESTFLAGS: ${{ github.event_name == 'schedule' && '-count=2 -shuffle=on -timeout=40m' || '' }}") {
		t.Errorf("-count and -shuffle (they turn the test cache off) must be set by the daily schedule only (%d settings)", got)
	}
	// D-371, D-376: only the daily run uses -race (main's no-race test cache then serves the merge queue). Only the daily run
	// sets SKIPTESTS empty, so it alone runs the tests of skip-tests.txt.
	if got := len(regexp.MustCompile(`\b(RACE|SKIPTESTS)\b`).FindAllString(code, -1)); got != 6 ||
		!strings.Contains(code, "RACE: ${{ github.event_name == 'schedule' && '-race' || '' }}") ||
		!strings.Contains(code, "SKIPTESTS: ${{ github.event_name != 'schedule' && '1' || '' }}") ||
		!strings.Contains(code, `make test-go-shard SHARD=${{ matrix.shard }} RACE="$RACE" SKIPTESTS="$SKIPTESTS"`) {
		t.Errorf("go-test must use -race and run the skip list in the daily run only (%d RACE/SKIPTESTS settings)", got)
	}
	if !regexp.MustCompile(`(?m)^SKIPTESTS \?= 1$`).MatchString(mk) ||
		len(regexp.MustCompile(`(?m)^\t.*go test \$\(RACE\) .*-skip "\$\$skip"`).FindAllString(mk, -1)) != 2 {
		t.Error("make test-go-shard must skip the skip list by default (SKIPTESTS ?= 1) in both go test calls")
	}
	if !regexp.MustCompile(`(?m)^RACE \?= -race$`).MatchString(mk) || len(regexp.MustCompile(`(?m)^\s*(override\s+|export\s+)?RACE\s*[:+?!]?=`).FindAllString(mk, -1)) != 1 ||
		len(regexp.MustCompile(`(?m)^\t.*go test \$\(RACE\) `).FindAllString(mk, -1)) != 2 {
		t.Error("make test-go-shard must run both go test calls with $(RACE), set once in the Makefile to -race unless given")
	}
	cached := regexp.MustCompile(`(?m)^\t.*go test .*\$\$c\b.*$`).FindAllString(mk, -1)
	if len(cached) != 1 || strings.Contains(cached[0], "-count") {
		t.Errorf("make test-go-shard must run the cached packages in one go test without -count: %q", cached)
	}
}

// Every package CI always runs uncached (main.go uncached) still exists: a renamed one would silently go back to the cache.
func TestEveryUncachedPackageExists(t *testing.T) {
	t.Parallel()
	for _, p := range uncached {
		if isDir, ok := exists(relPath(p)); !ok || !isDir {
			t.Errorf("uncached package %s is not a directory of the repo", p)
		}
	}
}
