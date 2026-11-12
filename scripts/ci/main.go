package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec" //nolint:depguard // CI helper outside the product: fixed argv (git, go), no shell
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ci:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ci changes | ci shard I N [cached|uncached] | ci times LOG | ci flaky RUN_URL < LOGS | ci skip")
	}
	switch args[0] {
	case "changes":
		return changes()
	case "shard":
		if len(args) != 3 && (len(args) != 4 || (args[3] != "cached" && args[3] != "uncached")) {
			return fmt.Errorf("usage: ci shard I N [cached|uncached]")
		}
		i, e1 := strconv.Atoi(args[1])
		n, e2 := strconv.Atoi(args[2])
		if e1 != nil || e2 != nil || n < 1 || i < 1 || i > n {
			return fmt.Errorf("shard: I and N must be integers with 1 <= I <= N")
		}
		mode := ""
		if len(args) == 4 {
			mode = args[3]
		}
		return shardCmd(i, n, mode)
	case "flaky":
		if len(args) != 2 {
			return fmt.Errorf("usage: ci flaky RUN_URL < LOGS")
		}
		return printFailures(os.Stdin, os.Stdout, args[1])
	case "skip":
		return printSkip(skipTestsTXT, time.Now().UTC(), os.Stdout, os.Stderr)
	case "times":
		if len(args) != 2 {
			return fmt.Errorf("usage: ci times LOG")
		}
		f, err := os.Open(args[1]) //nolint:gosec // G703: the CI log a maintainer names on the command line
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return printTimes(f, os.Stdout)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// changes prints the job switches as key=value lines to $GITHUB_OUTPUT (stdout when unset).
// On a pull request the checkout has fetch-depth 2, so HEAD^1 is the base tip of the PR merge commit.
func changes() error {
	event := os.Getenv("GITHUB_EVENT_NAME")
	var paths []string
	ok := false
	if event == "pull_request" {
		out, err := exec.CommandContext(context.Background(), "git", "diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD").Output()
		if err == nil {
			ok = true
			for _, p := range bytes.Split(out, []byte{0}) {
				if len(p) > 0 {
					paths = append(paths, string(p))
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "ci: git diff failed, running everything:", err)
		}
	}
	o := Decide(event, paths, ok)
	text := fmt.Sprintf("go=%t\ntests=%t\nweb=%t\nvuln=%t\naudit=%t\n", o.Go, o.Tests, o.Web, o.Vuln, o.Audit)
	fmt.Fprintf(os.Stderr, "ci: event=%q changed=%d\n%s", event, len(paths), text)
	if f := os.Getenv("GITHUB_OUTPUT"); f != "" {
		w, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // G304: $GITHUB_OUTPUT is set by the runner
		if err != nil {
			return err
		}
		if _, err = w.WriteString(text); err != nil {
			_ = w.Close()
			return err
		}
		return w.Close()
	}
	fmt.Print(text)
	return nil
}

type pkg struct {
	path   string
	weight int64
}

//go:embed testtime.tsv
var testTimeTSV string

const modulePath = "github.com/knt048/vedette"

// testTimes reads testtime.tsv: seconds of go test -race per package (path relative to the module, "." for the root).
func testTimes(tsv string) (map[string]float64, error) {
	out := map[string]float64{}
	for line := range strings.SplitSeq(tsv, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		secs, rel, ok := strings.Cut(line, "\t")
		s, err := strconv.ParseFloat(secs, 64)
		if !ok || err != nil || s < 0 {
			return nil, fmt.Errorf("testtime.tsv: bad line %q", line)
		}
		out[pkgPath(rel)] = s
	}
	return out, nil
}

// pkgPath is the import path of a module-relative directory ("." is the module itself); relPath is the reverse.
func pkgPath(rel string) string {
	if rel == "." {
		return modulePath
	}
	return modulePath + "/" + rel
}

func relPath(path string) string {
	if path == modulePath {
		return "."
	}
	return strings.TrimPrefix(path, modulePath+"/")
}

// weigh turns measured seconds into shard weights (milliseconds); a package not in the table weighs its _test.go bytes at the
// table's average seconds per byte, so a new package is never free.
func weigh(paths []string, bytesOf map[string]int64, times map[string]float64) []pkg {
	var secs float64
	var known int64
	for _, p := range paths {
		if s, ok := times[p]; ok {
			secs += s
			known += bytesOf[p]
		}
	}
	rate := 0.0
	if known > 0 {
		rate = secs / float64(known)
	}
	out := make([]pkg, 0, len(paths))
	for _, p := range paths {
		s, ok := times[p]
		if !ok {
			s = float64(bytesOf[p]) * rate
		}
		out = append(out, pkg{p, int64(s * 1000)})
	}
	return out
}

// printTimes prints testtime.tsv rows from a CI log: every "ok <package> <seconds>s" line of go test, the last one per package.
func printTimes(r io.Reader, w io.Writer) error {
	times := map[string]string{}
	cachedLines := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.Contains(sc.Text(), "\t(cached)") {
			cachedLines++
		}
		f := strings.Fields(sc.Text())
		for i := 0; i+2 < len(f); i++ {
			secs, isTime := strings.CutSuffix(f[i+2], "s")
			if f[i] != "ok" && f[i] != "FAIL" || !isTime || (f[i+1] != modulePath && !strings.HasPrefix(f[i+1], modulePath+"/")) {
				continue
			}
			if _, err := strconv.ParseFloat(secs, 64); err == nil {
				times[relPath(f[i+1])] = secs
			}
			break
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if cachedLines > 0 { // a cached package has no time: take the table from the daily run's log, which runs everything
		fmt.Fprintf(os.Stderr, "ci times: %d packages came from the test cache and are not in this table; use the log of a daily (schedule) run\n", cachedLines)
	}
	rels := slices.Sorted(maps.Keys(times))
	for _, rel := range rels {
		s, _ := strconv.ParseFloat(times[rel], 64)
		if _, err := fmt.Fprintf(w, "%.0f\t%s\n", s, rel); err != nil {
			return err
		}
	}
	return nil
}

// uncached are the packages whose tests read files through a child process (go build, go list, a built helper): go test's cache
// only sees what the test process itself opens, so a change to those files could pass from the cache (D-365). CI always runs them.
var uncached = []string{
	modulePath + "/core/pdftext",         // pdftexttest.BuildChild builds the child with go build
	modulePath + "/scripts/hostlicenses", // go list -deps and the license files of the module cache
}

// shardCmd prints the packages of shard i of n, one per line: all of them, or only those go test may take from its cache
// ("cached"), or only the ones it may not ("uncached").
func shardCmd(i, n int, mode string) error {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-f", "{{.ImportPath}} {{.Dir}}", "./...").Output()
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	times, err := testTimes(testTimeTSV)
	if err != nil {
		return err
	}
	var paths []string
	bytesOf := map[string]int64{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		path, dir, found := strings.Cut(line, " ")
		if !found {
			return fmt.Errorf("go list: unexpected line %q", line)
		}
		paths = append(paths, path)
		bytesOf[path] = testBytes(dir)
	}
	pkgs := weigh(paths, bytesOf, times)
	mine := Shard(pkgs, i, n)
	if len(mine) == 0 {
		return fmt.Errorf("shard %d/%d is empty (%d packages)", i, n, len(pkgs))
	}
	for _, p := range mine {
		if mode == "" || (mode == "uncached") == slices.Contains(uncached, p) {
			fmt.Println(p)
		}
	}
	return nil
}

// testBytes is the size of the package's test files: the proxy for the test time of a package testtime.tsv does not list.
func testBytes(dir string) int64 {
	files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
	var sum int64
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			sum += st.Size()
		}
	}
	return sum
}

// Shard splits pkgs into n shards (greedy: heaviest first into the lightest shard, ties by name) and returns
// shard i (1-based). Every package lands in exactly one shard, and the split depends only on the inputs.
func Shard(pkgs []pkg, i, n int) []string {
	sorted := slices.Clone(pkgs)
	slices.SortFunc(sorted, func(a, b pkg) int {
		return cmp.Or(cmp.Compare(b.weight, a.weight), cmp.Compare(a.path, b.path))
	})
	load := make([]int64, n)
	count := make([]int, n)
	var mine []string
	for _, p := range sorted {
		k := 0
		for j := 1; j < n; j++ {
			if load[j] < load[k] || (load[j] == load[k] && count[j] < count[k]) {
				k = j
			}
		}
		load[k] += p.weight
		count[k]++
		if k == i-1 {
			mine = append(mine, p.path)
		}
	}
	slices.Sort(mine)
	return mine
}
