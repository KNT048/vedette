package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec" //nolint:depguard // CI helper outside the product: fixed argv (git, go), no shell
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ci:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ci changes | ci shard I N")
	}
	switch args[0] {
	case "changes":
		return changes()
	case "shard":
		if len(args) != 3 {
			return fmt.Errorf("usage: ci shard I N")
		}
		i, e1 := strconv.Atoi(args[1])
		n, e2 := strconv.Atoi(args[2])
		if e1 != nil || e2 != nil || n < 1 || i < 1 || i > n {
			return fmt.Errorf("shard: I and N must be integers with 1 <= I <= N")
		}
		return shardCmd(i, n)
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
	text := fmt.Sprintf("go=%t\nweb=%t\nvuln=%t\naudit=%t\n", o.Go, o.Web, o.Vuln, o.Audit)
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

// shardCmd prints the packages of shard i of n, one per line.
func shardCmd(i, n int) error {
	out, err := exec.CommandContext(context.Background(), "go", "list", "-f", "{{.ImportPath}} {{.Dir}}", "./...").Output()
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	var pkgs []pkg
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		path, dir, found := strings.Cut(line, " ")
		if !found {
			return fmt.Errorf("go list: unexpected line %q", line)
		}
		pkgs = append(pkgs, pkg{path, testBytes(dir)})
	}
	mine := Shard(pkgs, i, n)
	if len(mine) == 0 {
		return fmt.Errorf("shard %d/%d is empty (%d packages)", i, n, len(pkgs))
	}
	for _, p := range mine {
		fmt.Println(p)
	}
	return nil
}

// testBytes is the size of the package's test files: the cheapest stable proxy for test time.
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
