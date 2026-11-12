package main

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var (
	failTest = regexp.MustCompile(`--- FAIL: (Test[^\s/]*) \(`)
	failPkg  = regexp.MustCompile(`(?:^|\s)FAIL\s+(github\.com/knt048/vedette\S*)\s`)
	timedOut = regexp.MustCompile(`^\s+(Test[^\s/]*) \(`) // under "panic: test timed out ... running tests:"
)

// failures reads go test output (CI job logs, with or without the runner's prefixes) and returns, per failed package, its failed
// top-level tests (D-365: the daily -count=2 -shuffle=on run lists them in the flaky issue). A package that failed with no test
// named (a build error, a panic outside a test) is listed with no tests.
func failures(r io.Reader) (map[string][]string, error) {
	out := map[string][]string{}
	var tests []string
	inTimeout := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "Z "); i > 0 && i < 40 {
			line = line[i+2:] // the runner's timestamp
		}
		switch {
		case strings.Contains(line, "panic: test timed out"):
			inTimeout = true
		case inTimeout && timedOut.MatchString(line):
			tests = append(tests, timedOut.FindStringSubmatch(line)[1]+" (timed out)")
		case failTest.MatchString(line):
			tests = append(tests, failTest.FindStringSubmatch(line)[1])
		case failPkg.MatchString(line + " "):
			pkg := relPath(failPkg.FindStringSubmatch(line + " ")[1])
			for _, t := range tests {
				if !slices.Contains(out[pkg], t) {
					out[pkg] = append(out[pkg], t)
				}
			}
			if _, ok := out[pkg]; !ok {
				out[pkg] = nil
			}
			tests, inTimeout = nil, false
		default:
			if inTimeout && strings.HasPrefix(strings.TrimSpace(line), "goroutine ") {
				inTimeout = false
			}
		}
	}
	return out, sc.Err()
}

// printFailures writes the markdown list of the flaky issue; nothing when nothing failed.
func printFailures(r io.Reader, w io.Writer, runURL string) error {
	f, err := failures(r)
	if err != nil || len(f) == 0 {
		return err
	}
	if _, err := fmt.Fprintf(w, "The daily run (`go test -race -count=2 -shuffle=on`, %s) failed in:\n\n", runURL); err != nil {
		return err
	}
	for _, pkg := range slices.Sorted(maps.Keys(f)) {
		tests := "(no test named: build error or a panic outside a test)"
		if len(f[pkg]) > 0 {
			tests = "`" + strings.Join(f[pkg], "`, `") + "`"
		}
		if _, err := fmt.Fprintf(w, "- `%s`: %s\n", pkg, tests); err != nil {
			return err
		}
	}
	return nil
}
