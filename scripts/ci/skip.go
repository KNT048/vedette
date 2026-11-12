package main

import (
	_ "embed"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// skip-tests.txt (D-376): the tests the merge gate skips. slow ones run only in the daily schedule; flaky ones are quarantined
// for at most flakyDays with an issue. `ci skip` prints go test's -skip pattern for them.
//
//go:embed skip-tests.txt
var skipTestsTXT string

const flakyDays = 7

var (
	testName = regexp.MustCompile(`^Test[A-Za-z0-9_]*$`) // also keeps the -skip pattern free of regexp metacharacters
	pkgDir   = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]*$`)
	issueURL = regexp.MustCompile(`^https://github\.com/KNT048/vedette/issues/[0-9]+$`)
)

type skipEntry struct {
	kind, name, pkg, reason string
	added                   time.Time
}

// expired reports a flaky line older than flakyDays on day today.
func (e skipEntry) expired(today time.Time) bool {
	return e.kind == "flaky" && today.Sub(e.added) > flakyDays*24*time.Hour
}

// skipEntries parses skip-tests.txt strictly: any bad line is an error.
func skipEntries(txt string) ([]skipEntry, error) {
	var out []skipEntry
	seen := map[string]bool{}
	for line := range strings.SplitSeq(txt, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			return nil, fmt.Errorf("skip-tests.txt: want kind, name, package, reason, date: %q", line)
		}
		e := skipEntry{kind: f[0], name: f[1], pkg: f[2], reason: strings.Join(f[3:len(f)-1], " ")}
		added, err := time.Parse(time.DateOnly, f[len(f)-1])
		if err != nil {
			return nil, fmt.Errorf("skip-tests.txt: bad date in %q", line)
		}
		e.added = added
		switch {
		case e.kind != "slow" && e.kind != "flaky":
			return nil, fmt.Errorf("skip-tests.txt: kind must be slow or flaky: %q", line)
		case !testName.MatchString(e.name):
			return nil, fmt.Errorf("skip-tests.txt: bad test name: %q", line)
		case !pkgDir.MatchString(e.pkg) || strings.Contains(e.pkg, ".."):
			return nil, fmt.Errorf("skip-tests.txt: bad package directory: %q", line)
		case e.kind == "flaky" && !issueURL.MatchString(e.reason):
			return nil, fmt.Errorf("skip-tests.txt: a flaky line's reason is its issue URL: %q", line)
		case seen[e.name]:
			return nil, fmt.Errorf("skip-tests.txt: %s is listed twice (go test -skip matches the name in every package)", e.name)
		}
		seen[e.name] = true
		out = append(out, e)
	}
	return out, nil
}

// printSkip writes the -skip pattern (empty when nothing is skipped). An expired flaky line is not skipped: the test is back in
// the gate (stderr says so) and the guard test fails until the line is fixed or deleted.
func printSkip(txt string, today time.Time, out, warn io.Writer) error {
	entries, err := skipEntries(txt)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.expired(today) {
			_, _ = fmt.Fprintf(warn, "ci skip: the quarantine of %s (%s) is over %d days old; it runs again\n", e.name, e.reason, flakyDays)
			continue
		}
		names = append(names, e.name)
	}
	if len(names) > 0 {
		_, err = fmt.Fprintf(out, "^(%s)$\n", strings.Join(names, "|"))
	}
	return err
}
