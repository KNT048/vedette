// Command trivyignore checks the committed exceptions of the vulnerability gate (WP-08i, D-159). trivy applies a
// .trivyignore.yaml entry until its expired_at date and never complains about an entry that has no date, an empty reason or
// an old date, so this gate does: every entry needs an id, a statement (the reason) and an expired_at (yyyy-mm-dd) that is
// after today (trivy stops applying an entry at the start of its date) and at most MaxDays ahead. An expired entry therefore fails `make vuln-scan` even when the finding it hid is
// gone: the exception is removed or renewed with a new reason, never left to rot.
//
//	go run ./scripts/trivyignore -file .trivyignore.yaml
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxDays is the furthest an exception may be dated: a long date is a permanent ignore under another name.
const MaxDays = 90

const dateLayout = "2006-01-02"

type entry struct {
	ID        string   `yaml:"id"`
	Paths     []string `yaml:"paths"`
	PURLs     []string `yaml:"purls"`
	Statement string   `yaml:"statement"`
	ExpiredAt string   `yaml:"expired_at"`
}

func main() {
	file := flag.String("file", "", "the .trivyignore.yaml to check")
	today := flag.String("today", "", "yyyy-mm-dd, for tests; default: today (UTC)")
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "trivyignore: -file is required")
		os.Exit(2)
	}
	now := time.Now().UTC()
	if *today != "" {
		var err error
		if now, err = time.Parse(dateLayout, *today); err != nil {
			fmt.Fprintln(os.Stderr, "trivyignore: -today:", err)
			os.Exit(2)
		}
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trivyignore:", err)
		os.Exit(1)
	}
	problems, n, err := check(b, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trivyignore:", err)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "trivyignore:", p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "trivyignore: %d problem(s) in %s; renew each entry with a reason and a new date, or delete it\n", len(problems), *file)
		os.Exit(1)
	}
	fmt.Printf("trivyignore: ok, %d exception(s), none expired\n", n)
}

// check returns the problems and the number of entries. Unknown top-level keys are an error: a typo would otherwise hide nothing and look fine.
func check(b []byte, now time.Time) ([]string, int, error) {
	var doc map[string][]entry
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) { // an empty file (comments only) holds no exception
		return nil, 0, fmt.Errorf("not a trivy ignore file: %w", err)
	}
	for k := range doc {
		switch k {
		case "vulnerabilities", "misconfigurations", "secrets", "licenses":
		default:
			return nil, 0, fmt.Errorf("unknown section %q (trivy knows vulnerabilities, misconfigurations, secrets, licenses)", k)
		}
	}
	today := now.UTC().Truncate(24 * time.Hour)
	last := today.AddDate(0, 0, MaxDays)
	var probs []string
	n := 0
	for _, section := range []string{"vulnerabilities", "misconfigurations", "secrets", "licenses"} {
		for i, e := range doc[section] {
			n++
			name := fmt.Sprintf("%s[%d] %q", section, i, e.ID)
			if strings.TrimSpace(e.ID) == "" {
				probs = append(probs, name+": id is required")
			}
			if strings.TrimSpace(e.Statement) == "" {
				probs = append(probs, name+": statement (the reason) is required")
			}
			d, err := time.Parse(dateLayout, e.ExpiredAt)
			switch {
			case e.ExpiredAt == "":
				probs = append(probs, name+": expired_at is required (trivy treats no date as forever)")
			case err != nil:
				probs = append(probs, fmt.Sprintf("%s: expired_at %q is not yyyy-mm-dd", name, e.ExpiredAt))
			case !d.After(today): // trivy stops applying an entry at the start of its date (measured: an entry dated today no longer ignores)
				probs = append(probs, fmt.Sprintf("%s: expired on %s", name, e.ExpiredAt))
			case d.After(last):
				probs = append(probs, fmt.Sprintf("%s: expired_at %s is more than %d days ahead", name, e.ExpiredAt, MaxDays))
			}
		}
	}
	return probs, n, nil
}
