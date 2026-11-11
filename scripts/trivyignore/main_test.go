package main

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 11, 15, 30, 0, 0, time.UTC)

func probs(t *testing.T, doc string) []string {
	t.Helper()
	p, _, err := check([]byte(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func entry1(date string) string {
	return "vulnerabilities:\n  - id: CVE-2026-0001\n    statement: no fix path yet, tracked in the issue\n    expired_at: " + date + "\n"
}

func TestExpiryDates(t *testing.T) {
	cases := []struct {
		date string
		ok   bool
		want string
	}{
		{"2026-11-10", false, "expired on 2026-11-10"},   // yesterday fails
		{"2026-11-11", false, "expired on 2026-11-11"},   // trivy no longer ignores on the date itself (measured)
		{"2026-12-11", true, ""},                         // next month passes
		{"2027-03-01", false, "more than 90 days ahead"}, // far dates are a permanent ignore
		{"11/12/2026", false, "is not yyyy-mm-dd"},       // not the trivy date format
		{"", false, "expired_at is required"},            // trivy treats no date as forever
		{"\"2026-11-12\"", true, ""},                     // quoted or bare, same date
	}
	for _, c := range cases {
		p := probs(t, entry1(c.date))
		if c.ok && len(p) != 0 {
			t.Errorf("%q: want ok, got %q", c.date, p)
		}
		if !c.ok && (len(p) != 1 || !strings.Contains(p[0], c.want)) {
			t.Errorf("%q: want one problem with %q, got %q", c.date, c.want, p)
		}
	}
}

func TestReasonAndIDRequired(t *testing.T) {
	p := probs(t, "vulnerabilities:\n  - id: CVE-2026-0002\n    expired_at: 2026-12-01\n  - statement: why\n    expired_at: 2026-12-01\n")
	if len(p) != 2 || !strings.Contains(p[0], "statement") || !strings.Contains(p[1], "id is required") {
		t.Fatalf("got %q", p)
	}
}

func TestEveryEntryIsChecked(t *testing.T) {
	doc := "vulnerabilities:\n  - id: A\n    statement: s\n    expired_at: 2026-12-01\n  - id: B\n    statement: s\n    expired_at: 2026-01-01\nsecrets:\n  - id: C\n    statement: s\n    expired_at: 2026-01-02\n"
	p, n, err := check([]byte(doc), now)
	if err != nil || n != 3 || len(p) != 2 {
		t.Fatalf("n=%d problems=%q err=%v", n, p, err)
	}
}

func TestEmptyAndCommentOnlyFilesHoldNoException(t *testing.T) {
	for _, doc := range []string{"", "# no exceptions\n", "vulnerabilities: []\n"} {
		if p, n, err := check([]byte(doc), now); err != nil || len(p) != 0 || n != 0 {
			t.Errorf("%q: n=%d problems=%q err=%v", doc, n, p, err)
		}
	}
}

func TestUnknownKeysAreErrors(t *testing.T) {
	for _, doc := range []string{
		"vulnerabilites:\n  - id: A\n", // a typo hides nothing and would look fine
		"vulnerabilities:\n  - id: A\n    expires: 2026-12-01\n",
	} {
		if _, _, err := check([]byte(doc), now); err == nil {
			t.Errorf("%q: want an error", doc)
		}
	}
}

// paths and purls narrow an entry to one binary or package (trivy's own fields); the strict decoder must accept them.
func TestPathsAndPURLsAreAccepted(t *testing.T) {
	doc := "vulnerabilities:\n  - id: CVE-2026-0001\n    paths: [\"usr/local/bin/nuclei\"]\n    purls: [\"pkg:golang/example.com/m@v1.0.0\"]\n    statement: not ours\n    expired_at: 2026-12-11\n"
	if p := probs(t, doc); len(p) != 0 {
		t.Errorf("unexpected problems: %v", p)
	}
}
