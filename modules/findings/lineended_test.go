package findings

import (
	"testing"
	"time"
)

// A line source's convention for a line it does not list ("a supported line not listed is not affected") rests on support data, which
// says which lines a vendor looks after and nothing about a CVE. It holds only for a line assessed when the CVE was published and still
// in support now: a line out of support is never closed by it. The product is made up: the rule reads the support rows only.
func TestConventionClears_NeverALineOutOfSupport(t *testing.T) {
	t.Parallel()
	published := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	cover := LineCover{Source: "example-security", Product: "example|gateway", StatedAt: published, Absent: AbsentUnaffectedIfSupported}
	line := func(released, until time.Time, ended bool) LineSupport {
		return LineSupport{Source: "example-lifecycle", Product: "example|gateway", Line: "20", Released: released, AssessedUntil: until, Ended: ended}
	}
	old, endOfLife, later := time.Date(2023, 4, 18, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC), time.Date(2027, 4, 30, 0, 0, 0, 0, time.UTC)
	stale := cover
	stale.Stale = true
	unknown := cover
	unknown.Absent = "unknown"
	for _, tc := range []struct {
		name         string
		c            LineCover
		sup          LineSupport
		held, clears bool
	}{
		{"supported when published and now", cover, line(old, later, false), true, true},
		{"supported when published, out of support now", cover, line(old, endOfLife, true), false, false},
		{"still assessed with no end date", cover, line(old, time.Time{}, false), true, true},
		{"released after the CVE", cover, line(later, time.Time{}, false), false, false},
		{"out of support before the CVE", cover, line(old, old.AddDate(1, 0, 0), true), false, false},
		{"a stale source", stale, line(old, later, false), true, false},
		{"no convention for unlisted lines", unknown, line(old, later, false), true, false},
	} {
		if held, clears := conventionClears(tc.c, tc.sup, published); held != tc.held || clears != tc.clears {
			t.Errorf("%s: held %v clears %v, want %v %v", tc.name, held, clears, tc.held, tc.clears)
		}
	}
}

// Through the match: a line the source does not list, supported when the CVE was published but out of support now, is no longer
// closed by the source's convention; the record's own rows decide it (none here, so nothing is proved), as for any line.
func TestLineJudge_ConventionDoesNotCloseALineOutOfSupport(t *testing.T) {
	t.Parallel()
	cover := LineCover{Source: "nodejs-security-wg", Product: "node.js|node.js", StatedAt: lineCVEDay, Absent: AbsentUnaffectedIfSupported}
	listed := []LineRow{{Source: cover.Source, Product: cover.Product, Line: "26", Status: "affected", Fixed: "26.12.1", Explicit: true}}
	for _, ended := range []bool{false, true} {
		sup := []LineSupport{{Source: "endoflife-date", Product: cover.Product, Line: "22", Released: time.Date(2024, 4, 24, 0, 0, 0, 0, time.UTC),
			AssessedUntil: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Ended: ended}}
		v := Vuln{CVE: "CVE-2026-105481", Published: lineCVEDay, NVDAnswered: true, Lines: listed, LineCovers: []LineCover{cover}, LineSupport: sup}
		a := Asset{ID: "dev", Name: "dev.example.com", Software: []Software{nodeRow("22.19.0")}}
		s := a.Software[0]
		_, out := matchOne(a, s, swInfoOn(s, a), v, false, nil, true, lineNow)
		if closed := out == outNotAffected; closed == ended {
			t.Errorf("line out of support now %v: outcome %d, want closed %v", ended, out, !ended)
		}
	}
}
