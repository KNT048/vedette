package feeds

import (
	"database/sql"
	"fmt"
	"testing"
)

// Every CVE the catalogue holds keeps its references, whether or not a list, a signal or a finding names it: a finding that pins an
// old CVE later finds the advisory and patch links already stored. A CVE retention removes leaves no reference rows.
func TestCount_EveryCatalogueCVEHasItsReferences(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	now := epoch0
	plain := []string{"CVE-2026-0801", "CVE-2026-0802", "CVE-2026-0803", "CVE-2026-0804"} // in the window, on no list, no signal, no finding
	listed := "CVE-2026-0805"
	applyV(t, db, now, "cisa-kev", []Vuln{vuln(listed, "Acme", "Box", "2026-11-01")}, false)
	refsOf := func(cve string) []RecordRef {
		return []RecordRef{
			{URL: "https://acme.example.com/advisory/" + cve, Tags: []string{"vendor-advisory"}, Source: OriginCNA},
			{URL: "https://acme.example.com/patch/" + cve, Tags: []string{"patch"}, Source: OriginCNA},
		}
	}
	// the catalogue holds the plain CVEs because NVD published them inside the window; two of them get NVD-tagged references
	var nvd []NVDRecord
	for _, c := range plain {
		r := NVDRecord{CVE: c, Published: now.AddDate(0, -1, 0), LastModified: now, Status: "Awaiting Analysis"}
		if c == plain[2] || c == plain[3] {
			r.Status = "Analyzed"
			r.Refs = []RecordRef{{URL: "https://nvd.example.com/ref/" + c, Tags: []string{"patch"}, Source: RefsNVD}}
		}
		nvd = append(nvd, r)
	}
	write(t, db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, nvd[:2], now) }) // the untagged ones first
	withoutRefs := func() int {
		return count(t, db, `SELECT count(*) FROM feeds_cve c WHERE NOT EXISTS (SELECT 1 FROM feeds_cve_ref r WHERE r.cve = c.cve)`)
	}
	// the CVE records of the first two plain CVEs and of the listed one
	write(t, db, func(tx *sql.Tx) error {
		var recs []CVERecord
		for _, c := range []string{plain[0], plain[1], listed} {
			recs = append(recs, CVERecord{CVE: c, State: RecordPublished, Refs: refsOf(c)})
		}
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, recs, k, now)
		return err
	})
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref WHERE cve IN ('CVE-2026-0801', 'CVE-2026-0802')`); n != 4 {
		t.Fatalf("record references of CVEs on no list: %d, want 4", n)
	}
	// an NVD pull of the other two stores NVD's tagged references too
	write(t, db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, nvd[2:], now) })
	for _, c := range plain[2:] {
		if n := count(t, db, fmt.Sprintf(`SELECT count(*) FROM feeds_cve_ref WHERE cve = '%s' AND source = 'nvd'`, c)); n != 1 {
			t.Fatalf("NVD references of %s: %d, want 1", c, n)
		}
	}
	if n := withoutRefs(); n != 0 {
		t.Fatalf("CVEs in the catalogue without references: %d, want 0", n)
	}
	t.Logf("catalogue CVEs without references after the reads: %d", withoutRefs())
	// a later record read does not drop them either (no cleanup step removes references of an unlisted CVE)
	write(t, db, func(tx *sql.Tx) error {
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, []CVERecord{{CVE: plain[0], State: RecordPublished, Refs: refsOf(plain[0])}}, k, now)
		return err
	})
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref WHERE cve = 'CVE-2026-0801'`); n != 2 {
		t.Fatalf("references after a second read: %d, want 2", n)
	}
	// a year later the window CVEs age out with their references; the listed CVE keeps its own
	write(t, db, func(tx *sql.Tx) error { return pruneCatalogue(t.Context(), tx, now.AddDate(1, 0, 1), nil) })
	if n := count(t, db, `SELECT count(*) FROM feeds_cve`); n != 1 {
		t.Fatalf("CVEs after retention: %d, want 1", n)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref WHERE cve NOT IN (SELECT cve FROM feeds_cve)`); n != 0 {
		t.Fatalf("orphan reference rows: %d", n)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_ref`); n != 2 {
		t.Fatalf("references left: %d, want only the listed CVE's 2", n)
	}
}
