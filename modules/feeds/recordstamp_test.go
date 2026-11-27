package feeds

import (
	"database/sql"
	"testing"
)

// A CVE's record stamp changes when what its record says changes (a reference, a range, the description, NVD's change time), never
// when the box only reads the same record again: an exploited CVE without NVD ranges is read again every recordRecheck, and a stamp
// that moved with every read would make every check of its advisories stale twice a day.
func TestRecordStamps_StableAcrossRereadChangesWithContent(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	const cve = "CVE-2026-0071"
	write(t, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, record_at, description, updated_at)
			VALUES (?, '2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z', 'Awaiting Analysis', '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z',
			'A flaw in Junos OS.', '2026-11-01T00:00:00.000Z')`, cve); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve_ref (cve, url, tags, source) VALUES (?, 'https://supportportal.example/JSA1', '["Vendor Advisory"]', 'record')`, cve)
		return err
	})
	stamp := func() string {
		t.Helper()
		got, err := s.RecordStamps(t.Context(), []string{cve})
		if err != nil {
			t.Fatal(err)
		}
		if got[cve] == "" {
			t.Fatalf("no stamp for %s", cve)
		}
		return got[cve]
	}
	first := stamp()
	exec := func(q string, args ...any) {
		t.Helper()
		write(t, db, func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q, args...); return err })
	}
	exec(`UPDATE feeds_cve SET record_at = '2026-11-01T12:00:00.000Z', nvd_at = '2026-11-01T12:00:00.000Z', updated_at = '2026-11-01T12:00:00.000Z' WHERE cve = ?`, cve)
	if got := stamp(); got != first {
		t.Errorf("reading the same record again changed the stamp: %q -> %q", first, got)
	}
	exec(`INSERT INTO feeds_cve_ref (cve, url, tags, source) VALUES (?, 'https://supportportal.example/JSA2', '[]', 'record')`, cve)
	second := stamp()
	if second == first {
		t.Errorf("a new reference did not change the stamp")
	}
	exec(`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl) VALUES (?, 'cna', 'o', 'juniper', 'junos', '', '21.4', '', '', '21.4R3-S5')`, cve)
	third := stamp()
	if third == second {
		t.Errorf("a new range did not change the stamp")
	}
	exec(`UPDATE feeds_cve SET description = 'A flaw in Junos OS and Junos OS Evolved.' WHERE cve = ?`, cve)
	if got := stamp(); got == third {
		t.Errorf("a new description did not change the stamp")
	}
}
