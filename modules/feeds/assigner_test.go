package feeds

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A CVE record's assigner is stored with the CVE, and the rows read for matching say whether the record's CNA is the row's vendor
// (VendorCNA): the vendor's own CNA lists its releases, a third party lists the build it tested. NVD's rows of the CVE carry the same
// word for the CPE's vendor; an assigner longer than the column takes is cut, never refused.
func TestRecordAssigner_RowsSayWhetherTheVendorAssigned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name, assigner string
		vendorCNA      bool
	}{
		{"the vendor's own CNA", "acme", true},
		{"a third party", "testlab", false},
	} {
		s, db := newStore(t)
		raw := strings.Replace(string(record(`{"vendor":"Acme","product":"Box","versions":[{"version":"4.0.4","status":"affected"}]}`)),
			`"assignerShortName":"acme"`, `"assignerShortName":"`+c.assigner+`"`, 1)
		rec, err := ParseCVERecord([]byte(raw), "CVE-2026-1000")
		if err != nil {
			t.Fatal(err)
		}
		write(t, db, func(tx *sql.Tx) error {
			if err := storeRecords(t.Context(), tx, []NVDRecord{{CVE: rec.CVE, Published: now.AddDate(0, 0, -2), LastModified: now, Status: "Analyzed",
				Affected: []AffectedRow{{CPE: "cpe:2.3:a:acme:box:4.0.4:*:*:*:*:*:*:*"}}}}, now); err != nil {
				return err
			}
			k, err := recordKeepOf(t.Context(), tx, now, nil)
			if err != nil {
				return err
			}
			w, err := writeRecords(t.Context(), tx, []CVERecord{rec}, k, now)
			if err == nil && w.Stored != 1 {
				err = fmt.Errorf("stored %d", w.Stored)
			}
			return err
		})
		var stored string
		if err := db.Reader().QueryRowContext(t.Context(), `SELECT assigner FROM feeds_cve WHERE cve = ?`, rec.CVE).Scan(&stored); err != nil || stored != c.assigner {
			t.Fatalf("%s: stored assigner %q %v", c.name, stored, err)
		}
		got, err := s.RangesOf(t.Context(), []string{rec.CVE})
		if err != nil || len(got) != 2 {
			t.Fatalf("%s: rows %+v %v", c.name, got, err)
		}
		for _, r := range got {
			if r.VendorCNA != c.vendorCNA || r.AffectedRow().VendorCNA != c.vendorCNA {
				t.Errorf("%s: %s row vendor CNA %v, want %v", c.name, r.Origin, r.VendorCNA, c.vendorCNA)
			}
		}
	}
	if got := clipAssigner(strings.Repeat("a", 80)); len(got) != maxAssigner {
		t.Errorf("assigner of %d bytes kept, want at most %d", len(got), maxAssigner)
	}
}
