package main

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// Where a vendor's affected ranges start decides "not affected" only when the starts are the vendor's word on where a flaw came in and
// every affected row of the product was read. A row the version scheme cannot read (Juniper's "22.2" lessThan "22.2*": every 22.2
// release) may cover the device; an exact release (Oracle's "8u503": the newest affected update of Java 8, every earlier one affected
// too) says nothing about where the flaw came in. Either way the device stays a finding or a question, never closed by the start rule.
func TestVendorRangeStartNeedsEveryRowRead(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2099-72002"
	run := func(t *testing.T, kevVendor, kevProduct, catalogID, version, affected string) (*stack, string) {
		t.Helper()
		raw := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"vendor"},` +
			`"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw."}],"affected":[` + affected + `]}}}`
		rec, err := feeds.ParseCVERecord([]byte(raw), cve)
		if err != nil {
			t.Fatal(err)
		}
		s := newStack(t)
		ctx := t.Context()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			if err := seedKEVRow(ctx, tx, cve, kevVendor, kevProduct, kevVendor+" flaw", time.Now().AddDate(0, -2, 0), false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
				return err
			}
			for _, r := range rec.Ranges {
				if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: catalogID, Version: version, Name: "dev-1", IP: "192.0.2.41"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.d.Findings.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		return s, r.ID
	}
	notClosed := func(t *testing.T, s *stack, dev, why string) {
		t.Helper()
		q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND (cve = ? OR json_extract(detail, '$.cve_list') LIKE '%' || ? || '%')`, dev, cve, cve)
		if !slices.Contains(openFindings(t, s, dev), cve) && q == 0 {
			t.Errorf("no finding and no question: %s", why)
		}
	}

	t.Run("a row the scheme cannot read may cover the device", func(t *testing.T) {
		t.Parallel()
		s, dev := run(t, "Juniper", "Junos OS", "juniper-junos-os", "22.2R3-S1", `{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","versions":[`+
			`{"version":"22.2","lessThan":"22.2*","status":"affected","versionType":"custom"},`+
			`{"version":"23.2R2-S1","lessThan":"23.2R2-S5","status":"affected","versionType":"custom"}]}`)
		notClosed(t, s, dev, "Juniper lists every 22.2 release as affected (22.2 lessThan 22.2*)")
	})
	t.Run("an exact release is no start of the flaw", func(t *testing.T) {
		t.Parallel()
		s, dev := run(t, "Oracle", "Java SE", "oracle-java-jre-jdk", "1.7.0_80", `{"vendor":"Oracle Corporation","product":"Java SE","versions":[`+
			`{"version":"8u503","status":"affected","versionType":"custom"},`+
			`{"version":"11.0.31","status":"affected","versionType":"custom"},`+
			`{"version":"17.0.19","status":"affected","versionType":"custom"}]}`)
		notClosed(t, s, dev, "Oracle names the newest affected update of each supported train; it says nothing about Java 7")
	})
}
