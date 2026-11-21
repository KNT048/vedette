package feeds

import (
	"database/sql"
	"slices"
	"testing"
)

// The readers of the match pass: the products the ranges name (a record's product key marked), the ranges of named CVEs with the
// precedence applied, the rows kept in a vendor's notation, the matcher's entry of a record row (by the catalogue's name of the
// product), and the distributions' word on any CVE.
func TestMatchReaders(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	now := epoch0
	write(t, db, func(tx *sql.Tx) error {
		err := storeRecords(t.Context(), tx, []NVDRecord{
			{CVE: "CVE-2026-0201", Published: now.AddDate(0, -2, 0), LastModified: now, Status: "Analyzed",
				Affected: []AffectedRow{{CPE: "cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}},
			{CVE: "CVE-2026-0202", Published: now.AddDate(0, -1, 0), LastModified: now, Status: "Received", Affected: []AffectedRow{}},
			{CVE: "CVE-2026-0203", Published: now.AddDate(0, -1, 0), LastModified: now, Status: "Received", Affected: []AffectedRow{}},
		}, now)
		if err != nil {
			return err
		}
		recs := []CVERecord{
			{CVE: "CVE-2026-0201", State: RecordPublished, Ranges: []Range{{CVE: "CVE-2026-0201", Origin: OriginCNA, Vendor: "acme", Product: "box", EndExcl: "1.9", DefaultStatus: DefaultUnaffected}}},
			{CVE: "CVE-2026-0202", State: RecordPublished, Ranges: []Range{{CVE: "CVE-2026-0202", Origin: OriginCNA, Vendor: "paloalto", Product: "panos", StartIncl: "11.1.0", EndExcl: "11.1.5", DefaultStatus: DefaultUnaffected}}},
			{CVE: "CVE-2026-0203", State: RecordPublished, Ranges: []Range{{CVE: "CVE-2026-0203", Origin: OriginCNA, Vendor: "vmware", Product: "esxi", StartIncl: "8.0", EndExcl: "ESXi80U3d-24585383", Fixed: "ESXi80U3d-24585383", VersionType: VendorNotation + "custom", DefaultStatus: DefaultUnaffected}}},
		}
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		if _, err := writeRecords(t.Context(), tx, recs, k, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(t.Context(), `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '24.04', 'box', 'CVE-2026-0201', 'fixed', '1.8-1')`)
		return err
	})
	prods, err := s.RangeProducts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []RangeProduct{{"acme", "box", false}, {"acme", "box", true}, {"paloalto", "panos", true}, {"vmware", "esxi", true}} {
		if !slices.Contains(prods, want) {
			t.Errorf("RangeProducts %+v: no %+v", prods, want)
		}
	}
	got, err := s.RangesOf(t.Context(), []string{"CVE-2026-0201", "CVE-2026-0202", "CVE-2026-0203", "CVE-2099-0001"})
	if err != nil {
		t.Fatal(err)
	}
	var origins []string
	for _, r := range got {
		origins = append(origins, r.CVE+"/"+r.Origin)
	}
	if !slices.Equal(origins, []string{"CVE-2026-0201/nvd", "CVE-2026-0202/cna"}) { // NVD's win; the vendor's notation is never generic
		t.Errorf("RangesOf %v", origins)
	}
	vendor, err := s.VendorRangesOf(t.Context(), []string{"CVE-2026-0201", "CVE-2026-0203"})
	if err != nil || len(vendor) != 1 || vendor[0].CVE != "CVE-2026-0203" {
		t.Fatalf("VendorRangesOf %+v %v", vendor, err)
	}
	if _, sp, fixed, ok := RangeScheme(vendor[0]); !ok || sp.End == nil || fixed == nil {
		t.Errorf("the ESXi row does not read in its scheme")
	}
	row, ok := got[1].MatchRow()
	if !ok || row.CPE != "cpe:2.3:*:paloalto:panos:*:*:*:*:*:*:*:*" || row.StartIncl != "11.1.0" || row.EndExcl != "11.1.5" {
		t.Errorf("record row of a product the catalogue files do not list, as the matcher reads it: %+v %v", row, ok) // the line answers to it (recordIdentity)
	}
	if row, ok := (Range{Origin: OriginCNA, Vendor: "jenkinsproject", Product: "jenkins", EndExcl: "2.500"}).MatchRow(); !ok || row.CPE != "cpe:2.3:*:jenkins:jenkins:*:*:*:*:*:*:*:*" {
		t.Errorf("record row of a catalogue product: %+v %v", row, ok) // by the product's NVD name
	}
	if v, p := MatchName("unknownco", "gadget", true); v != "unknownco" || p != "gadget" {
		t.Errorf("a record key the catalogue does not know: %s %s", v, p)
	}
	if _, ok := (Range{Origin: OriginCNA, Vendor: "juniper", Product: "junos", EndExcl: "1"}).MatchRow(); ok {
		t.Error("a record row of a vendor findings compares itself")
	}
	distro, err := s.DistroFixesFor(t.Context(), []string{"CVE-2026-0201"})
	if err != nil || len(distro["CVE-2026-0201"]) != 1 || distro["CVE-2026-0201"][0].Fixed != "1.8-1" {
		t.Errorf("DistroFixesFor %+v %v", distro, err)
	}
}
