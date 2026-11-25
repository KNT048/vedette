package feeds

import (
	"database/sql"
	"maps"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/versionscheme"
)

// Juniper's records list the fixed release of each maintenance branch after lessThan ("22.3 versions before 22.3R2-S2, 22.3R3-S1"):
// the list is kept as one row per branch, so the Junos scheme reads the vendor's word (22.3R2-S3 is fixed, 22.3R3 is not). Before,
// the list was one bound no scheme reads, so the vendor's rows of that release decided nothing. A list in another form stays as
// written.
func TestParseCVERecord_JuniperFixPerBranch(t *testing.T) {
	t.Parallel()
	const u = DefaultUnaffected
	got, err := ParseCVERecord(record(`{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","versions":[`+
		`{"version":"0","lessThan":"21.2R3-S6","status":"affected","versionType":"semver"},`+
		`{"version":"22.3","lessThan":"22.3R2-S2, 22.3R3-S1","status":"affected","versionType":"semver"},`+
		`{"version":"25.2","lessThan":"25.2R1-S2, 25.2R2","status":"affected","versionType":"semver"},`+
		`{"version":"23.2","lessThan":"23.2R2, 23.2R1-S1","status":"affected","versionType":"semver"}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	want := []vspan{{span{ee: "21.2R3-S6", fixed: "21.2R3-S6", def: u}, "vendor:semver"},
		{span{si: "22.3", ee: "22.3R2-S2", fixed: "22.3R2-S2", def: u}, "vendor:semver"}, {span{si: "22.3R3", ee: "22.3R3-S1", fixed: "22.3R3-S1", def: u}, "vendor:semver"},
		{span{si: "25.2", ee: "25.2R1-S2", fixed: "25.2R1-S2", def: u}, "vendor:semver"},
		{span{si: "23.2", ee: "23.2R2, 23.2R1-S1", fixed: "23.2R2, 23.2R1-S1", def: u}, "vendor:semver"}} // not in branch order: as written
	if v := vendorSpans(got.Ranges); !slices.Equal(v, want) {
		t.Fatalf("rows %+v, want %+v", v, want)
	}
	var sp []versionscheme.Span
	for _, r := range got.Ranges {
		r.Vendor, r.Product = "juniper", "junosos"
		if _, s, _, ok := RangeScheme(r); ok {
			sp = append(sp, s)
		}
	}
	if len(sp) != 4 {
		t.Fatalf("the Junos scheme reads %d rows, want 4", len(sp))
	}
	for ver, want := range map[string]versionscheme.State{
		"22.3R2-S1": versionscheme.Affected, "22.3R2-S3": versionscheme.NotAffected, "22.3R3": versionscheme.Affected, "22.3R3-S1": versionscheme.NotAffected,
		"25.2R1-S1": versionscheme.Affected, "25.2R1-S3": versionscheme.NotAffected, "25.2R2": versionscheme.NotAffected, "15.1R7.9": versionscheme.Affected,
	} {
		in, ok := versionscheme.Junos.Installed(ver, "")
		if !ok {
			t.Fatalf("%s does not read", ver)
		}
		if got := versionscheme.Judge(in, sp).State; got != want {
			t.Errorf("%s: %v, want %v", ver, got, want)
		}
	}
}

// A vendor's explicit "unaffected" statement and an entry limited to some models are kept for the product's version scheme
// (CVE-2026-21913's real record: Juniper's Junos OS on EX4000 models, defaultStatus unaffected, unaffected from 0 before 24.4R1):
// the unaffected range as a row of its own (UnaffectedNotation), the model-limited affected ranges with their models in platforms.
// Neither is read as an affected range by any existing reader (RangeScheme, the generic comparison); StatementScheme reads them, so
// the scheme can say "not affected" from them and never "affected".
func TestParseCVERecord_VendorUnaffectedAndModelRows(t *testing.T) {
	t.Parallel()
	const u = DefaultUnaffected
	got, err := ParseCVERecord(record(`{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected",`+
		`"platforms":["EX4000-48T","EX4000-48P","EX4000-48MP"],"versions":[`+
		`{"version":"24.4","lessThan":"24.4R2","status":"affected","versionType":"semver"},`+
		`{"version":"25.2","lessThan":"25.2R1-S2, 25.2R2","status":"affected","versionType":"semver"},`+
		`{"version":"0","lessThan":"24.4R1","status":"unaffected","versionType":"semver"}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	want := []vspan{{span{ee: "24.4R1", def: u}, UnaffectedNotation},
		{span{si: "24.4", ee: "24.4R2", fixed: "24.4R2", def: u}, "vendor:semver"},
		{span{si: "25.2", ee: "25.2R1-S2", fixed: "25.2R1-S2", def: u}, "vendor:semver"}}
	if v := vendorSpans(got.Ranges); !slices.Equal(v, want) {
		t.Fatalf("rows %+v, want %+v", v, want)
	}
	models := []string{"EX4000-48T", "EX4000-48P", "EX4000-48MP"}
	for _, r := range got.Ranges {
		if !slices.Equal(r.Platforms, models) {
			t.Errorf("row %+v: platforms %v, want the entry's models", r, r.Platforms)
		}
		r.Vendor, r.Product = "juniper", "junosos"
		if _, _, _, ok := RangeScheme(r); ok {
			t.Errorf("row %+v: read as an affected range", r)
		}
		_, _, unaffected, ok := StatementScheme(r)
		if !ok || unaffected != r.Unaffected() {
			t.Errorf("row %+v: statement read %v, unaffected %v", r, ok, unaffected)
		}
	}
	// a product without a version scheme keeps neither (nothing would read them)
	other, err := ParseCVERecord(record(`{"vendor":"Example","product":"Router","defaultStatus":"unaffected","platforms":["R100"],"versions":[`+
		`{"version":"2.0","lessThan":"2.4","status":"affected","versionType":"semver"},{"version":"0","lessThan":"2.0","status":"unaffected","versionType":"semver"}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	if v := vendorSpans(other.Ranges); len(v) != 0 {
		t.Errorf("a product without a scheme: rows %+v, want none", v)
	}
}

// The rows of a model-limited entry are stored with their models (feeds_cve_range.platforms) and read back for the version scheme
// (SchemeRangesOf); a record whose models change replaces them.
func TestStoreCVERecord_ModelsKept(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2026-1000"
	s, db := newStore(t)
	nvd := NVDRecord{CVE: cve, Published: epoch0.AddDate(0, -1, 0), LastModified: epoch0, Status: "Analyzed", Description: "A flaw.",
		Affected: []AffectedRow{{CPE: "cpe:2.3:o:juniper:junos:24.4:r1:*:*:*:*:*:*"}}}
	entry := func(models string) CVERecord {
		rec, err := ParseCVERecord(record(`{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":[`+models+`],"versions":[`+
			`{"version":"24.4","lessThan":"24.4R2","status":"affected","versionType":"semver"},`+
			`{"version":"0","lessThan":"24.4R1","status":"unaffected","versionType":"semver"}]}`), cve)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	stored := func(rec CVERecord) map[string][]string {
		write(t, db, func(tx *sql.Tx) error {
			if err := storeRecords(t.Context(), tx, []NVDRecord{nvd}, epoch0); err != nil {
				return err
			}
			k, err := recordKeepOf(t.Context(), tx, epoch0, nil)
			if err != nil {
				return err
			}
			_, err = writeRecords(t.Context(), tx, []CVERecord{rec}, k, epoch0)
			return err
		})
		rows, err := s.SchemeRangesOf(t.Context(), []string{cve})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, r := range rows {
			if r.Origin == OriginCNA {
				out[r.VersionType+" "+r.StartIncl+"-"+r.EndExcl] = r.Platforms
			}
		}
		return out
	}
	ex := []string{"EX4000-48T", "EX4000-48P"}
	want := map[string][]string{UnaffectedNotation + " -24.4R1": ex, "vendor:semver 24.4-24.4R2": ex}
	if got := stored(entry(`"EX4000-48T","EX4000-48P"`)); !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("stored %v, want %v", got, want)
	}
	series := []string{"EX Series"}
	want = map[string][]string{UnaffectedNotation + " -24.4R1": series, "vendor:semver 24.4-24.4R2": series}
	if got := stored(entry(`"EX Series"`)); !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("after the models changed: stored %v, want %v", got, want)
	}
}
