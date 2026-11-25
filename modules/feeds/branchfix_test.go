package feeds

import (
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
