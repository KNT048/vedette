package feeds

import (
	"slices"
	"testing"
)

// A CVE record entry limited to operating systems (platforms ["Windows"]) is read once per system, each row naming its system as the
// CPE's target_sw, as NVD writes a row for one system: beside NVD's rows it makes a version it states affected on that system only.
// Before, such an entry made the product's rows unusable, and a range the CNA stated beside NVD's single exact version was lost.
func TestRecordSystems_EntryLimitedToSystems(t *testing.T) {
	t.Parallel()
	got, err := ParseCVERecord(record(`{"vendor":"Example","product":"Text Editor","defaultStatus":"unaffected","platforms":["Windows","macOS","x64"],`+
		`"versions":[{"version":"0","lessThan":"8.9.4","status":"affected","versionType":"semver"}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	rows := genericRows(got.Ranges)
	var plats []string
	for _, r := range rows {
		if r.EndExcl != "8.9.4" || r.StartIncl != "" || len(r.Platforms) != 1 {
			t.Errorf("row %+v", r)
			continue
		}
		plats = append(plats, r.Platforms[0])
	}
	if !slices.Equal(plats, []string{"macos", "windows"}) || got.Skipped != 0 {
		t.Fatalf("systems %v (skipped %d), want one row each for macos and windows", plats, got.Skipped)
	}

	// beside NVD's exact row the record's rows only say "affected" (matchRows), on their system
	nvd := Range{CVE: "CVE-2026-1000", Origin: OriginNVD, Part: "a", Vendor: "example", Product: "text_editor",
		CPE: "cpe:2.3:a:example:text_editor:8.9.3:*:*:*:*:*:*:*", Platforms: []string{"microsoft:windows"}}
	var cpes []string
	for _, r := range matchRows(append([]Range{nvd}, rows...)) {
		row, ok := r.MatchRow()
		if !ok {
			t.Fatalf("row %+v not read", r)
		}
		if r.Origin == OriginNVD {
			if row.CPE != nvd.CPE {
				t.Errorf("NVD's row changed: %s", row.CPE) // NVD's running-on platforms are not a target_sw
			}
			continue
		}
		if !row.AffectedOnly || row.EndExcl != "8.9.4" {
			t.Errorf("record row %+v", row)
		}
		cpes = append(cpes, row.CPE)
	}
	want := []string{"cpe:2.3:*:example:texteditor:*:*:*:*:*:macos:*:*", "cpe:2.3:*:example:texteditor:*:*:*:*:*:windows:*:*"}
	if !slices.Equal(cpes, want) {
		t.Fatalf("CPEs %v, want %v", cpes, want)
	}

	// a record row that carries the CNA's own CPE names its system in that CPE's target_sw, unless the CPE already pins one
	for _, tc := range []struct{ cpe, want string }{
		{"cpe:2.3:a:example:text_editor:*:*:*:*:*:*:*:*", "cpe:2.3:a:example:text_editor:*:*:*:*:*:windows:*:*"},
		{"cpe:2.3:a:example:text_editor:*:*:*:*:*:macos:*:*", "cpe:2.3:a:example:text_editor:*:*:*:*:*:macos:*:*"},
	} {
		r := Range{CVE: "CVE-2026-1000", Origin: OriginCNA, Part: "a", Vendor: "example", Product: "text_editor", CPE: tc.cpe,
			EndExcl: "8.9.4", Platforms: []string{"windows"}}
		if row, ok := r.MatchRow(); !ok || row.CPE != tc.want {
			t.Errorf("record row with a CPE: %s (%v), want %s", row.CPE, ok, tc.want)
		}
	}

	// a platform that is neither a processor nor a system (a model) still leaves the entry unread, and a scheme's product keeps its rule
	if s, ok := recordSystems([]string{"Windows", "GW-400"}); ok || s != nil {
		t.Errorf("a model beside a system: %v %v", s, ok)
	}
	if s, ok := recordSystems([]string{"x64", "ARM64-based Systems"}); !ok || s != nil {
		t.Errorf("processors only: %v %v", s, ok)
	}
	never := func(string, string, bool) bool { return false }
	if _, _, ok := entryRows(cnaAffected{Platforms: []string{"Linux"}}, never); ok {
		t.Error("a scheme's product read an entry limited to a system")
	}
}
