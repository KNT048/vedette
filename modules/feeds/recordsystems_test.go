package feeds

import (
	"slices"
	"strings"
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
	rows := genericRows(asRead(got).Ranges)
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

// A lone unaffected version above every affected row reaches the matcher as the fix of the line the rows end on (LineFix), on the row
// that ends highest, in both views; a row's own fixed release at its excluded end is no such fix.
func TestRecordRanges_LineFixReachesTheMatcher(t *testing.T) {
	t.Parallel()
	got, err := ParseCVERecord(record(`{"vendor":"Example","product":"Router OS","versions":[`+
		`{"version":"0","lessThanOrEqual":"6.49.18","status":"affected"},{"version":"7.0.0","lessThanOrEqual":"7.11.2","status":"affected"},`+
		`{"version":"7.24.0","status":"unaffected"}]},`+
		`{"vendor":"Example","product":"Firmware","cpes":["cpe:2.3:o:example:firmware:*:*:*:*:*:*:*:*"],"versions":[{"version":"3.0","lessThanOrEqual":"3.4","status":"affected"},{"version":"3.9","status":"unaffected"}]},`+
		`{"vendor":"Example","product":"Mail Relay","versions":[{"version":"2.0","lessThan":"2.0.7","status":"affected","changes":[{"at":"2.0.7","status":"unaffected"}]}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	var fixes []string
	for _, r := range genericRows(got.Ranges) {
		row, ok := r.MatchRow()
		if !ok {
			t.Fatalf("row %+v not read", r)
		}
		fixes = append(fixes, row.LineFix)
	}
	if want := []string{"", "7.24.0", "3.9", ""}; !slices.Equal(fixes, want) {
		t.Fatalf("MatchRow line fixes %q, want %q", fixes, want)
	}
	rows, _ := KEVRecordRows(got.Ranges, "Example", "Router OS")
	if len(rows) != 2 || rows[0].LineFix != "" || rows[1].LineFix != "7.24.0" {
		t.Fatalf("exploited-list view %+v, want the line fix on the row that ends highest", rows)
	}
}

// An entry of a product the reader cannot keep (a version "unspecified", "n/a" or of status unknown, and no defaultStatus; an affected
// version that names none beside the entry's ranges) is a statement the rows do not carry: the product may be affected on any system,
// at any version. Every row of that product in the record then only ever says "affected" (Range.Lost): a version inside it is
// affected, a version outside it, past its fix or on another system proves nothing, and the list is never complete. An entry whose
// product cannot be told (no product, a CPE list naming two products) makes every row of the record so.
func TestRecordSystems_ADroppedEntryMakesTheProductAffectedOnly(t *testing.T) {
	t.Parallel()
	const ios = `{"vendor":"Acme","product":"Meeting App","platforms":["iOS"],"versions":[{"version":"0","lessThan":"7.0.0","status":"affected","versionType":"custom"}]}`
	adp := func(entry string) []byte {
		return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-1000","state":"PUBLISHED","assignerShortName":"acme",` +
			`"datePublished":"2026-11-01T10:00:00.000Z","dateUpdated":"2026-11-01T12:00:00.000Z"},"containers":{"cna":{"affected":[` + ios + `]},` +
			`"adp":[{"providerMetadata":{"orgId":"00000000-0000-0000-0000-000000000000","shortName":"example-adp"},"affected":[` + entry + `]}]}}`)
	}
	for _, tc := range []struct {
		name string
		rec  []byte
		lost bool
	}{
		{"alone", record(ios), false},
		{"beside a Windows entry of an unspecified version", record(`{"vendor":"Acme","product":"Meeting App","platforms":["Windows"],` +
			`"versions":[{"version":"unspecified","status":"affected"}]},` + ios), true},
		{"beside an entry of every system with n/a", record(`{"vendor":"Acme","product":"Meeting App","versions":[{"version":"n/a","status":"affected"}]},` + ios), true},
		{"beside a Linux entry of status unknown", record(`{"vendor":"Acme","product":"Meeting App","platforms":["Linux"],` +
			`"versions":[{"version":"5.0","status":"unknown"}]},` + ios), true},
		{"beside an entry whose one version is of status unknown, the rest unaffected", record(`{"vendor":"Acme","product":"Meeting App",` +
			`"platforms":["Windows"],"defaultStatus":"unaffected","versions":[{"version":"7.1.9","status":"unknown"}]},` + ios), true},
		{"beside an entry with an unspecified version beside its range", record(`{"vendor":"Acme","product":"Meeting App","platforms":["Windows"],` +
			`"versions":[{"version":"0","lessThan":"6.0","status":"affected"},{"version":"unspecified","status":"affected"}]},` + ios), true},
		{"beside an entry that states every version unaffected", record(`{"vendor":"Acme","product":"Meeting App","platforms":["Windows"],` +
			`"defaultStatus":"unaffected","versions":[{"version":"6.0","status":"unaffected"}]},` + ios), false},
		{"beside another product's dropped entry", record(`{"vendor":"Acme","product":"Meeting SDK","versions":[{"version":"n/a","status":"affected"}]},` + ios), false},
		{"beside an entry naming two products in its CPEs", record(`{"vendor":"Acme","product":"Meeting Suite","cpes":["cpe:2.3:a:acme:meeting_sdk:*:*:*:*:*:*:*:*",` +
			`"cpe:2.3:a:acme:meeting_server:*:*:*:*:*:*:*:*"],"versions":[{"version":"0","lessThan":"7.0.0","status":"affected"}]},` + ios), true},
		{"an ADP's entry naming no vendor", adp(`{"vendor":"n/a","product":"Meeting App","versions":[{"version":"0","lessThan":"7.0.0","status":"affected"}]}`), true},
		{"an ADP's dropped entry of the product", adp(`{"vendor":"Acme","product":"Meeting App","versions":[{"version":"unspecified","status":"affected"}]}`), true},
		{"a dropped entry naming the product by its CPE", record(`{"vendor":"Acme","product":"Meeting App","platforms":["Windows"],` +
			`"cpes":["cpe:2.3:a:acme:meeting_app:*:*:*:*:*:*:*:*"],"versions":[{"version":"unspecified","status":"affected"}]},` + ios), true},
		{"an ADP's dropped entry naming the product by its CPE", adp(`{"vendor":"Acme","product":"Meeting App",` +
			`"cpes":["cpe:2.3:a:acme:meeting_app:*:*:*:*:*:*:*:*"],"versions":[{"version":"unspecified","status":"affected"}]}`), true},
		{"an ADP's dropped entry beside a list the vendor states complete", []byte(strings.Replace(string(adp(
			`{"vendor":"Acme","product":"Meeting App","versions":[{"version":"n/a","status":"affected"}]}`)),
			`"platforms":["iOS"],`, `"platforms":["iOS"],"defaultStatus":"unaffected",`, 1)), true},
	} {
		got, err := ParseCVERecord(tc.rec, "CVE-2026-1000")
		if err != nil {
			t.Fatal(err)
		}
		var rows []Range
		for _, r := range genericRows(got.Ranges) {
			if r.Product == "meetingapp" && r.Origin == OriginCNA && r.EndExcl == "7.0.0" {
				rows = append(rows, r)
			}
		}
		if len(rows) != 1 || rows[0].EndExcl != "7.0.0" || !slices.Equal(rows[0].Platforms, []string{"iphone_os"}) {
			t.Errorf("%s: rows %+v, want the one iOS range", tc.name, rows)
			continue
		}
		r := rows[0]
		r.VendorCNA = true
		if r.Lost() != tc.lost {
			t.Errorf("%s: lost %v, want %v", tc.name, r.Lost(), tc.lost)
			continue
		}
		row, ok := r.MatchRow()
		if !ok {
			t.Fatalf("%s: row not read", tc.name)
		}
		if tc.lost && (r.StatesUnlisted() || !row.AffectedOnly || !row.Lost) {
			t.Errorf("%s: a row of a product with a dropped entry reads as %+v (states unlisted %v)", tc.name, row, r.StatesUnlisted())
		}
		if m := matchRows([]Range{r}); len(m) != 1 || tc.lost && (m[0].VendorList || !m[0].AffectedOnly) {
			t.Errorf("%s: as matched %+v", tc.name, m)
		}
	}
}

// What a version the list does not name is: only a list whose author states it for every row is complete. A third party's entry that
// calls every version on one system affected says nothing of another system; an entry with a version of status unknown does not
// state every version.
func TestRecordSystems_WhatAListStatesOfTheVersionsItDoesNotName(t *testing.T) {
	t.Parallel()
	every := Range{CVE: "CVE-2026-1000", Origin: OriginCNA, Vendor: "acme", Product: "meetingapp", DefaultStatus: DefaultAffected, Platforms: []string{"android"}}
	vendor := every
	vendor.VendorCNA = true
	plain := every
	plain.Platforms = nil
	for _, tc := range []struct {
		name string
		r    Range
		want bool
	}{
		{"a third party's every version on one system", every, false},
		{"the vendor's every version on one system", vendor, true},
		{"a third party's every version on every system", plain, true},
	} {
		if got := tc.r.StatesUnlisted(); got != tc.want {
			t.Errorf("%s: states unlisted %v, want %v", tc.name, got, tc.want)
		}
		if m := matchRows([]Range{tc.r}); len(m) != 1 || m[0].VendorList != tc.want {
			t.Errorf("%s: as matched %+v, want vendor list %v", tc.name, m, tc.want)
		}
	}

	got, err := ParseCVERecord(record(`{"vendor":"Acme","product":"Meeting App","defaultStatus":"unaffected","versions":[`+
		`{"version":"0","lessThan":"7.0.0","status":"affected"},{"version":"7.1.9","status":"unknown"}]}`), "CVE-2026-1000")
	if err != nil {
		t.Fatal(err)
	}
	rows := genericRows(got.Ranges)
	if len(rows) != 1 || rows[0].DefaultStatus != DefaultUnknown || rows[0].Lost() {
		t.Fatalf("an entry with a version of status unknown: %+v, want one range whose unlisted versions are unknown", rows)
	}
}
