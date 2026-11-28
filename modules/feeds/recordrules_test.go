package feeds

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// An unaffected range whose start is written as words instead of a release ("all version prior to" lessThan "23.4R1") states every
// release before its end unaffected, as "0" does: the words name no release a range could start at. A start that names a release
// stays that release.
func TestUnaffectedRows_ProseStartIsTheFirstRelease(t *testing.T) {
	t.Parallel()
	var entries []cnaAffected
	if err := json.Unmarshal([]byte(`[{"vendor":"Acme","product":"Switch OS","defaultStatus":"unaffected","versions":[`+
		`{"version":"23.4","lessThan":"23.4R2-S4","status":"affected","versionType":"semver"},`+
		`{"version":"all version prior to","lessThan":"23.4R1","status":"unaffected","versionType":"semver"},`+
		`{"version":"All Versions Before","lessThan":"21.1R1","status":"unaffected","versionType":"semver"},`+
		`{"version":"20.2R1","lessThan":"20.2R3","status":"unaffected","versionType":"semver"}]}]`), &entries); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range unaffectedRows(entries) {
		got = append(got, r.StartIncl+"-"+r.EndExcl)
	}
	if want := []string{"-23.4R1", "-21.1R1", "20.2R1-20.2R3"}; !slices.Equal(got, want) {
		t.Fatalf("unaffected rows %q, want %q", got, want)
	}
}

// An entry that lists its affected releases and states several single releases unaffected, every one above the last affected release
// (a fixed release per train: "7.21.5" and "7.23.1" above 7.20.8), keeps the highest of them as the fix of the line the rows end on
// (LineFix): a release at or past it on that line is past every fix the record states. An unaffected release below the end of an
// affected row, or the highest one on another line, keeps no fix.
func TestRecordRanges_SeveralFixedReleasesGiveTheLineFix(t *testing.T) {
	t.Parallel()
	entry := func(unaffected ...string) string {
		var b strings.Builder
		b.WriteString(`{"vendor":"Example","product":"Router OS","versions":[`)
		for _, v := range []string{"6.0", "6.44", "7.20.0", "7.20.8"} {
			b.WriteString(`{"version":"` + v + `","status":"affected"},`)
		}
		for i, v := range unaffected {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"version":"` + v + `","status":"unaffected"}`)
		}
		b.WriteString(`]}`)
		return b.String()
	}
	for _, tc := range []struct {
		name       string
		unaffected []string
		want       string
	}{
		{"two fixed releases above every affected one", []string{"7.21.5", "7.23.1"}, "7.23.1"},
		{"listed in any order", []string{"7.23.1", "7.21.5"}, "7.23.1"},
		{"one fixed release (as before)", []string{"7.21.5"}, "7.21.5"},
		{"one is below the end of an affected release", []string{"6.40", "7.23.1"}, ""},
		{"the highest is on another line", []string{"7.21.5", "8.0.1"}, ""},
	} {
		got, err := ParseCVERecord(record(entry(tc.unaffected...)), "CVE-2026-1000")
		if err != nil {
			t.Fatal(err)
		}
		fix := ""
		for _, r := range genericRows(got.Ranges) {
			row, ok := r.MatchRow()
			if !ok {
				t.Fatalf("%s: row %+v not read", tc.name, r)
			}
			if row.LineFix != "" {
				if fix != "" {
					t.Fatalf("%s: two rows carry a line fix", tc.name)
				}
				fix = row.LineFix
			}
		}
		if fix != tc.want {
			t.Errorf("%s: line fix %q, want %q", tc.name, fix, tc.want)
		}
	}
}

// A model-limited row says its product's unlisted versions are unaffected (default_status unaffected) only from the vendor's own CNA:
// whoever else wrote the record listed the hardware it tested, so its silence about other hardware is no statement (ownCNA). The
// vendor's own record keeps the word.
func TestParseCVERecord_ModelRowsKeepTheDefaultOnlyFromTheVendor(t *testing.T) {
	t.Parallel()
	entry := `{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":["QRX Series"],"versions":[` +
		`{"version":"24.2","lessThan":"24.2R2-S2","status":"affected","versionType":"semver"}]}`
	for _, tc := range []struct {
		assigner, want string
	}{
		{"acme", DefaultUnknown},
		{"juniper", DefaultUnaffected},
	} {
		raw := strings.Replace(string(record(entry)), `"assignerShortName":"acme"`, `"assignerShortName":"`+tc.assigner+`"`, 1)
		got, err := ParseCVERecord([]byte(raw), "CVE-2026-1000")
		if err != nil {
			t.Fatal(err)
		}
		got = asRead(got)
		n := 0
		for _, r := range got.Ranges {
			if !r.ModelLimited() {
				continue
			}
			n++
			if r.DefaultStatus != tc.want || r.Fixed != "24.2R2-S2" || !slices.Equal(r.Platforms, []string{"QRX Series"}) {
				t.Errorf("assigner %s: row %+v, want default %s, the fix and the platform", tc.assigner, r, tc.want)
			}
		}
		if n != 1 {
			t.Errorf("assigner %s: %d model-limited rows, want 1 (%+v)", tc.assigner, n, got.Ranges)
		}
	}
}
