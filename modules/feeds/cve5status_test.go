package feeds

import (
	"strings"
	"testing"
)

// The status semantics of CVE JSON 5 (https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md) as the rows the
// match reads: a version takes the status of the entry that names it, else the entry's defaultStatus; without one, unknown. The table
// is every defaultStatus word by who assigned the record. "unaffected" for the versions an entry does not list counts only from the
// vendor's own CNA (ownCNA): a third party lists the releases it tested. An entry whose defaultStatus is affected states every version
// affected, and the matcher reads it from version 0 (recordEvery); a version word alone ("all") without defaultStatus does not.
func TestCVE5Status_DefaultStatusByAssigner(t *testing.T) {
	t.Parallel()
	ranged := `"versions":[{"version":"4.0.0","lessThan":"4.0.1","status":"affected","versionType":"semver"}]`
	for _, c := range []struct {
		name, assigner, entry string
		def                   string // the default_status the rows keep
		vendorList            bool   // the product's list decides "not affected" too (matchRows' VendorList)
		every                 bool   // the matcher reads the row as every version (from 0)
	}{
		{"affected, the vendor's CNA", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"affected",` + ranged + `}`, DefaultAffected, true, true},
		{"affected, a third party", "VulnCheck", `{"vendor":"Acme","product":"Box","defaultStatus":"affected",` + ranged + `}`, DefaultAffected, true, true},
		{"unaffected, the vendor's CNA", "acme", `{"vendor":"Acme Inc.","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnaffected, true, false},
		{"unaffected, a third party", "VulnCheck", `{"vendor":"Acme","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnknown, false, false},
		{"unaffected, the CNA's own product (vendor n/a)", "acme", `{"vendor":"n/a","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnaffected, true, false},
		{"unknown", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"unknown",` + ranged + `}`, DefaultUnknown, false, false},
		{"absent", "acme", `{"vendor":"Acme","product":"Box",` + ranged + `}`, DefaultUnknown, false, false},
		{"absent, every version as a word", "acme", `{"vendor":"Acme","product":"Box","versions":[{"version":"all","status":"affected"}]}`, DefaultUnknown, false, false},
	} {
		raw := strings.Replace(string(record(c.entry)), `"assignerShortName":"acme"`, `"assignerShortName":"`+c.assigner+`"`, 1)
		rec, err := ParseCVERecord([]byte(raw), "CVE-2026-1000")
		if err != nil || len(rec.Ranges) != 1 {
			t.Fatalf("%s: %+v %v", c.name, rec.Ranges, err)
		}
		r := rec.Ranges[0]
		if r.DefaultStatus != c.def {
			t.Errorf("%s: default_status %q, want %q", c.name, r.DefaultStatus, c.def)
		}
		nvd := Range{CVE: r.CVE, Origin: OriginNVD, Part: "a", Vendor: "acme", Product: "box", CPE: "cpe:2.3:a:acme:box:4.0.0:*:*:*:*:*:*:*"}
		got := matchRows([]Range{nvd, r})
		if len(got) != 2 || got[1].VendorList != c.vendorList || got[1].AffectedOnly == c.vendorList {
			t.Errorf("%s: beside NVD's rows %+v, want vendor list %v (else affected only)", c.name, got, c.vendorList)
		}
		row, ok := r.MatchRow()
		if every := ok && row.StartIncl == "0" && row.EndExcl == "" && row.EndIncl == ""; every != c.every {
			t.Errorf("%s: the matcher's row %+v, every version %v, want %v", c.name, row, every, c.every)
		}
	}
}
