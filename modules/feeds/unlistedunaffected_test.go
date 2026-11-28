package feeds

import (
	"strings"
	"testing"
)

// The vendor's own word on the versions its record does not list (CVE JSON 5 defaultStatus "unaffected"): only the product's own CNA
// states it (a third party lists what it tested, an entry with no vendor does not say whose product it is), and it names the product
// with the names a record row gets for matching.
func TestUnlistedUnaffected_OnlyTheProductsOwnCNA(t *testing.T) {
	t.Parallel()
	ranged := `"versions":[{"version":"8.0.0","lessThan":"8.0.21","status":"affected","versionType":"semver"}]`
	for _, c := range []struct {
		name, assigner, entry string
		want                  bool
	}{
		{"unaffected, the vendor's CNA", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, true},
		{"unaffected, a third party", "VulnCheck", `{"vendor":"Acme","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, false},
		{"unaffected, no vendor named", "acme", `{"vendor":"n/a","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, false},
		{"affected, the vendor's CNA", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"affected",` + ranged + `}`, false},
		{"unknown", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"unknown",` + ranged + `}`, false},
		{"absent", "acme", `{"vendor":"Acme","product":"Box",` + ranged + `}`, false},
	} {
		raw := strings.Replace(string(record(c.entry)), `"assignerShortName":"acme"`, `"assignerShortName":"`+c.assigner+`"`, 1)
		rec, err := ParseCVERecord([]byte(raw), "CVE-2026-1000")
		if err != nil || len(rec.Ranges) != 1 {
			t.Fatalf("%s: %+v %v", c.name, rec.Ranges, err)
		}
		cpe, ok := asRead(rec).Ranges[0].UnlistedUnaffectedCPE()
		if ok != c.want || ok && cpe != "cpe:2.3:*:acme:box:*:*:*:*:*:*:*:*" {
			t.Errorf("%s: %q %v, want %v", c.name, cpe, ok, c.want)
		}
	}
}
