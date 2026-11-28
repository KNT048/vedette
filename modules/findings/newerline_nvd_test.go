package findings

import "testing"

// A CVE on no exploited list reaches a line through NVD's list alone (viaNVD), where an exact release says nothing by itself (#913):
// the vendor's own exact list read per line closes there as on the exploited list's path, and nothing else does. Synthetic product.
func TestMatch_ExactListClosesOnTheNVDPath(t *testing.T) {
	t.Parallel()
	var aff []Affected
	for _, v := range []string{"4.2.9", "5.1.3"} {
		aff = append(aff, Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:" + v + ":*:*:*:*:*:*:*", VendorCNA: true})
	}
	third := make([]Affected, len(aff))
	for i, af := range aff {
		af.VendorCNA = false
		third[i] = af
	}
	for _, tc := range []struct {
		ver    string
		rows   []Affected
		closes bool
	}{{"4.2.10", aff, true}, {"6.0.1", aff, true}, {"5.0.1", aff, false}, {"4.2.8", aff, false}, {"6.0.1", third, false}, {"4.2.10", third, false}} {
		s := Software{ID: "w", Display: "Gizmo " + tc.ver, Vendor: "Examplecorp", Product: "Gizmo", Version: tc.ver, Source: "agent"}
		a := Asset{ID: "pc", Name: "pc.example.com", Software: []Software{s}}
		v := Vuln{CVE: "CVE-2099-0204", NVDAnswered: true, Affected: tc.rows, DateAdded: uncNew, Published: uncNew}
		if _, out := matchOne(a, s, swInfoOn(s, a), v, false, nil, true, uncNow); (out == outNotAffected) != tc.closes {
			t.Errorf("%s (vendor's CNA %v): outcome %v, closes want %v", tc.ver, tc.rows[0].VendorCNA, out, tc.closes)
		}
	}
}
