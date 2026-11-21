package findings

import (
	"testing"
)

// Auto-resolve in the matcher: a proof is listed only for a CVE the device has a finding for, and only when every software
// of the product is proved outside (a second copy that needs a version proves nothing).
func TestMatchAsset_NotAffectedNeedsEverySoftwareProved(t *testing.T) {
	t.Parallel()
	v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	have := map[string]bool{v.CVE: true}
	if r := MatchAsset(nas("6.2.0"), []Vuln{v}, have, t0); len(r.NotAffected) != 1 || r.NotAffected[0].CVE != v.CVE {
		t.Fatalf("one software outside: %+v", r)
	}
	if r := MatchAsset(nas("6.2.0"), []Vuln{v}, nil, t0); len(r.NotAffected) != 0 {
		t.Fatalf("no finding to close, yet listed: %+v", r)
	}
	a := nas("6.2.0")
	a.Software = append(a.Software, Software{ID: "s-2", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", KevKeys: []string{"qnap|photo station"}})
	if r := MatchAsset(a, []Vuln{v}, have, t0); len(r.NotAffected) != 0 {
		t.Fatalf("a second copy without a version still needs deciding: %+v", r)
	}
}
