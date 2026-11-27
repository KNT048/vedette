package findings

import "testing"

// A list of exact affected releases only (no range, no fix, no unaffected word) says which releases its writer found affected. From
// the product's own vendor (its CNA, or NVD's rows of a record the vendor assigned) it is the vendor's enumeration: a later release it
// does not list is not affected. From a third party (a lab that tested one build) it says nothing about a later release: the CVE stays
// possible, undecided as third_party_tested_build.
func TestExactList_AThirdPartysTestedBuildDecidesNothingPastIt(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "pc", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{{ID: "s-1", Display: "Acme Desk", Vendor: "Acme",
		Product: "Acme Desk", Version: "3.7.6", Source: "agent", KevKeys: []string{"acme|acme desk"}}}}
	vuln := func(cve string, vendorCNA bool) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Published: uncNew, Affected: []Affected{
			{CPE: "cpe:2.3:*:acme:acme_desk:3.0.4:*:*:*:*:*:*:*", AffectedOnly: true, VendorCNA: vendorCNA}, // the record's row beside NVD's
			{CPE: "cpe:2.3:a:acme:acme_desk:3.0.4:*:*:*:*:*:*:*", VendorCNA: vendorCNA}}}
	}
	partial := Vuln{CVE: "CVE-2026-90023", NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrgPartial, Published: uncNew, Affected: []Affected{
		{CPE: "cpe:2.3:*:acme:acme_desk:2.0.15:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:*:acme:acme_desk:3.0.1:*:*:*:*:*:*:*"}}}
	res := MatchAsset(a, []Vuln{vuln("CVE-2026-90021", false), vuln("CVE-2026-90022", true), partial}, nil, uncNow)
	got := uncByCVE(res.Unchecked)
	for _, cve := range []string{"CVE-2026-90021", "CVE-2026-90023"} {
		u, ok := got["s-1 "+cve]
		if !ok || u.undecided == nil || u.undecided.Reason != UndecidedThirdPartyBuild {
			t.Errorf("%s: unchecked %+v, want possible as a third party's tested build", cve, u)
		}
	}
	if u, ok := got["s-1 CVE-2026-90022"]; ok {
		t.Errorf("the vendor's own list of exact releases: unchecked %+v, want decided (not affected)", u)
	}
	if len(res.New) != 0 || len(res.NeedVersion) != 0 {
		t.Errorf("new %+v, need version %+v", res.New, res.NeedVersion)
	}
}
