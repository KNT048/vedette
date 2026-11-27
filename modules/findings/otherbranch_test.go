package findings

import "testing"

// A CVE whose list names several release branches is decided by the branches it can read. OpenSSL lists its 1.0.2 and 1.1.1 branches
// in a letter notation ("1.1.1" before "1.1.1zk") beside the numeric 3.x ranges. A 3.5.0 install is in neither letter branch: the row
// of another branch that does not compare with the version is set aside, and the 3.x ranges decide. Only when no row decides does the
// CVE stay a question.
func TestDecide_RowOfAnotherBranchDoesNotBlockTheDecision(t *testing.T) {
	t.Parallel()
	const (
		any4  = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
		exact = "cpe:2.3:a:openssl:openssl:4.0.0:-:*:*:*:*:*:*"
	)
	row := func(ver string) Software {
		return Software{ID: "s-openssl", Display: "OpenSSL 3.5.0 Light (64-bit)", Vendor: "OpenSSL", Product: "OpenSSL", Version: ver,
			Source: "agent", CPE: any4, KevKeys: []string{"openssl|openssl"}}
	}
	r := func(start, end string) Affected {
		return Affected{CPE: any4, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	letters := []Affected{r("1.0.2", "1.0.2zl"), r("1.1.1", "1.1.1zb"), r("3.0.0", "3.0.16"), r("3.2.0", "3.2.4"), r("3.3.0", "3.3.3"), r("3.4.0", "3.4.1")}
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      Tri
		proof     proofKind
	}{
		{"letter branches, a 3.x install outside every 3.x range", "3.5.0", letters, No, proofRange},
		{"letter branches, a 3.x install inside a 3.x range", "3.4.0", letters, Yes, proofNone},
		{"an exact release of another branch with its update pinned", "3.5.0", []Affected{r("3.6.0", "3.6.3"), {CPE: exact}}, No, proofRange},
		{"the record's rows of the vendor's own list", "3.5.0", []Affected{
			{CPE: "cpe:2.3:*:openssl:openssl:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "4.0.0", EndExcl: "4.0.1"}, VendorList: true},
			{CPE: exact}}, No, proofRange},
		// Nothing but rows of another branch: no row decides, so the CVE is not proved either way.
		{"only rows of another branch", "3.5.0", []Affected{r("1.1.1", "1.1.1zk"), r("1.0.2", "1.0.2zt")}, Unknown, proofNone},
		// The version is of the letter branch itself: the letters decide, which this comparison does not read.
		{"an install of the letter branch", "1.1.1w", []Affected{r("1.1.1", "1.1.1zk"), r("3.0.0", "3.0.24")}, Unknown, proofNone},
		// A row starting nowhere is no branch: "before 1.1.1zk" spans every older release.
		{"a range with no start", "3.5.0", []Affected{{CPE: any4, Range: VersionRange{EndExcl: "1.1.1zk"}}, r("3.0.0", "3.0.24")}, Unknown, proofNone},
	} {
		v := uncVuln("CVE-2026-80131", "OpenSSL", "OpenSSL", uncNew, tc.aff...)
		got, _, _, proof := decide(newSWInfo(row(tc.ver), ""), v, keyIDs(v))
		if got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v (proof %d), want %v (proof %d)", tc.name, got, proof, tc.want, tc.proof)
		}
	}

	// As the device page reads it: the CVE is not a question (not_comparable, version_scheme_mismatch) on a 3.5.0 install.
	a := Asset{ID: "pc", Name: "pc-01", Software: []Software{row("3.5.0")}}
	res := MatchAsset(a, []Vuln{uncVuln("CVE-2026-80132", "OpenSSL", "OpenSSL", uncNew, letters...)}, nil, uncNow)
	if len(res.Unchecked) != 0 || len(res.New) != 0 {
		t.Fatalf("OpenSSL 3.5.0 against a list it is outside of: new %d, unchecked %+v", len(res.New), res.Unchecked)
	}
}

// A row in another notation than the version is not a row of another branch: Windows "1607" against build "10.0.14393" still cannot
// be compared, and stays a question.
func TestDecide_OtherNotationIsNotAnotherBranch(t *testing.T) {
	t.Parallel()
	const office = "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*"
	s := Software{ID: "s-office", Display: "Microsoft Office", Vendor: "Microsoft", Product: "Office", Version: "16.0.4266.1001", Source: "agent",
		CPE: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*", KevKeys: []string{"microsoft|office"}}
	v := uncVuln("CVE-2026-80133", "Microsoft", "Office", uncNew, Affected{CPE: office},
		Affected{CPE: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "17.0.0", EndExcl: "17.0.5"}})
	if got, _, _, _ := decide(newSWInfo(s, ""), v, keyIDs(v)); got == No {
		t.Fatalf("an exact row in another notation was set aside: %v", got)
	}
}
