package findings

import (
	"slices"
	"testing"
)

// D-488 on the real golden set (KEV + NVD ranges, testdata/kev-nvd-golden.json).
func TestFixedIn_Golden(t *testing.T) {
	vulns := goldenVulns(t)
	vuln := func(cve string) Vuln {
		for _, v := range vulns {
			if v.CVE == cve {
				return v
			}
		}
		t.Fatalf("%s is not in the golden set", cve)
		return Vuln{}
	}
	dev := func(s Software) Asset { return Asset{ID: "a", Name: "dev", Software: []Software{s}} }
	type br = FixedBranch
	cases := []struct {
		name string
		a    Asset
		cve  string
		want *FixedIn
	}{
		{"FortiOS 7.4.1 is fixed in its own branch's 7.4.3, not the 7.2 one", dev(fortiGate(vulns, "7.4.1")), "CVE-2024-21762",
			&FixedIn{Kind: "fixed", Version: "7.4.1", Fixed: "7.4.3"}},
		{"FortiOS 7.2.5 is fixed in 7.2.7", dev(fortiGate(vulns, "7.2.5")), "CVE-2024-21762",
			&FixedIn{Kind: "fixed", Version: "7.2.5", Fixed: "7.2.7"}},
		{"a range that ends at a version that is itself affected names no fix", dev(fortiGate(vulns, "5.6.8")), "CVE-2019-6693",
			&FixedIn{Kind: "up_to", Version: "5.6.8", Fixed: "5.6.10"}},
		{"iOS 16.0.3: the 16 line is fixed in 16.1, not 15.7.1", dev(iPhone(vulns, "16.0.3")), "CVE-2022-42827",
			&FixedIn{Kind: "fixed", Version: "16.0.3", Fixed: "16.1"}},
		{"no version: the fix of every line, newest first, one per line (the highest where a line has two)", dev(fortiGate(vulns, "")), "CVE-2022-42475",
			&FixedIn{Kind: "branches", Branches: []br{{"7.2", "7.2.3"}, {"7.0", "7.0.9"}, {"6.4", "6.4.11"}, {"6.2", "6.2.12"}, {"6.0", "6.0.16"}}}},
		{"no version: the iOS lines, a range with only an end bound included", dev(iPhone(vulns, "")), "CVE-2025-24200",
			&FixedIn{Kind: "branches", Branches: []br{{"18.3", "18.3.1"}, {"16.7", "16.7.11"}, {"15.8", "15.8.4"}}}},
		{"a version outside every range gives nothing", dev(fortiGate(vulns, "7.4.8")), "CVE-2024-21762", nil},
		{"only exact versions or no end bound: nothing is invented", dev(fortiGate(vulns, "6.2.0")), "CVE-2019-6693", nil},
	}
	for _, c := range cases {
		got := FixedInFor(c.a, vuln(c.cve))
		if c.want != nil {
			c.want.Source = FixedInSource
			if c.want.Branches == nil {
				c.want.Branches = []FixedBranch{}
			}
		}
		if (got == nil) != (c.want == nil) || got != nil && (got.Kind != c.want.Kind || got.Version != c.want.Version || got.Fixed != c.want.Fixed ||
			got.More != c.want.More || got.Source != c.want.Source || !slices.Equal(got.Branches, c.want.Branches)) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A range with no end bound, or no NVD data at all, never gives a fix.
func TestFixedIn_NoEndNoData(t *testing.T) {
	sw := Software{ID: "s", Display: "Acme", Vendor: "Acme", Product: "Gate", Version: "2.0", KevKeys: []string{KevKey("Acme", "Gate")}}
	a := Asset{ID: "a", Name: "dev", Software: []Software{sw}}
	if f := FixedInFor(a, Vuln{CVE: "CVE-2024-0001", Vendor: "Acme", Product: "Gate"}); f != nil {
		t.Errorf("no NVD data: %+v", f)
	}
	open := Vuln{CVE: "CVE-2024-0001", Vendor: "Acme", Product: "Gate", Affected: []Affected{{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.0"}}}}
	if f := FixedInFor(a, open); f != nil {
		t.Errorf("a range with no end bound: %+v", f)
	}
}

func TestFixedIn_BranchesAreShort(t *testing.T) {
	f := branches([]string{"1.1.1", "2.2.2", "3.3.3", "4.4.4", "5.5.5", "6.6.6", "7.7.7"})
	if len(f.Branches) != 5 || f.More != 2 || f.Branches[0].Fixed != "7.7.7" || f.Branches[0].Branch != "7.7" {
		t.Errorf("got %+v", f)
	}
}
