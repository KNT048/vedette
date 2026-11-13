package findings

import (
	"slices"
	"strings"
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
		{"no version: the fix of every line named by its start, newest first (the highest where a line has two); the 5.x lines that end at an affected version are counted, not given a fix", dev(fortiGate(vulns, "")), "CVE-2022-42475",
			&FixedIn{Kind: "branches", NoFix: 4, Branches: []br{{"7.2", "7.2.3"}, {"7.0", "7.0.9"}, {"6.4", "6.4.11"}, {"6.2", "6.2.12"}, {"6.0", "6.0.16"}}}},
		{"no version: the iOS lines, a range with only an end bound included", dev(iPhone(vulns, "")), "CVE-2025-24200",
			&FixedIn{Kind: "branches", Branches: []br{{"17.0", "18.3.1"}, {"16.0", "16.7.11"}, {"", "15.8.4"}}}},
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
			got.More != c.want.More || got.NoFix != c.want.NoFix || got.Source != c.want.Source || !slices.Equal(got.Branches, c.want.Branches)) {
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

// Review of D-488: the fix must be outside every applicable range, whatever the order of NVD's rows.
func TestFixedIn_ReviewCases(t *testing.T) {
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
	dev := func(s ...Software) Asset { return Asset{ID: "a", Name: "dev", Software: s} }
	// H1: an iPadOS-only bound (17.7.6) is not a fix for an iPhone: the iPhone range runs to 18.x.
	for cve, want := range map[string]string{"CVE-2025-24085": "18.3", "CVE-2025-24201": "18.3.2", "CVE-2025-43300": "18.6.2"} {
		if f := FixedInFor(dev(iPhone(vulns, "17.5")), vuln(cve)); f == nil || f.Kind != "fixed" || f.Fixed != want {
			t.Errorf("iPhone 17.5 %s: %+v, want fixed %s", cve, f, want)
		}
	}
	if f := FixedInFor(dev(iPhone(vulns, "17.5")), vuln("CVE-2025-43200")); f == nil || f.Kind != "up_to" || f.Fixed != "18.3.1" {
		t.Errorf("a bound that another range still lists is not named as a fix: %+v", f)
	}
	// H1: 7.0.8 is inside [7.0.0, 7.0.9), so it is not the fix, in either row order.
	v := vuln("CVE-2022-42475")
	r := v
	r.Affected = slices.Clone(v.Affected)
	slices.Reverse(r.Affected)
	for _, x := range []Vuln{v, r} {
		if f := FixedInFor(dev(fortiGate(vulns, "7.0.5")), x); f == nil || f.Kind != "fixed" || f.Fixed != "7.0.9" {
			t.Errorf("FortiOS 7.0.5: %+v, want fixed 7.0.9", f)
		}
	}
	// M1: a version that is given but unreadable is not "no version yet".
	for _, ver := range []string{"v7.0.5,build0304 (GA)", "7.0.x"} {
		if f := FixedInFor(dev(fortiGate(vulns, ver)), v); f == nil || f.Kind != "branches" || f.Version != ver {
			t.Errorf("FortiOS %q: %+v, want branches carrying the unreadable version", ver, f)
		}
	}
	// M2: of two rows of one product the one with a readable version and an answer wins, in either order.
	blank := Software{ID: "s-a", Display: "FortiGate A", Vendor: "Fortinet", Product: "FortiOS", KevKeys: []string{"fortinet|fortios"}}
	for _, a := range []Asset{dev(blank, fortiGate(vulns, "7.2.1")), dev(fortiGate(vulns, "7.2.1"), blank)} {
		if f := FixedInFor(a, vuln("CVE-2024-21762")); f == nil || f.Kind != "fixed" || f.Fixed != "7.2.7" {
			t.Errorf("two rows: %+v, want fixed 7.2.7", f)
		}
	}
	// M3: a distribution's package is fixed by its security updates, never by an upstream number.
	for _, cve := range []string{"CVE-2026-123158", "CVE-2026-46300"} {
		a := Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}
		if f := FixedInFor(a, vuln(cve)); f == nil || f.Kind != "distro" || f.Fixed != "" || len(f.Branches) != 0 {
			t.Errorf("ubuntu %s: %+v, want kind distro with no number", cve, f)
		}
	}
	// M4: the range the evidence quotes and the fix come from the same range (iPad 17.7.2, CVE-2025-24200).
	a := dev(iPhone(vulns, "17.7.2"))
	res := MatchAsset(a, []Vuln{vuln("CVE-2025-24200")}, nil, t0)
	f := FixedInFor(a, vuln("CVE-2025-24200"))
	if len(res.New) != 1 || f == nil || f.Fixed != "18.3.1" || !strings.Contains(res.New[0].Evidence.Summary, "before 18.3.1") {
		t.Errorf("evidence %+v vs fix %+v", res.New, f)
	}
	// L1: a bound that does not parse (a bidi override after the number) is no fix, with or without a version.
	bad := Vuln{CVE: "CVE-2024-0001", Vendor: "Acme", Product: "Gate", Affected: []Affected{{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.0", EndExcl: "2.0.1\u202e"}}}}
	sw := Software{ID: "s", Display: "Acme", Vendor: "Acme", Product: "Gate", Version: "1.5", KevKeys: []string{"acme|gate"}}
	if f := FixedInFor(dev(sw), bad); f != nil {
		t.Errorf("unreadable bound with a version: %+v", f)
	}
	sw.Version = ""
	if f := FixedInFor(dev(sw), bad); f != nil {
		t.Errorf("unreadable bound without a version: %+v", f)
	}
}

func TestFixedIn_BranchesAreShort(t *testing.T) {
	var aff []Affected
	for _, e := range []string{"1.1.1", "2.2.2", "3.3.3", "4.4.4", "5.5.5", "6.6.6", "7.7.7"} {
		aff = append(aff, Affected{CPE: "cpe:2.3:a:acme:gate:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: e[:1] + ".0.0", EndExcl: e}})
	}
	sw := Software{ID: "s", Display: "Acme", Vendor: "Acme", Product: "Gate", KevKeys: []string{"acme|gate"}}
	f := FixedInFor(Asset{ID: "a", Name: "dev", Software: []Software{sw}}, Vuln{CVE: "CVE-2024-0001", Vendor: "Acme", Product: "Gate", Affected: aff})
	if f == nil || len(f.Branches) != 5 || f.More != 2 || f.Branches[0].Fixed != "7.7.7" || f.Branches[0].Branch != "7.0" {
		t.Errorf("got %+v", f)
	}
}
