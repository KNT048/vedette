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
			&FixedIn{Kind: "branches", Branches: []br{{"17.x", "18.3.1"}, {"16.x", "16.7.11"}, {"", "15.8.4"}}}},
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
	// M3 (round 2): inventory does not say where a row came from, so a plain version on a distribution keeps the
	// upstream number and carries the distribution for the page's condition; only a distribution-marked version is
	// told to take the distribution's security updates, with no number.
	conf := Software{ID: "s-c", Display: "Confluence", Vendor: "Atlassian", Product: "Confluence", Version: "8.2.0", KevKeys: []string{"atlassian|confluence"}}
	cv := Vuln{CVE: "CVE-2024-0002", Vendor: "Atlassian", Product: "Confluence", Affected: []Affected{{CPE: "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "8.0.0", EndExcl: "8.3.3"}}}}
	if f := FixedInFor(Asset{ID: "a", Name: "wiki", OS: "Ubuntu 22.04.4 LTS", Software: []Software{conf}}, cv); f == nil || f.Kind != "fixed" || f.Fixed != "8.3.3" || f.Distro != "Ubuntu" {
		t.Errorf("Confluence on Ubuntu: %+v, want fixed 8.3.3 with distro Ubuntu", f)
	}
	if f := FixedInFor(Asset{ID: "a", Name: "wiki", Software: []Software{conf}}, cv); f == nil || f.Kind != "fixed" || f.Distro != "" {
		t.Errorf("Confluence with no known distribution: %+v", f)
	}
	jenkins := Software{ID: "s-j", Display: "Jenkins", Vendor: "Jenkins", Product: "Jenkins", Version: "2.426.1", KevKeys: []string{"jenkins|jenkins"}}
	jv := Vuln{CVE: "CVE-2024-0003", Vendor: "Jenkins", Product: "Jenkins", Affected: []Affected{{CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "2.0", EndExcl: "2.442"}}}}
	if f := FixedInFor(Asset{ID: "a", Name: "ci", OS: "Ubuntu 22.04.4 LTS", Software: []Software{jenkins}}, jv); f == nil || f.Kind != "fixed" || f.Fixed != "2.442" {
		t.Errorf("Jenkins from the vendor repo: %+v, want fixed 2.442", f)
	}
	for _, ver := range []string{"2.426.1-1ubuntu2", "2.426.1-1+deb12u2", "2.426.1-3.el9"} {
		jenkins.Version = ver
		if f := FixedInFor(Asset{ID: "a", Name: "ci", OS: "Ubuntu 22.04.4 LTS", Software: []Software{jenkins}}, jv); f == nil || f.Kind != "distro" || f.Fixed != "2.442" || f.Distro != "Ubuntu" {
			t.Errorf("version %q: %+v, want kind distro with the upstream 2.442 as reference", ver, f)
		}
	}
	jenkins.Version = "2.426.1"
	// Ubuntu kernel and OpenSSH rows from the agent carry upstream numbers: the number plus the condition.
	ub := Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}
	if f := FixedInFor(ub, vuln("CVE-2026-46300")); f == nil || f.Kind != "fixed" || f.Fixed != "7.0.10" || f.Distro != "Ubuntu" {
		t.Errorf("ubuntu kernel: %+v, want fixed 7.0.10 with distro Ubuntu", f)
	}
	// OpenSSH: the same entry also lists 10.6p1 as affected, so 10.6 is not clean ground to name: nothing is said.
	if f := FixedInFor(ub, vuln("CVE-2026-123158")); f != nil {
		t.Errorf("ubuntu OpenSSH: %+v, want nil", f)
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

// D-556: ranges from the vendor's CVE.org record, written by feeds under CISA's own vendor and product, decide by
// version like NVD's, and every sentence names their source.
func TestCVEOrgRangesNameTheirSource(t *testing.T) {
	v := Vuln{CVE: "CVE-2024-3400", Vendor: "Palo Alto Networks", Product: "PAN-OS", RangesFrom: RangesCVEOrg, Affected: []Affected{
		{CPE: "cpe:2.3:*:paloaltonetworks:panos:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.2.0", EndExcl: "10.2.9-h1"}},
		{CPE: "cpe:2.3:*:paloaltonetworks:panos:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.1.0", EndExcl: "11.1.2-h3"}}}}
	fw := func(ver string) Asset {
		return Asset{ID: "a", Name: "fw", Software: []Software{{ID: "s", Display: "PAN-OS", Vendor: "Palo Alto Networks", Product: "PAN-OS", Version: ver,
			KevKeys: []string{KevKey("Palo Alto Networks", "PAN-OS")}}}}
	}
	res := MatchAsset(fw("10.2.5"), []Vuln{v}, nil, t0)
	if len(res.New) != 1 || res.New[0].Basis != BasisVersion {
		t.Fatalf("10.2.5: %+v", res)
	}
	if f := FixedInFor(fw("10.2.5"), v); f == nil || f.Fixed != "10.2.9-h1" || f.Source != FixedInSourceCVEOrg {
		t.Fatalf("fixed in: %+v", f)
	}
	res = MatchAsset(fw("10.1.9"), []Vuln{v}, map[string]bool{"CVE-2024-3400": true}, t0)
	if len(res.NotAffected) != 1 || !strings.Contains(res.NotAffected[0].Evidence.Summary, "outside every version range the vendor's CVE.org record lists") {
		t.Fatalf("10.1.9: %+v", res)
	}
}

// D-488 follow-up (inventory INV-28 (3)): an agent row read from the package database is told to take the distribution's
// security updates, with the upstream release only as a reference; a row a person typed keeps the upstream number, and a
// row whose origin is not known (stored before inventory kept the flag, or no source) keeps the conditional wording.
func TestFixedIn_PackagedAgentRow(t *testing.T) {
	ssl := Software{ID: "s-o", Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL", Version: "3.0.2", KevKeys: []string{"openssl|openssl"}}
	v := Vuln{CVE: "CVE-2024-0004", Vendor: "OpenSSL", Product: "OpenSSL", Affected: []Affected{{CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "3.0.0", EndExcl: "3.0.7"}}}}
	on := func(osName string, s Software) *FixedIn {
		return FixedInFor(Asset{ID: "a", Name: "web", OS: osName, Software: []Software{s}}, v)
	}
	pkg := ssl
	pkg.Source, pkg.Packaged = "agent", true
	if f := on("Ubuntu 22.04.4 LTS", pkg); f == nil || f.Kind != "distro" || f.Fixed != "3.0.7" || f.Distro != "Ubuntu" || f.Version != "3.0.2" {
		t.Errorf("packaged agent row on Ubuntu: %+v, want distro Ubuntu with upstream 3.0.7", f)
	}
	if f := on("Rocky Linux 9.4", pkg); f == nil || f.Kind != "distro" || f.Fixed != "3.0.7" || f.Distro != "" {
		t.Errorf("packaged agent row on a distribution Vedette does not name: %+v, want distro with no name", f)
	}
	if g := FixedInForAll(Asset{ID: "a", Name: "web", OS: "Ubuntu 22.04.4 LTS", Software: []Software{pkg}}, []Vuln{v})[v.CVE]; g == nil || g.Kind != "distro" {
		t.Errorf("weekly report group of a packaged row: %+v, want distro", g)
	}
	manual := ssl
	manual.Source = "manual"
	unknown := ssl // no source: a caller that does not know it
	old := ssl     // an agent row stored before inventory kept the flag
	old.Source = "agent"
	notAgent := ssl // the flag means nothing outside an agent row
	notAgent.Source, notAgent.Packaged = "scan", true
	for name, s := range map[string]Software{"manual": manual, "unknown source": unknown, "agent row before the flag": old, "scan": notAgent} {
		if f := on("Ubuntu 22.04.4 LTS", s); f == nil || f.Kind != "fixed" || f.Fixed != "3.0.7" || f.Distro != "Ubuntu" {
			t.Errorf("%s on Ubuntu: %+v, want fixed 3.0.7 with the Ubuntu condition", name, f)
		}
	}
	if f := on("", manual); f == nil || f.Kind != "fixed" || f.Distro != "" {
		t.Errorf("manual row with no OS: %+v, want fixed with no condition", f)
	}
}
