package findings

import "testing"

// The release named for a device is outside the affected range of EVERY vulnerability of the product, not just the highest of the
// ones that each name a fix (D-490 review H1: 26.3 fixes one iOS CVE and is inside the range of another).
func TestFixedInForAllNamesAReleaseNoVulnerabilityStillAffects(t *testing.T) {
	vulns := goldenVulns(t)
	type mk func([]Vuln, string) Software
	sets := map[string]struct {
		f    mk
		vers []string
	}{
		"FortiOS":   {fortiGate, []string{"6.0.4", "6.4.5", "7.0.6", "7.2.0", "7.2.5", "7.4.0", "7.4.2"}},
		"iOS":       {iPhone, []string{"15.7", "16.0", "16.7.2", "17.0", "17.2", "18.0", "18.2"}},
		"NetScaler": {netScaler, []string{"12.1.55", "13.0.80", "13.1.30", "14.1.4"}},
		"Office":    {office, []string{"16.0.4266.1001", "16.0.5000.1000"}},
	}
	named := 0
	for name, s := range sets {
		for _, ver := range s.vers {
			a := Asset{ID: "a", Name: "dev", Software: []Software{s.f(vulns, ver)}}
			var g *GroupFix
			for _, x := range FixedInForAll(a, vulns) {
				g = x // one group: every CVE of the software row shares it
			}
			if g == nil || g.Kind != "fixed" {
				continue
			}
			named++
			if len(g.Closed) == 0 {
				t.Errorf("%s %s: names %s and closes nothing", name, ver, g.Fixed)
			}
			b := Asset{ID: "a", Name: "dev", Software: []Software{s.f(vulns, g.Fixed)}}
			for _, v := range vulns {
				if f := FixedInFor(b, v); f != nil && (f.Kind == "fixed" || f.Kind == "up_to") {
					t.Errorf("%s %s: group fix %s is still affected by %s", name, ver, g.Fixed, v.CVE)
				}
			}
		}
	}
	if named == 0 {
		t.Fatal("the golden feed gave no group fix at all")
	}
}

// One software row is one group, whatever CISA calls the products of its CVEs, and the release is not limited to the ranges the device
// is inside (review round 2): every CVE of the phone gets the same release and nothing of the phone's feed is still affected by it.
func TestFixedInForAllIsOneGroupPerSoftwareAndLooksAboveEveryRange(t *testing.T) {
	vulns := goldenVulns(t)
	for _, c := range []struct {
		name string
		f    func([]Vuln, string) Software
		ver  string
	}{{"iOS", iPhone, "18.2"}, {"FortiOS", fortiGate, "7.2.5"}, {"FortiOS", fortiGate, "7.0.6"}} {
		a := Asset{ID: "a", Name: "dev", Software: []Software{c.f(vulns, c.ver)}}
		m := FixedInForAll(a, vulns)
		if len(m) < 3 {
			t.Fatalf("%s %s: %d CVEs in the group", c.name, c.ver, len(m))
		}
		var g *GroupFix
		for cve, x := range m {
			if g != nil && x != g {
				t.Fatalf("%s %s: %s is in another group", c.name, c.ver, cve)
			}
			g = x
		}
		if g.Kind != "fixed" {
			t.Errorf("%s %s: kind %s, want a release that clears all %d", c.name, c.ver, g.Kind, len(m))
			continue
		}
		b := Asset{ID: "a", Name: "dev", Software: []Software{c.f(vulns, g.Fixed)}}
		for _, v := range vulns {
			if f := FixedInFor(b, v); f != nil && (f.Kind == "fixed" || f.Kind == "up_to") {
				t.Errorf("%s %s: %s is still affected by %s", c.name, c.ver, g.Fixed, v.CVE)
			}
		}
		t.Logf("%s %s -> %s, closes %d", c.name, c.ver, g.Fixed, len(g.Closed))
	}
}
