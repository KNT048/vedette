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
			g := FixedInForAll(a, vulns)
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

func TestReleaseLine(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"8.9p1": "8.9p1", "7.4.1": "7.4", "16.0.4266.1001": "16.0", "7": "7"} {
		if got := releaseLine(in); got != want {
			t.Errorf("releaseLine(%q) = %q, want %q", in, got, want)
		}
	}
}
