package findings

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// A vendor's own list of exact releases closes a later release of a line only in the list's own numbering and only for the vendor's
// own build: a release on another build branch of the same first two numbers ("10.0.19045.10" beside "10.0.17763.100"), a release
// written with more numbers than the listed one ("4.2.9.1" beside "4.2.9"), or a distribution's package of the product (whose
// version is not the upstream release the list speaks of) is never closed by the per-line reading, on the exploited list's path or on
// NVD's. Synthetic product (Examplecorp Gizmo).
func TestMatch_ExactListClosesOnlyTheListsOwnLineAndBuild(t *testing.T) {
	t.Parallel()
	rows := func(vs ...string) []Affected {
		var out []Affected
		for _, v := range vs {
			out = append(out, Affected{CPE: "cpe:2.3:a:examplecorp:gizmo:" + v + ":*:*:*:*:*:*:*", VendorCNA: true})
		}
		return out
	}
	sys := func(aff []Affected, systems ...string) []Affected { // the row's target_sw
		for i, sw := range systems {
			aff[i].CPE = strings.Replace(aff[i].CPE, ":*:*:*:*:*:*:*", ":*:*:*:*:"+sw+":*:*", 1)
		}
		return aff
	}
	for _, tc := range []struct {
		name, ver, pkg, os string
		aff                []Affected
		closes             bool
		newer              bool // a closure by the newer-line reading: never for an exploited CVE
	}{
		{"a later release of the listed build branch", "10.0.17763.120", "", "", rows("10.0.17763.100"), true, false},
		{"another build branch with the same first two numbers", "10.0.19045.10", "", "", rows("10.0.17763.100"), false, false},
		{"past the newest listed release of its branch", "10.0.19045.50", "", "", rows("10.0.17763.100", "10.0.19045.40"), true, false},
		{"a newer branch than the newest listed one", "10.0.22621.10", "", "", rows("10.0.17763.100", "10.0.19045.40"), false, false},
		{"more numbers than the listed release", "4.2.9.1", "", "", rows("4.2.9"), false, false},
		{"the upstream release, past the last affected one", "4.2.12", "", "", rows("4.2.9"), true, false},
		{"a distribution's package, past the last affected release", "4.2.12", "4.2.12-1ubuntu1", "Ubuntu 24.04", rows("4.2.9"), false, false},
		{"a distribution's package, on a line newer than every listed one", "6.0.1", "6.0.1-1ubuntu1", "Ubuntu 24.04", rows("4.2.9", "5.1.3"), false, false},
		{"rows on another system name older lines only", "6.0.1", "", "Microsoft Windows 11 Pro", sys(rows("4.2.9", "5.1.3", "5.1.5"), "windows", "windows", "linux"), true, true},
		{"a row on another system names the installation's line", "6.0.1", "", "Microsoft Windows 11 Pro", sys(rows("4.2.9", "5.1.3", "6.0.4"), "windows", "windows", "linux"), false, false},
		{"a row on another system names a newer line", "6.0.1", "", "Microsoft Windows 11 Pro", sys(rows("4.2.9", "5.1.3", "7.0.2"), "windows", "windows", "linux"), false, false},
	} {
		for _, exploited := range []bool{false, true} {
			s := Software{ID: "w", Display: "Gizmo " + tc.ver, Vendor: "Examplecorp", Product: "Gizmo", Version: tc.ver, Source: "agent"}
			if tc.pkg != "" {
				s.Packaged, s.PkgVersion, s.PkgSource = true, tc.pkg, "gizmo"
			}
			v := Vuln{CVE: "CVE-2099-0310", NVDAnswered: true, Affected: tc.aff, DateAdded: uncNew, Published: uncNew}
			if exploited {
				v.Vendor, v.Product = "Examplecorp", "Gizmo"
				s.KevKeys = []string{productid.NormKey("Examplecorp", "Gizmo")}
			}
			a := Asset{ID: "pc", Name: "pc.example.com", OS: tc.os, AgentOS: tc.os, Software: []Software{s}}
			_, out := matchOne(a, s, swInfoOn(s, a), v, exploited, keyIDs(v), true, uncNow)
			if want := tc.closes && (!exploited || !tc.newer); (out == outNotAffected) != want {
				t.Errorf("%s (%s, exploited %v): outcome %v, closes want %v", tc.name, tc.ver, exploited, out, want)
			}
		}
	}
}

// NVD lists a vendor's build that carries the fix as affected (Edge 117.0.2045.47 for CVE-2023-5217): read per line, that only ever
// keeps the listed build and the builds below it open; only a later build of its line closes, and only on the vendor's own list.
func TestMatch_ExactListAFixBuildListedAsAffectedErrsTowardAffected(t *testing.T) {
	t.Parallel()
	list := func(own bool) []Affected {
		return []Affected{{CPE: "cpe:2.3:a:microsoft:edge:116.0.1938.98:*:*:*:*:*:*:*", VendorCNA: own}, {CPE: "cpe:2.3:a:microsoft:edge:117.0.2045.47:*:*:*:*:*:*:*", VendorCNA: own}}
	}
	for _, tc := range []struct {
		ver    string
		own    bool
		closes bool
	}{
		{"117.0.2045.47", true, false}, {"117.0.2045.40", true, false}, {"117.0.2045.55", true, true},
		{"117.0.2045.55", false, false}, {"117.0.2045.47", false, false}, {"116.0.1938.81", true, false},
	} {
		for _, exploited := range []bool{false, true} {
			s := edgeRow(tc.ver)
			v := Vuln{CVE: "CVE-2099-0311", NVDAnswered: true, Affected: list(tc.own), DateAdded: uncNew, Published: uncNew}
			if exploited {
				v.Vendor, v.Product = "Microsoft", "Edge"
			}
			a := Asset{ID: "pc", Name: "pc.example.com", OS: "Microsoft Windows 11 Pro", Software: []Software{s}}
			_, out := matchOne(a, s, swInfoOn(s, a), v, exploited, keyIDs(v), true, uncNow)
			if (out == outNotAffected) != tc.closes {
				t.Errorf("Edge %s (vendor's list %v, exploited %v): outcome %v, closes want %v", tc.ver, tc.own, exploited, out, tc.closes)
			}
		}
	}
}
