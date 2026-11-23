package versionscheme

import (
	"testing"
)

// An ESXi release as a host, a scan or a person writes it is stated as the host states it to the matcher: "<line>.<update>" with the
// build in the name. A text that does not say the release (a line alone, a build of another update) is kept as given.
func TestESXi_Stated(t *testing.T) {
	t.Parallel()
	s, _ := Lookup("vmware-esxi")
	u3 := "VMware ESXi 8.0 Update 3 (build 24022510)"
	for _, c := range []struct{ version, display, wantVersion, wantDisplay string }{
		{"8.0.3 build 24022510", "VMware ESXi", "8.0.3", u3}, // what "vmware -v" prints, typed by a person
		{"8.0.3 build-24022510", "VMware ESXi", "8.0.3", u3}, // with its hyphen
		{"8.0.3-24022510", "", "8.0.3", u3},                  // version-build
		{"8.0 U3", "VMware ESXi", "8.0.3", u3},               // the release named as VMware names it: Update 3 is build 24022510
		{"8.0 Update 3 (build 24022510)", "", "8.0.3", u3},   // the banner's words
		{"8.0", u3, "8.0.3", u3},                             // a scan's version with the banner's build
		{"8.0 U3", u3, "8.0.3", u3},                          // a correction on the scanned host
		{"8.0.3", "VMware ESXi 8.0 Update 3e (build 24674464)", "8.0.3", "VMware ESXi 8.0 Update 3e (build 24674464)"}, // the device's build is more precise
		{"8.0 U3e", "VMware ESXi", "8.0.3", "VMware ESXi 8.0 Update 3e (build 24674464)"},
		{"8.0U3e", "", "8.0.3", "VMware ESXi 8.0 Update 3e (build 24674464)"},
		{"8.0b", "", "8.0.0", "VMware ESXi 8.0b (build 21203435)"},
		{"7.0 U3s", "", "7.0.3", "VMware ESXi 7.0 Update 3s (build 24585291)"},
		{"8.0.3 build 99999999", "", "8.0.3", "VMware ESXi 8.0 Update 3 (build 99999999)"}, // a build newer than the table: placed by its version
	} {
		v, d, ok := s.Stated(c.version, c.display)
		if !ok || v != c.wantVersion || d != c.wantDisplay {
			t.Errorf("Stated(%q, %q) = %q %q %v, want %q %q", c.version, c.display, v, d, ok, c.wantVersion, c.wantDisplay)
		}
		if in, ok := s.Installed(v, esxiNamedBuild.FindStringSubmatch(d)[1]); !ok || in.LineStart {
			t.Errorf("Stated(%q) = %q %q: the scheme does not place it", c.version, v, d)
		}
	}
	for _, c := range [][2]string{
		{"8.0", "VMware ESXi"},               // a line alone says no release
		{"8.0.2 build 24022510", ""},         // the build is Update 3's
		{"8.0 U3z", ""},                      // a release the table does not list, without its build
		{"8.0.2 U3", ""},                     // two updates
		{"latest", ""},                       // no release at all
		{"9.0.1.0 build 24957456", "VMware"}, // 9.x states its own version: kept as given
	} {
		if v, d, ok := s.Stated(c[0], c[1]); ok {
			t.Errorf("Stated(%q, %q) = %q %q, want it kept as given", c[0], c[1], v, d)
		}
	}
}

// DSM: a release is compared only inside its line, by build and update; NVD's bounds read the same way as Synology's.
func TestDSM(t *testing.T) {
	t.Parallel()
	s, ok := Lookup("synology-dsm")
	if !ok || !s.NVDNotation {
		t.Fatal("no synology-dsm scheme that reads NVD's rows")
	}
	// CVE-2024-10441 as NVD states it
	sp := spans(t, s, [3]string{"7.2", "7.2-64570-4", ""}, [3]string{"7.2.1-69057", "7.2.1-69057-6", ""}, [3]string{"7.2.2", "7.2.2-72806-1", ""})
	runJudge(t, s, sp, []judgeCase{
		{"7.2.1 update 5", "7.2.1-69057-5", "", Affected, "7.2.1-69057 Update 6", "inside its line, before the fixed update"},
		{"7.2.1 update 5 as DSM says it", "7.2.1-69057 Update 5", "", Affected, "7.2.1-69057 Update 6", "DSM's own words"},
		{"7.2.1 update 6", "7.2.1-69057-6", "", NotAffected, "", "the fixed update"},
		{"7.2 update 3", "7.2-64570-3", "", Affected, "7.2-64570 Update 4", "the 7.2 line has its own fix"},
		{"7.2 update 4", "7.2-64570-4", "", NotAffected, "", "fixed in its line, whatever 7.2.1 says"},
		{"7.2.2 base", "7.2.2-72806", "", Affected, "7.2.2-72806 Update 1", "the line's first release"},
		{"7.1.1", "7.1.1-42962-8", "", NotAffected, "", "a line before every range's start"},
		{"a line alone", "7.2.1", "", NotComparable, "", "says no release"},
	})
	for _, c := range [][2]string{{"7.2.1-69057 Update 5", "7.2.1-69057-5"}, {"DSM 7.2.2-72806 Update 3", "7.2.2-72806-3"}, {"7.2.1-69057", "7.2.1-69057"}, {"7.2.1-69057-5", "7.2.1-69057-5"}} {
		if v, d, ok := s.Stated(c[0], "Synology DiskStation Manager (DSM)"); !ok || v != c[1] || d != "" {
			t.Errorf("Stated(%q) = %q %q %v, want %q", c[0], v, d, ok, c[1])
		}
	}
	if _, _, ok := s.Stated("7.2", ""); ok {
		t.Error("a line alone is kept as given")
	}
}
