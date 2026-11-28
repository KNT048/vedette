package findings

import (
	"slices"
	"testing"
)

// One software line can hold several installations (a distribution's package beside a third-party build of another release, an older
// second install). Each is decided on its own evidence: the distribution's word on its package, a range that holds or clears a version,
// or the vendor's statement decides only the installation it is about. An installation with no evidence of its own keeps the line
// undecided and asked about; it is never closed by a sibling's evidence. Affected evidence about one installation still opens the line.
// Two readings of one installation (the same upstream version, the same source package or none) share their evidence. The products and
// packages are made up.
func TestInstallations_EachDecidedOnItsOwnEvidence(t *testing.T) {
	t.Parallel()
	const gw = "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
	ranges := []Affected{{CPE: gw, Range: VersionRange{StartIncl: "3.2.0", EndExcl: "3.2.12"}}, {CPE: gw, Range: VersionRange{StartIncl: "3.3.0", EndExcl: "3.3.3"}}}
	distroPkg := func(upstream, full string) Software { // the distribution's own build
		return Software{ID: "s-gw", Display: "Example Gateway", Vendor: "Example", Product: "Gateway", Version: upstream, KevKeys: []string{"example|gateway"},
			Source: "agent", Packaged: true, PkgVersion: full, PkgSource: "example-gateway"}
	}
	upstream := func(ver string) Software { // a build installed outside the package manager, as the agent reads it
		return Software{ID: "s-gw", Display: "Example Gateway", Vendor: "Example", Product: "Gateway", Version: ver, KevKeys: []string{"example|gateway"}, Source: "agent"}
	}
	extras := func(upstream, full string) Software { // another package of the same upload
		s := distroPkg(upstream, full)
		s.PkgSource = "example-gateway-extras"
		return s
	}
	trainOnly := func(ver string, packaged bool) Software { // a reading that names only the release train (a package that pulls in the real one)
		s := upstream(ver)
		s.Packaged = packaged
		if !packaged {
			s.Source = "nmap"
		}
		return s
	}
	notAffected := []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "example-gateway", Status: "not_affected"}}
	const (
		closed    = "closed"
		undecided = "undecided"
		affected  = "affected"
	)
	for _, tc := range []struct {
		name     string
		readings []Software
		distro   []DistroFix
		vendor   bool // the product's own CNA states every unlisted version unaffected
		want     string
	}{
		{"the distribution's word on its package, a build of another release beside it", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), upstream("3.0.5")}, notAffected, false, undecided},
		{"the same, the third-party build read first", []Software{upstream("3.0.5"), distroPkg("2.8.5", "2.8.5-1ubuntu3")}, notAffected, false, undecided},
		{"a range clears one installation, another is on a line the record does not list", []Software{upstream("3.2.15"), upstream("3.0.5")}, nil, false, undecided},
		{"each installation cleared by evidence of its own", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), upstream("3.2.15")}, notAffected, false, closed},
		{"two readings of one installation share the distribution's word", []Software{distroPkg("3.0.5", "3.0.5-1ubuntu1"), upstream("3.0.5")}, notAffected, false, closed},
		{"two packages one upload of the release builds share the distribution's word", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), extras("2.8.5", "2.8.5-1ubuntu3")}, notAffected, false, closed},
		{"a package naming only the release train beside the package that installs it", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), trainOnly("2.8+12ubuntu1", true)}, notAffected, false, closed},
		{"the same, the train-only package read first", []Software{trainOnly("2.8+12ubuntu1", true), distroPkg("2.8.5", "2.8.5-1ubuntu3")}, notAffected, false, closed},
		{"a less precise reading outside the package database", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), trainOnly("2.8", false)}, notAffected, false, undecided},
		{"a train-only package of another train", []Software{distroPkg("2.8.5", "2.8.5-1ubuntu3"), trainOnly("2.9+12ubuntu1", true)}, notAffected, false, undecided},
		{"affected evidence about one installation opens the line", []Software{upstream("3.2.15"), upstream("3.2.5")}, nil, false, affected},
		{"affected beside an undecided installation still opens", []Software{upstream("3.0.5"), upstream("3.2.5")}, nil, false, affected},
		{"the vendor's statement covers every installation of its product", []Software{upstream("3.2.15"), upstream("3.0.5")}, nil, true, closed},
	} {
		v := uncVuln("CVE-2026-92001", "Example", "Gateway", uncNew, ranges...)
		v.Distro, v.DistroOn = tc.distro, map[string]bool{"ubuntu": true}
		if tc.vendor {
			v.UnlistedUnaffected = []string{"cpe:2.3:*:example:gateway:*:*:*:*:*:*:*:*"}
		}
		a := Asset{ID: "srv", Name: "srv-01", OS: "Ubuntu 24.04.1 LTS", Software: tc.readings}
		res := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, uncNow)
		got := ""
		switch {
		case len(res.Existing)+len(res.New) == 1:
			got = affected
		case len(res.NotAffected) == 1 && len(res.Unchecked) == 0:
			got = closed
		case len(res.NotAffected) == 0 && slices.ContainsFunc(res.Unchecked, func(u Unchecked) bool { return u.CVE == v.CVE && u.SoftwareID == "s-gw" }):
			got = undecided
		}
		if got != tc.want {
			t.Errorf("%s: %q, want %q (not affected %d, findings %d, unchecked %+v)", tc.name, got, tc.want, len(res.NotAffected), len(res.Existing)+len(res.New), res.Unchecked)
		}
	}
}
