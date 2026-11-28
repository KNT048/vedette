package findings

import (
	"strings"
	"testing"
	"time"
)

// The build class of a dpkg version, read only from the Debian version conventions: the distribution's own revision grammar, a
// revision that carries the distribution's packaging mark outside that grammar (unknown builder), or a version with none of the
// distribution's marks at all (an upstream release in its own numbering: another builder, or a native package).
func TestDebBuildOf(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		distro, pkg, v string
		want           debBuild
	}{
		// the distribution's own revision grammar
		{"ubuntu", "exampled", "1.24.0-2ubuntu7.21", buildOwn},
		{"ubuntu", "exampled", "2.2.1-0ubuntu1~24.04.4", buildOwn},
		{"ubuntu", "exampled", "10.1.16-1", buildOwn}, // taken from Debian unchanged
		{"ubuntu", "exampled", "3.1-2build1", buildOwn},
		{"ubuntu", "exampled", "1:8.2p1-4ubuntu0.13+esm3", buildOwn},
		{"ubuntu", "exampled", "1.9.15p5-3ubuntu5.24.04.1", buildOwn},
		{"ubuntu", "linux", "7.0.0-44.44", buildOwn},
		{"debian", "exampled", "1.26.3-3+deb13u11", buildOwn},
		{"debian", "exampled", "10.1.60-1~deb13u1", buildOwn},
		{"debian", "exampled", "1.7.24~ds1-6+b4", buildOwn},
		{"debian", "exampled", "1.7.28-1", buildOwn}, // a plain revision is Debian's own form
		// the distribution's mark outside its grammar: the builder is unknown
		{"ubuntu", "exampled", "8.4.6-1ubuntu24.04", buildMarked}, // a release number where Ubuntu counts uploads
		{"ubuntu", "exampled", "8.4.6-1ubuntu24.04.1", buildMarked},
		{"ubuntu", "exampled", "3.2.5+dfsg-3~ubuntu24.04.3", buildMarked},
		{"ubuntu", "exampled", "17.0.21.1+2-1~24.04.1", buildMarked},
		{"ubuntu", "exampled", "1.1.39-0exp1ubuntu0.24.04.3", buildMarked},
		{"ubuntu", "exampled", "2.8.4ubuntu0.1", buildMarked}, // native with Ubuntu's mark
		{"debian", "exampled", "20250419+deb13u1", buildMarked},
		{"debian", "exampled", "2.4.63-1~bpo12+1", buildMarked},
		// none of the distribution's marks: the version is an upstream release
		{"ubuntu", "exampled", "1.28.0-1~noble", buildUpstream},
		{"ubuntu", "exampled", "5:28.5.1-1~ubuntu.24.04~noble", buildUpstream},
		{"ubuntu", "exampled", "17.6-1.pgdg24.04+1", buildUpstream},
		{"ubuntu", "exampled", "22.20.0-1nodesource1", buildUpstream},
		{"ubuntu", "exampled", "8.3.27-1+ubuntu24.04.1+deb.sury.org+1", buildUpstream},
		{"ubuntu", "exampled", "18.5.1-ce.0", buildUpstream},
		{"ubuntu", "exampled", "1:7.0.19-1+ubuntu24.04", buildUpstream},
		{"ubuntu", "exampled", "6:8.2.2-1rl1~noble1", buildUpstream},
		{"ubuntu", "exampled", "3.2.7-1ppa1~noble", buildUpstream},
		{"ubuntu", "exampled", "12.2.1", buildUpstream},            // native, no mark
		{"ubuntu", "exampled", "1.26.3-3+deb13u11", buildUpstream}, // Debian's build installed on Ubuntu
		{"debian", "exampled", "1.28.0-1~trixie", buildUpstream},
		{"debian", "exampled", "8.4.6-1debian13", buildUpstream},
		{"debian", "exampled", "2.4.58-1ubuntu8.8", buildUpstream}, // Ubuntu's build installed on Debian
		{"debian", "exampled", "9.1.5", buildUpstream},
		// not a Debian version: nothing is known
		{"ubuntu", "exampled", "", buildUnknown},
		{"debian", "exampled", "not a version", buildUnknown},
	} {
		if got := debBuildOf(c.distro, c.pkg, c.v); got != c.want {
			t.Errorf("debBuildOf(%s, %s) = %v, want %v", c.distro, c.v, got, c.want)
		}
	}
}

// A dpkg package whose version carries none of the distribution's marks is an upstream product: NVD's (or the CNA's) ranges judge
// it both ways, on an exploited CVE and on any other, and the distribution's fix for its own build of the same source never decides
// it. The distribution's own build keeps the distribution's word; a build with the distribution's mark outside its grammar is never
// closed by the distribution's word and stays undecided with a named cause.
func TestMatchAsset_UpstreamBuildIsJudgedAsTheUpstreamProduct(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	const cpe = "cpe:2.3:a:example:example_server:*:*:*:*:*:*:*:*"
	pkg := func(version, full string) Software {
		return Software{ID: "s-ex", Display: "Example Server", Vendor: "Example", Product: "Example Server", Version: version,
			Source: "agent", Packaged: true, PkgVersion: full, PkgSource: "exampled"}
	}
	// NVD: every release from 1.9.5 before 1.29.1. Ubuntu 24.04 fixed its own 1.24.0 build; Debian 13 its 1.26.3 build.
	vuln := func(cve string, listed bool) Vuln {
		v := Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD,
			Affected: []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "1.9.5", EndExcl: "1.29.1"}}},
			Distro: []DistroFix{
				{Distro: "ubuntu", Release: "24.04", Package: "exampled", Status: "fixed", Fixed: "1.24.0-2ubuntu7.20"},
				{Distro: "ubuntu", Release: "26.04", Package: "exampled", Status: "not_affected"},
				{Distro: "debian", Release: "13", Package: "exampled", Status: "fixed", Fixed: "1.26.3-3+deb13u11"},
			},
			DistroOn: map[string]bool{"ubuntu": true, "debian": true}}
		if listed {
			v.Vendor, v.Product = "Example", "Example Server"
		}
		return v
	}
	on := func(osName string, s Software, v Vuln) MatchResult {
		return MatchAsset(Asset{ID: "a", Name: "web-01", OS: osName, Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: true}, now)
	}
	const noble, resolute, trixie = "Ubuntu 24.04.3 LTS", "Ubuntu 26.04.1 LTS", "Debian GNU/Linux 13 (trixie)"
	for _, listed := range []bool{false, true} {
		v := vuln("CVE-2026-71001", listed)
		// a vendor build above the upstream fix: NVD proves it not affected, never the distribution's fix of its own build
		r := on(noble, pkg("1.29.2", "1.29.2-1~noble"), v)
		if len(r.New)+len(r.Existing) != 0 || len(r.NotAffected) != 1 || strings.Contains(r.NotAffected[0].Evidence.Summary, "Ubuntu") {
			t.Errorf("listed %v: a vendor build above NVD's range: %+v", listed, r)
		}
		// a vendor build inside the upstream range that compares higher than the distribution's fix: NVD's finding
		for _, c := range []struct{ os, ver, full string }{
			{noble, "1.28.0", "1.28.0-1~noble"},
			{noble, "1.28.0", "1.28.0-1+ubuntu24.04.1+vendor.example+1"},
			{noble, "1.28.0", "1.28.0"}, // native, no revision
			{resolute, "1.28.0", "1.28.0-1~resolute"},
			{trixie, "1.28.0", "1.28.0-1~trixie"},
		} {
			r := on(c.os, pkg(c.ver, c.full), v)
			if len(r.NotAffected) != 0 || len(r.New)+len(r.Existing) != 1 {
				t.Errorf("listed %v, %s on %s: closed or undecided, want NVD's finding: %+v", listed, c.full, c.os, r)
				continue
			}
			m := append(r.New, r.Existing...)[0]
			if strings.Contains(m.Evidence.Summary, "Ubuntu") || strings.Contains(m.Evidence.Summary, "Debian") {
				t.Errorf("listed %v, %s: the finding speaks of the distribution: %s", listed, c.full, m.Evidence.Summary)
			}
			if f := FixedInFor(Asset{ID: "a", Name: "web-01", OS: c.os, Software: []Software{pkg(c.ver, c.full)}}, v); f == nil || f.Kind == "distro" {
				t.Errorf("listed %v, %s: the fix is the distribution's: %+v", listed, c.full, f)
			}
		}
	}
	// the distribution's own build keeps the distribution's word, on a CVE on no exploited list too
	if r := on(noble, pkg("1.24.0", "1.24.0-2ubuntu7.21"), vuln("CVE-2026-71002", false)); len(r.NotAffected) != 1 ||
		!strings.Contains(r.NotAffected[0].Evidence.Summary, "Ubuntu 24.04 fixed CVE-2026-71002") {
		t.Errorf("Ubuntu's own build: %+v", r)
	}
	if r := on(trixie, pkg("1.26.3", "1.26.3-3+deb13u11"), vuln("CVE-2026-71003", false)); len(r.NotAffected) != 1 ||
		!strings.Contains(r.NotAffected[0].Evidence.Summary, "Debian 13 fixed CVE-2026-71003") {
		t.Errorf("Debian's own build: %+v", r)
	}
	// a release number where Ubuntu counts its uploads: the distribution's "not affected" never closes it
	if r := on(resolute, pkg("1.28.0", "1.28.0-1ubuntu26.04"), vuln("CVE-2026-71004", true)); len(r.NotAffected) != 0 {
		t.Errorf("a vendor's ubuntu26.04 revision was closed by Ubuntu's word: %+v", r)
	}
	// Ubuntu's mark outside its grammar: neither the distribution's fix nor NVD's range closes it
	if r := on(noble, pkg("1.29.2", "1.29.2-3~ubuntu24.04.3"), vuln("CVE-2026-71005", false)); len(r.NotAffected) != 0 {
		t.Errorf("a build of unknown origin was closed: %+v", r)
	}
}

// In the coverage an upstream build's pairs are decided by the upstream ranges, never left to a distribution cause; a build of
// unknown origin stays undecided with the distribution's named cause.
func TestCoverage_UpstreamBuildPairsAreDecidedByTheUpstreamRanges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := *e.clock
	const cpe = "cpe:2.3:a:example:example_server:*:*:*:*:*:*:*:*"
	pkg := func(id, version, full string) Software {
		return Software{ID: id, Display: "Example Server", Vendor: "Example", Product: "Example Server", Version: version, Source: "agent",
			Packaged: true, PkgVersion: full, PkgSource: "exampled"}
	}
	a := Asset{ID: "u-1", Name: "web-01", OS: "Ubuntu 24.04.3 LTS", Software: []Software{
		pkg("s-vendor", "1.29.2", "1.29.2-1~noble"),
		pkg("s-old", "1.28.0", "1.28.0"),
		pkg("s-marked", "1.29.2", "1.29.2-3~ubuntu24.04.3"),
	}}
	v := Vuln{CVE: "CVE-2026-71010", NVDAnswered: true, Origin: RangeNVD, Published: now.AddDate(0, -1, 0),
		Affected: []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "1.9.5", EndExcl: "1.29.1"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "exampled", Status: "fixed", Fixed: "1.24.0-2ubuntu7.20"}},
		DistroOn: map[string]bool{"ubuntu": true}}
	e.inv.assets = map[string]AssetView{a.ID: {ID: a.ID, Hostname: ptr(a.Name), IP: "192.0.2.10", Kind: "server", Approved: true}}
	e.inv.match = map[string]Asset{a.ID: a}
	e.feeds.vulns = []Vuln{v}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	rows, err := readDeviceRows(t.Context(), e.db.Reader(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	in, err := e.svc.causeInputsOf(t.Context(), rows.questions, cveSet(e.feeds.vulns))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := pairStates(newDevMatch(a, e.feeds.vulns, now), rows, in)
	for _, c := range []struct {
		sw, by, cause, detail string
		affected              bool
	}{
		{sw: "s-vendor", by: RangeNVD},
		{sw: "s-old", by: RangeNVD, affected: true},
		{sw: "s-marked", cause: CauseDistroSilent, detail: DistroOtherBuild}, // asked about, never left silent
	} {
		got, ok := st[lineKey(v.CVE, c.sw)]
		if !ok || got.by != c.by || got.cause != c.cause || got.detail != c.detail || got.affected != c.affected {
			t.Errorf("%s: %+v (related %v), want by %q affected %v cause %q detail %q", c.sw, got, ok, c.by, c.affected, c.cause, c.detail)
		}
	}
}

// Ubuntu's own build of a repacked upstream ("10.1.61~us1-0ubuntu1~24.04.2") whose CVE Ubuntu lists for other packages only: NVD's
// upstream ranges read its upstream release in Debian's order, so a range of a far older line raises nothing.
func TestMatchAsset_RepackedUpstreamIsOutsideAnOldLine(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	s := Software{ID: "s-ex", Display: "Example Server", Vendor: "Example", Product: "Example Server", Version: "10.1.61~us1", KevKeys: []string{"example|example server"},
		Source: "agent", Packaged: true, PkgVersion: "10.1.61~us1-0ubuntu1~24.04.2", PkgSource: "exampled10"}
	v := Vuln{CVE: "CVE-2017-71020", Vendor: "Example", Product: "Example Server", NVDAnswered: true, Origin: RangeNVD,
		Affected: []Affected{{CPE: "cpe:2.3:a:example:example_server:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.0.0", EndIncl: "7.0.79"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "16.04", Package: "exampled7", Status: "fixed", Fixed: "7.0.68-1ubuntu0.1"}},
		DistroOn: map[string]bool{"ubuntu": true}}
	r := MatchAsset(Asset{ID: "a", Name: "web-01", OS: "Ubuntu 24.04.3 LTS", Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: true}, now)
	if len(r.New)+len(r.Existing) != 0 {
		t.Errorf("a far older line's range raised a finding: %+v", r)
	}
}

// A vendor's build whose upstream part does not state the upstream release plainly is never closed by an upstream range at the
// release it might be: a tilde word ("1.7.24~ds1", a repack of 1.7.24 or a snapshot before it) against a range that starts at
// 1.7.24, and Debian's "X+reallyY" (the release is Y, the version sorts as X) against a fix between Y and X.
func TestMatchAsset_UpstreamBuildOfUnclearReleaseIsNotClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	const cpe = "cpe:2.3:a:example:example_server:*:*:*:*:*:*:*:*"
	for _, c := range []struct {
		ver, full string
		r         VersionRange
	}{
		{"1.7.24~ds1", "1.7.24~ds1-1~noble", VersionRange{StartIncl: "1.7.24", EndExcl: "1.7.30"}},
		{"1.7.24~ds1", "1.7.24~ds1-1~noble", VersionRange{StartIncl: "1.7.24", EndIncl: "1.7.24"}},
		{"2.5+really2.4", "2.5+really2.4-1~noble", VersionRange{EndExcl: "2.4.5"}},
	} {
		s := Software{ID: "s-ex", Display: "Example Server", Vendor: "Example", Product: "Example Server", Version: c.ver,
			Source: "agent", Packaged: true, PkgVersion: c.full, PkgSource: "exampled"}
		v := Vuln{CVE: "CVE-2026-71030", NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: cpe, Range: c.r}},
			DistroOn: map[string]bool{"ubuntu": true}}
		r := MatchAsset(Asset{ID: "a", Name: "web-01", OS: "Ubuntu 24.04.3 LTS", Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: true}, now)
		if len(r.NotAffected) != 0 {
			t.Errorf("%s against %s: closed: %+v", c.full, c.r, r.NotAffected[0].Evidence.Summary)
		}
	}
}

// A release written as a timestamp ("20251015172955.0.0", a vendor's .deb of a date-named release) and a bound written as a date
// ("2023-03-20t20-16-18z") are two notations: their first numbers differ in precision, so ordering them means nothing (a 2022
// timestamp is numerically above 2023). The pair stays undecided rather than closed.
func TestSchemeClash_TimestampAgainstADate(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		r    VersionRange
		ver  string
		want bool
	}{
		{VersionRange{EndExcl: "2023-03-20t20-16-18z"}, "20221005145827.0.0", true},
		{VersionRange{EndExcl: "2023-03-20t20-16-18z"}, "20251015172955.0.0", true},
		{VersionRange{EndExcl: "20230320"}, "20221005145827", true},
		{VersionRange{EndExcl: "20230320"}, "20221005", false},
		{VersionRange{EndExcl: "2016"}, "2019", false},
		{VersionRange{EndExcl: "1607"}, "19045", false},
		{VersionRange{EndExcl: "2016"}, "16.0.1", true},
	} {
		if got := schemeClash(c.r, c.ver); got != c.want {
			t.Errorf("schemeClash(%+v, %s) = %v, want %v", c.r, c.ver, got, c.want)
		}
	}
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	s := Software{ID: "s-obj", Display: "Example Store", Vendor: "Example", Product: "Example Store", Version: "20221005145827.0.0",
		Source: "agent", Packaged: true, PkgVersion: "20221005145827.0.0", PkgSource: "examplestore"}
	v := Vuln{CVE: "CVE-2023-71030", NVDAnswered: true, Origin: RangeNVD,
		Affected: []Affected{{CPE: "cpe:2.3:a:example:example_store:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2023-03-20t20-16-18z"}}}}
	r := MatchAsset(Asset{ID: "a", Name: "store-01", OS: "Ubuntu 24.04.3 LTS", Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: true}, now)
	if len(r.NotAffected) != 0 {
		t.Errorf("a timestamp release was closed against a date bound: %+v", r.NotAffected)
	}
}
