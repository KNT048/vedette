package findings

import (
	"strings"
	"testing"
	"time"
)

// distroCase is one (package line, CVE) pair of a distribution's package and how the pass must leave it: decided by a source, or
// undecided with a named cause (never an unnamed class).
type distroCase struct {
	name   string
	device string
	sw     string
	vuln   Vuln
	by     string // the source that decides it ("" when it stays undecided)
	affect bool
	cause  string // undecided: the named cause
}

// Every pair of a distribution's package is decided by the distribution's data, by the upstream ranges where the distribution's data
// lists fixes only (Alpine), or stays undecided with a cause the coverage names: none is left to an unnamed class.
func TestCoverage_EveryDistributionPackagePairIsDecidedOrNamed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := *e.clock
	pkg := func(id, vendor, product, version, full, source string) Software {
		return Software{ID: id, Display: product, Vendor: vendor, Product: product, Version: version, Source: "agent", Packaged: true, PkgVersion: full, PkgSource: source}
	}
	ubuntu := Asset{ID: "u-1", Name: "web-01", OS: "Ubuntu 26.04.1 LTS", Software: []Software{
		pkg("s-kernel", "Linux", "Kernel", "7.0.0", "7.0.0-44.44", "linux-signed"),
		pkg("s-ssl", "OpenSSL", "OpenSSL", "3.5.5", "3.5.5-1ubuntu3.7", "openssl"),
		pkg("s-glibc", "GNU", "glibc", "2.43", "2.43-2ubuntu2.7", "glibc"),
		pkg("s-apache", "Apache", "HTTP Server", "2.4.62", "2.4.62-1+ubuntu26.04.1+deb.sury.org+1", "apache2"),
		pkg("s-ssh", "OpenBSD", "OpenSSH", "10.2p1", "", ""), // a package row whose agent gave no release or source
	}}
	alpine := Asset{ID: "a-2", Name: "gw-01", OS: "Alpine Linux 3.23.8", Software: []Software{pkg("s-assl", "OpenSSL", "OpenSSL", "3.5.9", "3.5.9-r0", "openssl")}}
	rhel := Asset{ID: "r-3", Name: "db-01", OS: "Red Hat Enterprise Linux 9.4", Software: []Software{pkg("s-rssl", "OpenSSL", "OpenSSL", "3.0.7", "3.0.7-27.el9", "openssl")}}

	const kernel, ssl, glibc, apache, ssh = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
	nvd := func(cve, cpe, end string, rows ...DistroFix) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: cpe, Range: VersionRange{EndExcl: end}}}, Distro: rows,
			DistroOn: map[string]bool{"ubuntu": true}}
	}
	row := func(distro, release, pkg, status, fixed string) DistroFix {
		return DistroFix{Distro: distro, Release: release, Package: pkg, Status: status, Fixed: fixed}
	}
	old := nvd("CVE-2024-60003", kernel, "7.1")
	old.Published = now.AddDate(-2, 0, 0)
	listed := nvd("CVE-2014-60005", ssl, "1.0.1g", row("ubuntu", "14.04", "openssl", "fixed", "1.0.1f-1ubuntu2.1"))
	listed.Vendor, listed.Product, listed.Published = "OpenSSL", "OpenSSL", now.AddDate(-12, 0, 0)
	cases := []distroCase{
		{name: "Ubuntu's not affected decides its signed kernel", device: "u-1", sw: "s-kernel",
			vuln: nvd("CVE-2026-60001", kernel, "7.1", row("ubuntu", "26.04", "linux", "not_affected", "")), by: RangeDistro},
		{name: "a fix of another kernel flavour only", device: "u-1", sw: "s-kernel",
			vuln: nvd("CVE-2026-60002", kernel, "7.1", row("ubuntu", "26.04", "linux-aws", "fixed", "7.0.0-1010.10")), cause: DistroOtherPackages},
		{name: "older than the window and on no list", device: "u-1", sw: "s-kernel", vuln: old, cause: DistroOutsideWindow},
		{name: "affected with no fix yet, on no list", device: "u-1", sw: "s-ssl",
			vuln: nvd("CVE-2026-60004", ssl, "3.6", row("ubuntu", "26.04", "openssl", "open", "")), by: CoverageDistroNoFix, affect: true},
		{name: "an exploited CVE the distribution lists for an older release only", device: "u-1", sw: "s-ssl", vuln: listed, cause: DistroOtherReleases},
		{name: "the distribution's own build of a later upstream than its fix", device: "u-1", sw: "s-glibc",
			vuln: nvd("CVE-2026-60006", glibc, "2.44", row("ubuntu", "26.04", "glibc", "fixed", "2.42-2ubuntu5")), by: RangeDistro},
		{name: "a PPA build of the package", device: "u-1", sw: "s-apache",
			vuln: nvd("CVE-2026-60007", apache, "2.4.66", row("ubuntu", "26.04", "apache2", "fixed", "2.4.62-1ubuntu1.1")), cause: DistroOtherBuild},
		{name: "the distribution has no row of the CVE", device: "u-1", sw: "s-ssl", vuln: nvd("CVE-2026-60008", ssl, "3.6"), cause: DistroNotListed},
		{name: "a package row with no release", device: "u-1", sw: "s-ssh", vuln: nvd("CVE-2026-60009", ssh, "10.6"), cause: CauseVersionNeeded},
		{name: "Alpine's fixed release of the device's branch decides", device: "a-2", sw: "s-assl",
			vuln: nvd("CVE-2026-60010", ssl, "3.6", row("alpine", "3.23", "openssl", "fixed", "3.5.9-r2")), by: RangeDistro, affect: true},
		{name: "Alpine names no fix: the upstream ranges decide", device: "a-2", sw: "s-assl", vuln: nvd("CVE-2026-60011", ssl, "3.5.10"), by: RangeNVD, affect: true},
		{name: "Alpine names no fix and the upstream release is outside", device: "a-2", sw: "s-assl", vuln: nvd("CVE-2026-60012", ssl, "3.5.2"), by: RangeNVD},
		{name: "no data of the distribution", device: "r-3", sw: "s-rssl", vuln: nvd("CVE-2026-60013", ssl, "3.6"), cause: DistroNoData},
	}
	var vulns []Vuln
	for _, c := range cases {
		vulns = append(vulns, c.vuln)
	}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for _, a := range []Asset{ubuntu, alpine, rhel} {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Hostname: ptr(a.Name), IP: "192.0.2.10", Kind: "server", Approved: true}
		e.inv.match[a.ID] = a
	}
	e.feeds.vulns = vulns
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	states := map[string]pairState{}
	for _, a := range []Asset{ubuntu, alpine, rhel} {
		rows, err := readDeviceRows(t.Context(), e.db.Reader(), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		in, err := e.svc.causeInputsOf(t.Context(), rows.questions, cveSet(vulns))
		if err != nil {
			t.Fatal(err)
		}
		st, _ := pairStates(newDevMatch(a, vulns, now), rows, in)
		for k, v := range st {
			states[a.ID+"/"+k] = v
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, ok := states[c.device+"/"+lineKey(c.vuln.CVE, c.sw)]
			if !ok {
				t.Fatalf("the pair is not related")
			}
			if st.by != c.by || st.affected != c.affect || st.cause != c.cause {
				t.Errorf("state %+v, want by %q affected %v cause %q", st, c.by, c.affect, c.cause)
			}
		})
	}
	for k, st := range states {
		if strings.HasPrefix(st.cause, CoverageOther) {
			t.Errorf("%s: unnamed %q", k, st.cause)
		}
	}
}

// Alpine's per-branch rows decide a CVE on no exploited list like Ubuntu's and Debian's (one path, distroVerdict): at or above the
// branch's fixed release is not affected, below it is a finding naming that release; a fix only a later branch has (same upstream
// release) decides too and the evidence names that branch; while the feed's first pull is still to come the upstream ranges wait.
func TestMatchAsset_AlpineRowsDecideCatalogueCVEs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	ssl := func(full string) Asset {
		return Asset{ID: "a", Name: "gw-01", OS: "Alpine Linux 3.23.8", Software: []Software{{ID: "s-ssl", Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL",
			Version: "3.5.9", Source: "agent", Packaged: true, PkgVersion: full, PkgSource: "openssl"}}}
	}
	v := Vuln{CVE: "CVE-2026-60020", NVDAnswered: true, Origin: RangeNVD,
		Affected: []Affected{{CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "3.6"}}},
		Distro:   []DistroFix{{Distro: "alpine", Release: "3.23", Package: "openssl", Status: "fixed", Fixed: "3.5.9-r2"}}}
	if r := MatchAsset(ssl("3.5.9-r2"), []Vuln{v}, map[string]bool{v.CVE: true}, now); len(r.New)+len(r.Existing) != 0 || len(r.NotAffected) != 1 ||
		!strings.Contains(r.NotAffected[0].Evidence.Summary, "Alpine Linux 3.23 fixed CVE-2026-60020 in openssl 3.5.9-r2") {
		t.Fatalf("at the fix: %+v", r)
	}
	r := MatchAsset(ssl("3.5.9-r0"), []Vuln{v}, nil, now)
	if len(r.New) != 1 || r.New[0].Evidence.Summary != "The agent on gw-01 reports OpenSSL 3.5.9-r0 installed from Alpine Linux 3.23's packages. Alpine Linux fixed CVE-2026-60020 in openssl 3.5.9-r2 (Alpine Linux security database), so this device has the flaw until it installs Alpine Linux's security updates." {
		t.Fatalf("below the fix: %+v", r.New)
	}
	f := FixedInFor(ssl("3.5.9-r0"), v)
	if f == nil || f.Kind != "distro" || f.Distro != "Alpine Linux" || f.DistroFixed != "3.5.9-r2" || f.DistroRelease != "3.23" || f.Source != "Alpine Linux security database" {
		t.Fatalf("fixed in: %+v", f)
	}
	later := v
	later.Distro = []DistroFix{{Distro: "alpine", Release: "3.24", Package: "openssl", Status: "fixed", Fixed: "3.5.9-r5"}}
	if r := MatchAsset(ssl("3.5.9-r0"), []Vuln{later}, nil, now); len(r.New) != 1 ||
		!strings.Contains(r.New[0].Evidence.Summary, "from Alpine Linux 3.23's packages. Alpine Linux fixed CVE-2026-60020 in openssl 3.5.9-r5 for its 3.24 branch") {
		t.Fatalf("a later branch's fix: %+v", r.New)
	}
	none := v
	none.Distro, none.DistroLoading = nil, map[string]bool{"alpine": true}
	if r := MatchAsset(ssl("3.5.9-r0"), []Vuln{none}, nil, now); len(r.New) != 0 {
		t.Fatalf("Alpine's first pull still to come, the upstream ranges wait: %+v", r.New)
	}
}

// Ubuntu's and Debian's "affected, no fix yet" of a CVE on no exploited list raises no finding (it would ask for an update that does not
// exist): it waits for the fix or an exploited list; the same word on an exploited CVE is a finding with no fixed package yet.
func TestMatchAsset_UnfixedDistributionWordRaisesOnlyExploitedCVEs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	a := Asset{ID: "a", Name: "web-01", OS: "Ubuntu 26.04.1 LTS", Software: []Software{{ID: "s-ssl", Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL",
		Version: "3.5.5", Source: "agent", Packaged: true, PkgVersion: "3.5.5-1ubuntu3.7", PkgSource: "openssl", KevKeys: []string{"openssl|openssl"}}}}
	v := Vuln{CVE: "CVE-2026-60030", NVDAnswered: true, Origin: RangeNVD, DistroOn: map[string]bool{"ubuntu": true},
		Affected: []Affected{{CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "3.6"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "openssl", Status: "open"}}}
	if r := MatchAsset(a, []Vuln{v}, nil, now); len(r.New) != 0 {
		t.Fatalf("on no list: %+v", r.New)
	}
	if c := distroSilence(swInfoOn(a.Software[0], a), v, now); c != DistroNoFixYet {
		t.Fatalf("cause %q", c)
	}
	v.Vendor, v.Product = "OpenSSL", "OpenSSL"
	r := MatchAsset(a, []Vuln{v}, nil, now)
	if len(r.New) != 1 || FixOf(a, a.Software[0], v).Kind != FixNoneYet {
		t.Fatalf("exploited: %+v", r.New)
	}
}

// Ubuntu's own build of a package it took from Debian experimental carries "~exp" before its mark ("1.14-1~exp2ubuntu1.1"): Ubuntu's
// data names such builds as fixed releases, so a device below one is affected and one at it is fixed, not left undecided.
func TestMatchAsset_UbuntuBuildOfAnExperimentalUploadIsItsOwn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	v := Vuln{CVE: "CVE-2026-60031", NVDAnswered: true, Origin: RangeNVD, DistroOn: map[string]bool{"ubuntu": true}, Published: now.AddDate(0, -1, 0),
		Affected: []Affected{{CPE: "cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "1.15"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "26.04", Package: "gzip", Status: "fixed", Fixed: "1.14-1~exp2ubuntu1.1"}}}
	on := func(pkgVer string) (Asset, MatchResult) {
		a := Asset{ID: "a", Name: "web-01", OS: "Ubuntu 26.04.1 LTS", Software: []Software{{ID: "s-gz", Display: "gzip", Vendor: "GNU", Product: "gzip",
			Version: "1.14", Source: "agent", Packaged: true, PkgVersion: pkgVer, PkgSource: "gzip"}}}
		return a, MatchAsset(a, []Vuln{v}, nil, now)
	}
	if _, r := on("1.14-1~exp2ubuntu1"); len(r.New) != 1 {
		t.Errorf("below Ubuntu's fixed release: %+v", r)
	}
	if a, r := on("1.14-1~exp2ubuntu1.1"); len(r.New) != 0 {
		t.Errorf("at Ubuntu's fixed release: %+v", r)
	} else if d, ok := distroVerdict(swInfoOn(a.Software[0], a), v); !ok || d.kind != distroFixedHere {
		t.Errorf("at Ubuntu's fixed release: %+v %v", d, ok)
	}
	if a, r := on("1.14-1~exp2ubuntu1~ppa1"); len(r.New) != 0 {
		t.Errorf("a PPA build: %+v", r)
	} else if _, ok := distroVerdict(swInfoOn(a.Software[0], a), v); ok {
		t.Error("a PPA build took Ubuntu's word")
	}
}
