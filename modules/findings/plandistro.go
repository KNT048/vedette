package findings

import (
	"cmp"
	"strings"

	"github.com/knt048/vedette/core/debver"
)

// A distribution's package (INV-20). The distribution backports fixes under its own release numbers, so a package is judged by the
// distribution's own fix data, the way Trivy and Grype judge one: at or above the distribution's fixed release, or a CVE the
// distribution marks not affected, is not affected; below the fixed release it is, with that release as the fix; the distribution's
// "affected, no fix yet" is affected with no fixed release.
//
// One mechanism for every distribution the feeds supply (distroVerdict); what differs is data, read through an adapter (distroData):
// how the OS names the release, how releases compare, which release's row decides, which builds are the distribution's own, and
// whether the data lists every CVE it tracks for a package (Ubuntu, Debian: fixed, not affected and affected entries) or its fixed
// releases only (Alpine's secdb: each package's "secfixes" list names the CVEs a release fixed, and "0" the ones that never affected
// it; nothing says a CVE affects a package). For data of fixed releases only, a CVE the data does not list for the package leaves the
// package at its upstream release, which NVD's upstream ranges judge (upstreamJudges), as Grype's apk matcher keeps an NVD match
// secdb has no fix for; silence in Ubuntu's or Debian's data never decides. Red Hat, SUSE and the other RPM distributions have no
// adapter yet: their packages take the fallback.

// distroData is one distribution whose own security data the feeds supply.
type distroData struct {
	id   string                   // the feeds' distro id ("ubuntu", "debian", "alpine")
	name string                   // how the evidence names it ("Ubuntu", "Debian", "Alpine Linux")
	is   func(osName string) bool // the OS is this distribution
	os   func(a Asset) string     // the OS text the release is read from
	rel  func(osName string) string
	// anyRelease: the rows of every release are read and choose picks the one that applies (Alpine: a package from another branch's
	// repository, an OS that names no branch); otherwise only the device's release's rows, and a device whose OS names none is not judged.
	anyRelease bool
	// fixedOnly: the data lists fixed releases only (secdb), so a CVE it does not list for a package says nothing about it: the
	// package is its upstream release, judged by NVD's upstream ranges (upstreamJudges); otherwise silence decides nothing.
	fixedOnly  bool
	kernelRule bool // apt keeps older kernels' packages installed: only the running kernel's count (distroRows)
	// pkgOf is the package release and source package of a row the data may decide: an agent's package row, or a package release a
	// person gave. ok is false for any other row.
	pkgOf func(s Software, osName string) (ver, src string, ok bool)
	// release is the package release the data compares, read from an agent's package version ("" when it is none).
	release func(pkgVer string) string
	// source is the source package under which the data lists a device's source package (securitySource).
	source func(src string) string
	// own says the installed release is the distribution's own build of the package (a PPA, a backport or a vendor's build is not);
	// strict is the rule for "not affected", which compares no version.
	own func(pkg, ver string, strict bool) bool
	// upstream says the installed release carries none of the distribution's packaging marks (debBuildOf): another builder's package or
	// a native one, judged as its upstream product by the upstream ranges and never by this data; nil when every release is the
	// distribution's (Alpine's apk releases).
	upstream func(pkg, ver string) bool
	// applies says a fixed release of the data is about the installed build, so the two compare (the same upstream release of a
	// backport, a later one the distribution built, Debian's kernel moving inside its series).
	applies func(pkg, installed, fixed string) bool
	// compare orders two releases; ok is false when either cannot be read.
	compare func(a, b string) (int, bool)
	// choose is the row of a CVE (among its rows of the package) that decides the installed release on the device's release; ok is
	// false when the data has no word on it there.
	choose func(rows []DistroFix, release, installed string) (DistroFix, bool)
}

func debCompare(a, b string) (int, bool) {
	c, err := debver.Compare(a, b)
	return c, err == nil
}

func apkCompare(a, b string) (int, bool) {
	x, ok1 := parseAPK(a)
	y, ok2 := parseAPK(b)
	return compareAPK(x, y), ok1 && ok2
}

func debPkgOf(s Software, _ string) (string, string, bool) {
	ver, src, _, ok := debPkg(s)
	return ver, src, ok
}

// debRelease is the Ubuntu or Debian release of an OS name as the feeds name it ("24.04", "12").
func debRelease(osName string) string {
	var in swInfo
	in.os, in.osVer = osIdentity(osName)
	_, rel := distroOf(in)
	return rel
}

func osVendor(osName string) string {
	id, _ := osIdentity(osName)
	return id.vendor
}

var (
	ubuntuData = &distroData{id: "ubuntu", name: "Ubuntu", is: func(o string) bool { return osVendor(o) == "canonical" }, os: func(a Asset) string { return a.OS },
		rel: debRelease, kernelRule: true, pkgOf: debPkgOf, release: debReleaseOf, source: func(src string) string { return securitySource("ubuntu", src) },
		own: func(pkg, ver string, strict bool) bool { return ownBuild("ubuntu", pkg, ver, strict) }, upstream: debUpstreamBuild("ubuntu"), applies: debApplies("ubuntu"),
		compare: debCompare, choose: chooseInRelease}
	debianData = &distroData{id: "debian", name: "Debian", is: func(o string) bool { return osVendor(o) == "debian" }, os: func(a Asset) string { return a.OS },
		rel: debRelease, kernelRule: true, pkgOf: debPkgOf, release: debReleaseOf, source: func(src string) string { return securitySource("debian", src) },
		own: func(pkg, ver string, strict bool) bool { return ownBuild("debian", pkg, ver, strict) }, upstream: debUpstreamBuild("debian"), applies: debApplies("debian"),
		compare: debCompare, choose: chooseInRelease}
	alpineData = &distroData{id: DistroAlpine, name: "Alpine Linux", is: func(o string) bool { return linuxDistro(o) == DistroAlpine },
		os: func(a Asset) string { return cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS, a.OS) }, rel: alpineBranch, anyRelease: true, fixedOnly: true,
		pkgOf: apkPkgOf, release: func(v string) string { _, t := apkRelease(v); return t }, source: func(src string) string { return src },
		own: func(string, string, bool) bool { return true }, applies: func(string, string, string) bool { return true }, compare: apkCompare,
		choose: chooseAlpine}
	distroAdapters = []*distroData{ubuntuData, debianData, alpineData}
)

// debUpstreamBuild is distroData.upstream of Ubuntu and Debian.
func debUpstreamBuild(distro string) func(pkg, ver string) bool {
	return func(pkg, ver string) bool { return debBuildOf(distro, pkg, ver) == buildUpstream }
}

// debReleaseOf is the Debian version of an agent's deb row as the data compares it ("1:9.6p1-3ubuntu13.14"); "" when it is none.
func debReleaseOf(v string) string {
	if !debver.Valid(v) {
		return ""
	}
	return v
}

// debApplies is distroData.applies of Ubuntu and Debian: the fix compares with the installed build when the installed release is the
// distribution's own build (review H2 of #732: a PPA or a vendor's build of the same source name compares higher while being another
// build) and either has the fix's upstream release (the backport), or Debian's kernel moved to a later point release of the same
// series (debianKernelMoves), or the installed release is the distribution's own build of a later upstream release than the fix (the
// release took a new upstream version after the fix: Ubuntu 26.04 fixed CVE-2025-15281 in glibc 2.42-2ubuntu5 and ships
// 2.43-2ubuntu2.7); never a kernel's, whose other upstream release is another kernel series. An installed release of an earlier
// upstream than the fix is not compared: the data names the first fixed build of the release, so an own build below it of another
// upstream is one the data does not speak of.
func debApplies(distro string) func(pkg, installed, fixed string) bool {
	return func(pkg, installed, fixed string) bool {
		if !ownBuild(distro, pkg, installed, false) {
			return false
		}
		if debver.SameUpstream(installed, fixed) || debianKernelMoves(distro, pkg, installed, fixed) {
			return true
		}
		if kernelSource(pkg) { // a kernel of another upstream release is another series (a later release's kernel installed by hand)
			return false
		}
		c, err := debver.Compare(installed, fixed)
		return err == nil && c > 0 && laterUpstream(installed, fixed)
	}
}

// distroOfDevice is the adapter of the device's distribution, nil when the feeds supply no data for it.
func distroOfDevice(a Asset) *distroData {
	for _, d := range distroAdapters {
		if d.is(d.os(a)) {
			return d
		}
	}
	return nil
}

// distroOfOS is the adapter of the distribution an OS name names, nil when the feeds supply no data for it.
func distroOfOS(osName string) *distroData {
	for _, d := range distroAdapters {
		if d.is(osName) {
			return d
		}
	}
	return nil
}

// apkPkgOf is the apk release and source package (origin) of an agent's apk row, or of an apk release a person gave (its source
// package, else the product's own name, a guess the data's rows confirm or not).
func apkPkgOf(s Software, _ string) (string, string, bool) {
	_, rel := apkRelease(s.PkgVersion)
	if rel == "" {
		return "", "", false
	}
	src := ""
	switch {
	case s.Packaged && s.builtBy() == "agent":
		src = strings.TrimSpace(s.PkgSource)
	case s.Source == "manual":
		src = cmp.Or(strings.TrimSpace(s.PkgSource), debSourceName(s.Product))
	}
	if src == "" {
		return "", "", false
	}
	return rel, src, true
}

// chooseInRelease is the row of the device's release: a fixed release (a public fix over one only Ubuntu Pro has), else "not affected",
// else "being triaged", else "open" (no fix yet). A stated triage outranks "open": Ubuntu's OSV file writes a release with no fixed
// event for "needed", "deferred" and "needs triage" alike, while its VEX file names the triage, and Debian never states both. A "not
// affected" stated only for an Ubuntu Pro pocket never outranks the public release's own "open": the two differ, so it stays affected.
func chooseInRelease(rows []DistroFix, release, _ string) (DistroFix, bool) {
	var fix, na, triage, open *DistroFix
	for i := range rows {
		f := &rows[i]
		if f.Release != release {
			continue
		}
		switch f.Status {
		case "fixed":
			if f.Fixed != "" && (fix == nil || fix.Pro && !f.Pro) {
				fix = f
			}
		case "not_affected":
			if na == nil || na.Pro && !f.Pro { // a public release's word over a Pro pocket's
				na = f
			}
		case distroTriage:
			triage = f
		case "open":
			if open == nil || open.Pro && !f.Pro { // a public release's word over a Pro pocket's
				open = f
			}
		}
	}
	if na != nil && na.Pro && open != nil && !open.Pro { // the pocket's word differs from the public release's own: the cautious one stands
		na = nil
	}
	for _, f := range []*DistroFix{fix, na, triage, open} {
		if f != nil {
			return *f, true
		}
	}
	return DistroFix{}, false
}

// chooseAlpine is the row of the Alpine branch whose fix applies to the installed release, by the rule of the exploited path
// (alpineFixBranch), or the device's branch's "not affected", or the device's branch's fix of an older upstream version than the release.
// A package release ("-rN") counts within its branch only: another branch's fix is chosen only when the release's upstream version is
// older than the fix's (it is below it), so it never proves the package fixed; with no row of the device's branch that decides, Alpine
// has no word on it and NVD's upstream ranges judge it (upstreamJudges).
func chooseAlpine(rows []DistroFix, osBranch, installed string) (DistroFix, bool) {
	releases := map[string]string{}
	fixed, na := map[string]DistroFix{}, map[string]DistroFix{}
	for _, f := range rows {
		if !branchKeyRE.MatchString(f.Release) {
			continue
		}
		switch f.Status {
		case "fixed":
			if _, ok := parseAPK(f.Fixed); ok {
				releases[f.Release], fixed[f.Release] = f.Fixed, f
			}
		case "not_affected":
			na[f.Release] = f
		}
	}
	if f, ok := na[osBranch]; ok && osBranch != "" && releases[osBranch] == "" {
		return f, true
	}
	rel, ok := parseAPK(installed)
	if !ok || len(releases) == 0 {
		return DistroFix{}, false
	}
	if b, by := alpineFixBranch(releases, osBranch, rel, installed); by != branchNone {
		return fixed[b], true
	}
	if f, ok := fixed[osBranch]; ok && osBranch != "" { // the device's branch fixed an older upstream version than the release
		return f, true
	}
	return DistroFix{}, false
}

// laterUpstream says Debian version a has the same epoch as b and a later upstream release ("2.43-2ubuntu2.7" of "2.42-2ubuntu5").
func laterUpstream(a, b string) bool {
	ua, ea := debUpstream(a)
	ub, eb := debUpstream(b)
	if ea != eb {
		return false
	}
	c, err := debver.Compare(ua, ub)
	return err == nil && c > 0
}

// debUpstream is a Debian version without its revision ("1:2.43" of "1:2.43-2ubuntu2.7") and its epoch ("1"; "0" when none).
func debUpstream(v string) (string, string) {
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	epoch, _, ok := strings.Cut(v, ":")
	if !ok {
		epoch = "0"
	}
	return v, epoch
}
