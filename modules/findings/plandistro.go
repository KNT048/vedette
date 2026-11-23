package findings

import (
	"cmp"
	"strings"

	"github.com/knt048/vedette/core/debver"
)

// A distribution's package (INV-20). The distribution backports fixes under its own release numbers, so a package is judged by the
// distribution's own fix data, the way Trivy and Grype judge one: at or above the distribution's fixed release, or a CVE the
// distribution marks not affected, is not affected; below the fixed release it is, with that release as the fix.
//
// One mechanism for every distribution the feeds supply; what differs is data, read through an adapter (distroData): how the OS names
// the release, how releases compare, which release's row decides, and whether the data lists every CVE it tracks for a package (Ubuntu,
// Debian: a CVE it does not list is no item) or its fixed releases only (Alpine's secdb: a CVE NVD puts the package inside and Alpine
// does not list has no fix from Alpine yet). Red Hat, SUSE and the other RPM distributions have no adapter yet: their packages take the
// fallback.

// distroData is one distribution whose own security data the feeds supply.
type distroData struct {
	id  string                   // the feeds' distro id ("ubuntu", "debian", "alpine")
	is  func(osName string) bool // the OS is this distribution
	os  func(a Asset) string     // the OS text the release is read from
	rel func(osName string) string
	// anyRelease: the rows of every release are read and choose picks the one that applies (Alpine: a package from another branch's
	// repository, an OS that names no branch); otherwise only the device's release's rows, and a device whose OS names none is not judged.
	anyRelease bool
	// fixedOnly: the data lists fixed releases only (secdb), so a CVE NVD's upstream range puts the package inside and the data does not
	// list for it has no fix from the distribution yet; otherwise such a CVE is no item (the data lists what the distribution tracks).
	fixedOnly  bool
	kernelRule bool // apt keeps older kernels' packages installed: only the running kernel's count (distroRows)
	// pkgOf is the package release and source package of a row the data may decide: an agent's package row, or a package release a
	// person gave. ok is false for any other row.
	pkgOf func(s Software, osName string) (ver, src string, ok bool)
	// source is the source package under which the data lists a device's source package (securitySource).
	source func(src string) string
	// own says the installed release is the distribution's own build of the package (a PPA, a backport or a vendor's build is not).
	own func(pkg, ver string) bool
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
	ubuntuData = &distroData{id: "ubuntu", is: func(o string) bool { return osVendor(o) == "canonical" }, os: func(a Asset) string { return a.OS }, rel: debRelease,
		kernelRule: true, pkgOf: debPkgOf, source: func(src string) string { return securitySource("ubuntu", src) },
		own: func(pkg, ver string) bool { return ownBuild("ubuntu", pkg, ver, false) }, compare: debCompare, choose: chooseInRelease}
	debianData = &distroData{id: "debian", is: func(o string) bool { return osVendor(o) == "debian" }, os: func(a Asset) string { return a.OS }, rel: debRelease,
		kernelRule: true, pkgOf: debPkgOf, source: func(src string) string { return securitySource("debian", src) },
		own: func(pkg, ver string) bool { return ownBuild("debian", pkg, ver, false) }, compare: debCompare, choose: chooseInRelease}
	alpineData = &distroData{id: DistroAlpine, is: func(o string) bool { return linuxDistro(o) == DistroAlpine },
		os: func(a Asset) string { return cmp.Or(a.ManualOS, a.AgentOS, a.SNMPOS, a.OS) }, rel: alpineBranch, anyRelease: true, fixedOnly: true,
		pkgOf: apkPkgOf, source: func(src string) string { return src }, own: func(string, string) bool { return true }, compare: apkCompare, choose: chooseAlpine}
	distroAdapters = []*distroData{ubuntuData, debianData, alpineData}
)

// distroOfDevice is the adapter of the device's distribution, nil when the feeds supply no data for it.
func distroOfDevice(a Asset) *distroData {
	for _, d := range distroAdapters {
		if d.is(d.os(a)) {
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
// else "open" (no fix yet).
func chooseInRelease(rows []DistroFix, release, _ string) (DistroFix, bool) {
	var fix, na, open *DistroFix
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
			na = f
		case "open":
			open = f
		}
	}
	for _, f := range []*DistroFix{fix, na, open} {
		if f != nil {
			return *f, true
		}
	}
	return DistroFix{}, false
}

// chooseAlpine is the row of the Alpine branch whose fix applies to the installed release, by the rule of the exploited path
// (alpineFixBranch: the device's branch when its fix has the release's upstream version, else the branch whose fix has it), or the
// device's branch's "not affected". A release at or above every fix whose upstream no fix has is at or above the highest one; else the
// device's branch's fix decides; with no branch named and no fix of its upstream, Alpine has no word on it.
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
	if !ok {
		return DistroFix{}, false
	}
	if len(releases) == 0 {
		if osBranch == "" {
			for _, f := range na { // every branch Alpine names says not affected
				return f, true
			}
		}
		return DistroFix{}, false
	}
	if b, by := alpineFixBranch(releases, osBranch, rel, installed); by != branchNone {
		return fixed[b], true
	}
	var top DistroFix
	above := true
	for _, f := range fixed {
		x, _ := parseAPK(f.Fixed)
		if compareAPK(rel, x) < 0 {
			above = false
		}
		if y, ok := parseAPK(top.Fixed); !ok || compareAPK(x, y) > 0 {
			top = f
		}
	}
	if above {
		return top, true
	}
	if f, ok := fixed[osBranch]; ok {
		return f, true
	}
	return DistroFix{}, false
}
