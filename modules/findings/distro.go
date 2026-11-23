package findings

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/productid"
)

// linuxDistro is the Linux distribution an OS name names, as a platform id ("alpine", "ubuntu", "debian", "rhel", "suse"), "" for
// none (Windows, a network OS, an unknown OS).
func linuxDistro(osName string) string {
	for _, id := range platformsIn(osName) {
		switch id {
		case "alpine", "ubuntu", "debian", "rhel", "suse":
			return id
		}
	}
	return ""
}

var (
	debEpoch   = regexp.MustCompile(`^[0-9]+:`)
	debPkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
)

// personDeb says a package release a person gave is a full Debian version with a revision ("1:10.2p1-2ubuntu3.8", "9.2p1-2+deb12u3").
func personDeb(p string) bool {
	p = strings.TrimSpace(p)
	if _, t := apkRelease(p); t != "" {
		return false
	}
	return debver.Valid(p) && debver.Revision(p) != ""
}

// debPkg is the full Debian version and source package of a row the Ubuntu or Debian data can decide on the plan: an agent's deb row
// (both read from the package database), or a Debian release a person gave (Needs your input, a correction), which the
// distribution's word decides like an agent's row: its source package is the row's when inventory kept one, else the product's own
// name as Debian and Ubuntu name many sources ("openssh"; guessed true). A guessed name is only a key to ask the feeds for: many
// sources are named otherwise (postgresql-16, bind9, exim4, php8.3), so the plan reads the distribution's data for such a row only
// when the feeds hold rows under that name, and otherwise compares its upstream version with NVD (tierIndex.byDistroData).
func debPkg(s Software) (version, source string, guessed, ok bool) {
	switch {
	case s.Packaged && s.builtBy() == "agent" && s.PkgVersion != "" && s.PkgSource != "":
		return s.PkgVersion, s.PkgSource, false, true
	case s.Source == "manual" && personDeb(s.PkgVersion):
		if src := strings.TrimSpace(s.PkgSource); src != "" {
			return strings.TrimSpace(s.PkgVersion), src, false, true
		}
		if src := debSourceName(s.Product); src != "" {
			return strings.TrimSpace(s.PkgVersion), src, true, true
		}
	}
	return "", "", false, false
}

// debSourceName is a product's name as Debian names its source package ("OpenSSH" -> "openssh"), "" when it is not one.
func debSourceName(product string) string {
	if n := strings.ToLower(strings.TrimSpace(product)); debPkgName.MatchString(n) {
		return n
	}
	return ""
}

// pkgReleaseText says a text is a distribution's package release: Alpine's apk ("10.2_p1-r1"), a release with a distribution's mark
// ("2ubuntu3.8", "+deb12u3", ".el9"), or a Debian version with an epoch ("1:9.2p1-2"). A plain "7.2.13" or "v7.2.13" is not.
func pkgReleaseText(p string) bool {
	p = strings.TrimSpace(p)
	if _, t := apkRelease(p); t != "" {
		return true
	}
	return distroMarked(p) || debEpoch.MatchString(p) && debver.Valid(p)
}

// Distribution backports. Ubuntu and Debian fix a package without changing its upstream version, so NVD's
// upstream ranges cannot tell a patched OpenSSH 9.6p1 from a vulnerable one. For a row an agent read from the device's
// package database, with its full Debian version and source package, on a device whose OS names the release, the
// distribution's word decides:
//   - installed version at or above the version the distribution fixed it in, or the distribution says the package is
//     not affected: proved not affected (no new finding; an open suspected one closes as not_relevant);
//   - installed below the fixed version: affected, basis version, and "Fixed in <distro version> for <release>";
//   - no word (no row for the release and package, still open, needs triage, deferred, ignored): NVD decides, as before.
//
// A fixed version beats "not affected" (feeds keep both kinds for Ubuntu from two files): the comparison is the stronger
// evidence, and it keeps a finding open rather than closing one.

type distroKind int

const (
	distroFixedHere   distroKind = iota + 1 // installed >= fixed
	distroNotAffected                       // the distribution says its package is not affected
	distroNeeded                            // installed < fixed
)

// distroAnswer is the distribution's word on one software row for one CVE.
type distroAnswer struct {
	kind    distroKind
	pkg     string // the source package the distribution's data names ("linux" for a linux-signed kernel)
	name    string // "Ubuntu", "Debian"
	release string // "24.04", "12"
	fixed   string // the fixed version (fixed here, needed)
	pro     bool   // the fix is in Ubuntu Pro (ESM) only
}

// DistroSource names where a distribution's word comes from, for the evidence line and FixedIn.Source.
func DistroSource(name string) string {
	if name == "Debian" {
		return "Debian Security Tracker"
	}
	return "Ubuntu security data"
}

// distroOf is the distribution and release of the device's OS as the feeds name them ("ubuntu", "24.04"; "debian", "12").
func distroOf(in swInfo) (string, string) {
	switch in.os.vendor {
	case "canonical":
		return "ubuntu", in.osVer
	case "debian":
		major, _, _ := strings.Cut(in.osVer, ".")
		return "debian", major
	}
	return "", ""
}

// DeviceDistro is the distribution whose own security data the feeds supply ("ubuntu", "debian", "alpine") when it can say something
// about this device: its OS is that distribution and it has at least one package row that data names (distroRows); "" otherwise. The
// feeds module pulls a distribution's files only while some device needs them (LEAN).
func DeviceDistro(a Asset) string {
	d, _, _ := DevicePackages(a)
	return d
}

// DevicePackages is DeviceDistro with the release as the distribution's data is asked for it ("24.04", "12"; "" for a distribution
// whose rows of every release are read, Alpine: the plan picks the branch, distroData.anyRelease) and the source packages of the
// device's package rows as the security data names them (securitySource: "linux" for linux-signed), sorted, each once (the
// distribution feeds keep the tier CVEs' rows for these packages only). A kernel's packages count only for the running kernel
// (distroRows). "" and nil when DeviceDistro is "".
func DevicePackages(a Asset) (distro, release string, pkgs []string) {
	d, rel, rows := distroRows(a)
	if d == nil || len(rows) == 0 {
		return "", "", nil
	}
	for _, r := range rows {
		pkgs = append(pkgs, r.pkg)
	}
	slices.Sort(pkgs)
	if d.anyRelease {
		rel = ""
	}
	return d.id, rel, slices.Compact(pkgs)
}

// distroPkgRow is a row the distribution's word may decide on the plan: its swInfo, its package release and its source package as the
// security data names it.
type distroPkgRow struct {
	s   Software
	in  swInfo
	ver string // the package release ("1:9.6p1-3ubuntu13.14", "10.2_p1-r1")
	pkg string
}

// distroRows are the device's package rows the plan compares with its distribution's data (distroData.pkgOf: an agent's package row
// with its release and source package, or a package release a person gave), with that distribution and the device's release ("" when
// the OS names none: no row, unless the distribution's rows of every release are read, Alpine). Packages of a kernel source count only
// when they are the running kernel's (review r1 #1 of #808, distroData.kernelRule): apt keeps the previous kernel's linux-modules-*,
// linux-headers-* and linux-tools-* installed, intake blanks only the image of a kernel that does not run, and those rows would plan
// "Upgrade linux" on a box that already runs the fix. The running kernel is the Kernel row intake built from the running image (its
// source and version); a device without one compares no kernel package (drop when unsure).
func distroRows(a Asset) (d *distroData, release string, rows []distroPkgRow) {
	d = distroOfDevice(a)
	if d == nil {
		return nil, "", nil
	}
	osName := d.os(a)
	release = d.rel(osName)
	if release == "" && !d.anyRelease {
		return d, "", nil
	}
	var ksrc, kver string
	var all []distroPkgRow
	for _, s := range a.Software {
		ver, src, ok := d.pkgOf(s, osName)
		if !ok {
			continue
		}
		in := newSWInfo(s, osName)
		in.pkgVer, in.pkgSrc = ver, src
		r := distroPkgRow{s: s, in: in, ver: ver, pkg: d.source(src)}
		if d.kernelRule && productid.Norm(s.Vendor) == "linux" && productid.Norm(s.Product) == "kernel" {
			ksrc, kver = r.pkg, ver
		}
		all = append(all, r)
	}
	for _, r := range all {
		if d.kernelRule && kernelSource(r.pkg) && (r.pkg != ksrc || r.ver != kver) {
			continue
		}
		rows = append(rows, r)
	}
	return d, release, rows
}

// notKernel are the linux-* source packages that build no kernel, kernel modules, headers or tools.
var notKernel = map[string]bool{"linux-firmware": true, "linux-atm": true, "linux-base": true, "linux-sound-base": true}

// kernelSource says whether a source package (as the security data names it) builds a Linux kernel or its modules, headers and
// tools: "linux", "linux-hwe-6.8", "linux-aws", "linux-meta", "linux-restricted-modules".
func kernelSource(pkg string) bool {
	return pkg == "linux" || strings.HasPrefix(pkg, "linux-") && !notKernel[pkg]
}

// securitySource is the source package under which the distribution's security data lists a device's source package.
// Kernel images are built by a signing source package whose binaries carry the kernel's own version, while Ubuntu's and
// Debian's data list the kernel's source: Ubuntu linux-signed → linux, linux-signed-hwe-7.0 → linux-hwe-7.0; Debian
// linux-signed-amd64 (and -arm64, -i386) → linux. Every other package is listed under its own source name.
func securitySource(distro, src string) string {
	rest, ok := strings.CutPrefix(src, "linux-signed")
	switch {
	case !ok:
		return src
	case distro == "debian":
		return "linux"
	}
	return "linux" + rest
}

// The distribution's word is about the distribution's own package (review H2 of #732). A package from a PPA or a vendor's
// repository can share the source name and compare higher ("2.4.62-1+ubuntu24.04.1+deb.sury.org+1" against Ubuntu's fix
// "2.4.58-1ubuntu8.8") while being another build, so the word applies only to a revision the distribution itself builds,
// and anything else is left to NVD:
//   - Ubuntu: a revision with Ubuntu's own mark ("3ubuntu13.14", "0ubuntu0.24.04.1", "1ubuntu0.1~22.04.1", "2build1",
//     "+esm6"), or a plain Debian revision ("43.43" of a kernel, "2" of a package Ubuntu took from Debian unchanged) for a fix;
//   - Debian: a plain revision, optionally a stable update ("+deb12u3", "~deb12u1") and a binNMU ("+b1").
//
// A PPA (~ppa, ondrej's +deb.sury.org), a backport (~bpo12+1), a vendor suffix (~noble, ~ubuntu.24.04, ~bookworm) or a
// native version with no revision does not match. "Not affected" has no version to compare, so on Ubuntu it needs
// Ubuntu's own mark (a plain revision may be a vendor's own .deb).
var (
	ubuntuOwnRE = regexp.MustCompile(`^[0-9][0-9.]*((build|ubuntu)[0-9][0-9.]*)+(\+esm[0-9]+)?(~[0-9][0-9.]*)*$`)
	debianOwnRE = regexp.MustCompile(`^[0-9][0-9.]*([+~]deb[0-9]+u[0-9]+)?(\+b[0-9]+)?$`)
)

// ubuntuKernelRE is the revision of an Ubuntu kernel built for an older release or a cloud: "45.45~22.04.1" (HWE),
// "1015.16~22.04.1" (a cloud kernel), the plain ABI.upload revision with the release it was backported to (review round 2 of
// #732). Digits only after "~", so "45.45~ppa1" and "~bpo" do not match.
var ubuntuKernelRE = regexp.MustCompile(`^[0-9][0-9.]*(~[0-9][0-9.]*)*$`)

// ownBuild says whether the installed revision is the distribution's own build of the source package pkg (as the security data
// names it); strict is the rule for "not affected".
func ownBuild(distro, pkg, version string, strict bool) bool {
	rev := debver.Revision(version)
	if distro == "debian" {
		return debianOwnRE.MatchString(rev)
	}
	if !strict && (pkg == "linux" || strings.HasPrefix(pkg, "linux-")) && ubuntuKernelRE.MatchString(rev) {
		return true
	}
	return ubuntuOwnRE.MatchString(rev) || !strict && debianOwnRE.MatchString(rev) && !strings.Contains(rev, "deb")
}

// distroVerdict reads v.Distro for the software row; ok is false when the distribution has no word on it.
func distroVerdict(in swInfo, v Vuln) (distroAnswer, bool) {
	if in.pkgVer == "" || in.pkgSrc == "" || len(v.Distro) == 0 {
		return distroAnswer{}, false
	}
	d, rel := distroOf(in)
	if d == "" || rel == "" {
		return distroAnswer{}, false
	}
	pkg := securitySource(d, in.pkgSrc)
	var fix *DistroFix
	notAffected := false
	for i := range v.Distro {
		f := &v.Distro[i]
		if f.Distro != d || f.Release != rel || f.Package != pkg {
			continue
		}
		switch f.Status {
		case "fixed":
			if fix == nil || fix.Pro && !f.Pro { // a public fix over one only Ubuntu Pro has
				fix = f
			}
		case "not_affected":
			notAffected = true
		}
	}
	a := distroAnswer{pkg: pkg, name: distroName(in), release: rel}
	switch {
	case fix != nil:
		// only the backport case: the same epoch and upstream release, a revision the distribution builds (review H2)
		if !debver.SameUpstream(in.pkgVer, fix.Fixed) || !ownBuild(d, pkg, in.pkgVer, false) {
			return distroAnswer{}, false
		}
		c, err := debver.Compare(in.pkgVer, fix.Fixed)
		if err != nil {
			return distroAnswer{}, false // a version Vedette cannot compare: NVD decides
		}
		a.fixed, a.pro, a.kind = fix.Fixed, fix.Pro, distroNeeded
		if c >= 0 {
			a.kind = distroFixedHere
		}
	case notAffected:
		if !ownBuild(d, pkg, in.pkgVer, true) {
			return distroAnswer{}, false
		}
		a.kind = distroNotAffected
	default:
		return distroAnswer{}, false
	}
	return a, true
}

// distroMatch is matchOne's result for a row the distribution has a word on.
func distroMatch(a Asset, s Software, in swInfo, v Vuln, d distroAnswer, now time.Time) (Match, outcome) {
	src := DistroSource(d.name)
	if d.kind != distroNeeded {
		note := fmt.Sprintf("Not affected: %s %s fixed %s in %s %s, and this device has %s (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
			d.name, d.release, v.CVE, clean(d.pkg), clean(d.fixed), clean(in.pkgVer), src)
		provedOn := strings.TrimSpace(in.pkgVer)
		if d.kind == distroNotAffected { // the distribution's word on the package, no version compared
			provedOn = ""
			note = fmt.Sprintf("Not affected: %s says its %s package of %s %s is not affected by %s (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
				d.name, clean(d.pkg), d.name, d.release, v.CVE, src)
		}
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, provedOn: provedOn}, outNotAffected
	}
	m := Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisVersion, Confidence: ConfVersion, Severity: SeverityHigh, bounded: true}
	if v.Ransomware || v.EPSS >= 0.5 {
		m.Severity = SeverityCritical
	}
	pro := ""
	if d.pro {
		pro = " (Ubuntu Pro)"
	}
	m.Evidence = Evidence{CheckedAt: now, Summary: fmt.Sprintf("%s runs %s %s from %s %s's packages. %s fixed %s in %s %s%s (%s); no scan has confirmed it yet, so this is only suspected.",
		clean(a.Name), softwareName(s.Display, in.pkgVer), clean(in.pkgVer), d.name, d.release, d.name, v.CVE, clean(d.pkg), clean(d.fixed), pro, src)}
	if s.Source == "agent" { // The agent read the installed package; a detection
		m.Evidence.Agent = true
		if deviceSays(a) { // a person's OS correction is not the device's word
			m.Evidence.Source = SourceAgent
		}
		m.Evidence.Summary = fmt.Sprintf("The agent on %s reports %s %s installed from %s %s's packages. %s fixed %s in %s %s%s (%s), so this device has the flaw until it installs %s's security updates.",
			clean(a.Name), softwareName(s.Display, in.pkgVer), clean(in.pkgVer), d.name, d.release, d.name, v.CVE, clean(d.pkg), clean(d.fixed), pro, src, d.name)
	}
	return m, outMatch
}
