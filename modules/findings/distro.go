package findings

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/debver"
)

// Distribution backports (D-516). Ubuntu and Debian fix a package without changing its upstream version, so NVD's
// upstream ranges cannot tell a patched OpenSSH 9.6p1 from a vulnerable one. For a row an agent read from the device's
// package database, with its full Debian version and source package, on a device whose OS names the release, the
// distribution's word decides:
//   - installed version at or above the version the distribution fixed it in, or the distribution says the package is
//     not affected: proved not affected (no new finding; an open suspected one closes as not_relevant, D-530);
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

// ownBuild says whether the installed revision is the distribution's own build; strict is the rule for "not affected".
func ownBuild(distro, version string, strict bool) bool {
	rev := debver.Revision(version)
	if distro == "debian" {
		return debianOwnRE.MatchString(rev)
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
		if !debver.SameUpstream(in.pkgVer, fix.Fixed) || !ownBuild(d, in.pkgVer, false) {
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
		if !ownBuild(d, in.pkgVer, true) {
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
		if d.kind == distroNotAffected {
			note = fmt.Sprintf("Not affected: %s says its %s package of %s %s is not affected by %s (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
				d.name, clean(d.pkg), d.name, d.release, v.CVE, src)
		}
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}}, outNotAffected
	}
	m := Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisVersion, Confidence: ConfVersion, Severity: SeverityHigh}
	if v.Ransomware || v.EPSS >= 0.5 {
		m.Severity = SeverityCritical
	}
	pro := ""
	if d.pro {
		pro = " (Ubuntu Pro)"
	}
	m.Evidence = Evidence{CheckedAt: now, Summary: fmt.Sprintf("%s runs %s %s from %s %s's packages. %s fixed %s in %s %s%s (%s); no scan has confirmed it yet, so this is only suspected.",
		clean(a.Name), clean(s.Display), clean(in.pkgVer), d.name, d.release, d.name, v.CVE, clean(d.pkg), clean(d.fixed), pro, src)}
	return m, outMatch
}
