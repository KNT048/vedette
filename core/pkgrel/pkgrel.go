// Package pkgrel says whether two readings of a software's release are the same release written with more or less detail:
// a scan banner's "10.2", an upstream "10.2p1", Alpine's "10.2_p1-r1", Debian's "1:10.2p1-2ubuntu3.8", RPM's "8.7p1-38.el9".
// A pure function on text a device, a person or a scan sent; a text of another shape is compared as written, never guessed.
package pkgrel

import (
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
)

var (
	epochRE = regexp.MustCompile(`^[0-9]+:`)
	// a distribution's package revision after the last hyphen: Debian "2", "2ubuntu3.8", "2+deb12u3", RPM "38.el9"; never a
	// pre-release ("rc1", "beta") or a date part
	revisionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9._+~]*$`)
	bareRE     = regexp.MustCompile(`^[0-9]+$`)
	patchRE    = regexp.MustCompile(`^p[0-9]*$`)
)

// Upstream is the upstream version a release text names, lower case: a banner's extra words are dropped ("10.2p1 Ubuntu
// 2ubuntu3.8" is 10.2p1), an apk release reads as NVD writes it ("10.2_p1-r1" is 10.2p1), and a Debian or RPM release loses its
// epoch and its distribution revision ("1:9.2p1-2+deb12u3" is 9.2p1, "8.7p1-38.el9" is 8.7p1).
func Upstream(v string) string {
	v = strings.TrimSpace(v)
	if f := strings.Fields(v); len(f) > 0 {
		v = f[0]
	}
	if apkver.Valid(v) {
		return strings.ToLower(apkver.NVDVersion(v))
	}
	v = epochRE.ReplaceAllString(v, "")
	if i := strings.LastIndexByte(v, '-'); i > 0 && revisionRE.MatchString(v[i+1:]) && !strings.Contains(v[:i], "-") && !bareRE.MatchString(v[:i]) {
		v = v[:i]
	}
	return strings.ToLower(v)
}

// Same reports whether two readings are one release: each reading is its package release when it has one, else its version.
// "10.2" and "10.2p1" are the same (the shorter one omits the patch level); 10.2 and 9.8, or 10.2 and 10.3, are not. An empty
// reading is never the same as anything.
func Same(aVersion, aPkg, bVersion, bPkg string) bool {
	if ea, eb := epochOf(pick(aPkg, aVersion)), epochOf(pick(bPkg, bVersion)); ea != "" && eb != "" && ea != eb {
		return false // another epoch is another package line
	}
	a, b := Upstream(pick(aPkg, aVersion)), Upstream(pick(bPkg, bVersion))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// A reading may also hold both: a person's version "10.2" next to the package release "10.2_p1-r1": either of its two is enough
	if aPkg != "" && aVersion != "" {
		if Upstream(aVersion) == b {
			return true
		}
	}
	if bPkg != "" && bVersion != "" && Upstream(bVersion) == a {
		return true
	}
	return lessPrecise(a, b) || lessPrecise(b, a)
}

func pick(pkg, version string) string {
	if strings.TrimSpace(pkg) != "" {
		return pkg
	}
	return version
}

// lessPrecise: long is short followed only by a patch level ("10.2" and "10.2p1").
func lessPrecise(short, long string) bool {
	return strings.HasPrefix(long, short) && patchRE.MatchString(long[len(short):])
}

// epochOf is the epoch of a release text ("1" of "1:9.2p1-2"), "" when it has none.
func epochOf(v string) string {
	if e := epochRE.FindString(strings.TrimSpace(v)); e != "" {
		return e
	}
	return ""
}

// The Linux distribution families an OS name can name, as platform ids, with the words that name them.
var distroWords = []struct {
	id string
	re *regexp.Regexp
}{
	{"alpine", regexp.MustCompile(`(?i)\balpine\b`)},
	{"ubuntu", regexp.MustCompile(`(?i)\bubuntu\b`)},
	{"debian", regexp.MustCompile(`(?i)\b(debian|raspbian)\b`)},
	{"rhel", regexp.MustCompile(`(?i)\b(red ?hat|rhel|centos|rocky|almalinux|oracle linux|fedora|amazon linux)\b`)},
	{"suse", regexp.MustCompile(`(?i)\b(open)?suse\b|\bsles\b`)},
}

// Distro is the Linux distribution family an OS name names ("alpine", "ubuntu", "debian", "rhel", "suse"), "" for none (Windows, a
// network OS such as Junos, an unknown OS). Only a distribution builds packages whose release differs from the upstream version.
func Distro(osName string) string {
	for _, w := range distroWords {
		if w.re.MatchString(osName) {
			return w.id
		}
	}
	return ""
}

// distroMarkRE is a distribution's mark inside a package revision ("2.4.52-1ubuntu4", "1.1.1n-0+deb11u5", "1.2-3.el9").
var distroMarkRE = regexp.MustCompile(`(?i)ubuntu|[+~.-]deb\d|\.(el|fc)\d`)

// Marked says a release text carries a distribution's mark in its revision ("2ubuntu3.8", "+deb12u3", ".el9").
func Marked(v string) bool { return distroMarkRE.MatchString(v) }

// Release says a text is a distribution's package release by its own shape: Alpine's apk ("10.2_p1-r1", also after a package
// name: "openssh-10.2_p1-r1"), a release with a distribution's mark ("1:10.2p1-2ubuntu3.8", "9.2p1-2+deb12u3", "8.7p1-38.el9"), or a
// Debian version with an epoch ("1:9.2p1-2"). A vendor's release ("15.1R7.9", "v7.2.13", "9.6") is not one.
func Release(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if apkver.Valid(p) {
		return true
	}
	for j := 0; j+1 < len(p); j++ {
		if p[j] == '-' && p[j+1] >= '0' && p[j+1] <= '9' && apkver.Valid(p[j+1:]) {
			return true
		}
	}
	return Marked(p) || epochRE.MatchString(p) && debver.Valid(p)
}
