// Package pkgrel says whether two readings of a software's release are the same release written with more or less detail:
// a scan banner's "10.2", an upstream "10.2p1", Alpine's "10.2_p1-r1", Debian's "1:10.2p1-2ubuntu3.8", RPM's "8.7p1-38.el9".
// A pure function on text a device, a person or a scan sent; a text of another shape is compared as written, never guessed.
package pkgrel

import (
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apkver"
)

var (
	epochRE = regexp.MustCompile(`^[0-9]+:`)
	patchRE = regexp.MustCompile(`^p[0-9]*$`)
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
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

// Same reports whether two readings are one release: each reading is its package release when it has one, else its version.
// "10.2" and "10.2p1" are the same (the shorter one omits the patch level); 10.2 and 9.8, or 10.2 and 10.3, are not. An empty
// reading is never the same as anything.
func Same(aVersion, aPkg, bVersion, bPkg string) bool {
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
