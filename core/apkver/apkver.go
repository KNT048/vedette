// Package apkver reads and orders Alpine package releases (D-604, D-605): apk's version format, "10.2_p1-r1" = upstream 10.2p1 (the
// _p1 suffix), Alpine's package revision 1. Only what Alpine's openssh and similar packages use: dotted digits, an optional letter,
// suffixes (_alpha _beta _pre _rc before the release, _cvs _svn _git _hg _p after it, each with an optional number) and the -rN
// revision. Compared as apk-tools does for these shapes: numbers numerically, then the letter, the suffixes, the revision. A pure
// function on text a device, a person or a feed sent: a release of another shape is refused, never guessed.
package apkver

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
)

var apkVerRE = regexp.MustCompile(`^(\d{1,9}(?:\.\d{1,9}){0,7})([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d{0,9}){0,4})-r(\d{1,9})$`)

var apkSuffixRE = regexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)`)

// apkSuffixRank orders the suffixes: the pre-release ones before none (0), the post-release ones after.
var apkSuffixRank = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

// Version is a parsed apk release.
type Version struct {
	nums     []int
	letter   string
	suffixes [][2]int // rank, number
	rev      int
}

// Parse reads an Alpine package release with its revision ("10.2_p1-r1"); ok is false for any other shape (a Debian or RPM release,
// an upstream version without -rN).
func Parse(s string) (Version, bool) {
	m := apkVerRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	var v Version
	for i, p := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(p)
		// apk-tools compares a later component with a leading zero as a string ("1.05" < "1.4"); Vedette refuses it rather than
		// order it otherwise (review r1 L4 of #968: no fixed KEV release has one, 2026-11-17)
		if err != nil || i > 0 && len(p) > 1 && p[0] == '0' {
			return Version{}, false
		}
		v.nums = append(v.nums, n)
	}
	v.letter = m[2]
	for _, sm := range apkSuffixRE.FindAllStringSubmatch(m[3], -1) {
		n := -1 // a suffix without a number comes before the same suffix with 0, as in apk-tools ("1.0_p" < "1.0_p0")
		if sm[2] != "" {
			n, _ = strconv.Atoi(sm[2])
		}
		v.suffixes = append(v.suffixes, [2]int{apkSuffixRank[sm[1]], n})
	}
	v.rev, _ = strconv.Atoi(m[4])
	return v, true
}

// Compare orders two parsed releases (-1, 0, 1).
func Compare(a, b Version) int {
	for i := 0; i < max(len(a.nums), len(b.nums)); i++ {
		switch {
		case i >= len(a.nums):
			return -1 // 1.0 < 1.0.1
		case i >= len(b.nums):
			return 1
		}
		if c := cmp.Compare(a.nums[i], b.nums[i]); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(a.letter, b.letter); c != 0 {
		return c
	}
	for i := 0; i < max(len(a.suffixes), len(b.suffixes)); i++ {
		var x, y [2]int // a missing suffix ranks as none (0): 1.0_rc1 < 1.0 < 1.0_p1
		if i < len(a.suffixes) {
			x = a.suffixes[i]
		}
		if i < len(b.suffixes) {
			y = b.suffixes[i]
		}
		if c := cmp.Or(cmp.Compare(x[0], y[0]), cmp.Compare(x[1], y[1])); c != 0 {
			return c
		}
	}
	return cmp.Compare(a.rev, b.rev)
}

// CompareUpstream orders two releases by their upstream version only (the -rN revision left out).
func CompareUpstream(a, b Version) int {
	a.rev, b.rev = 0, 0
	return Compare(a, b)
}

// Upstream is the release without its revision ("10.2_p1" of "10.2_p1-r1").
func Upstream(s string) string {
	if i := strings.LastIndex(s, "-r"); i > 0 {
		return s[:i]
	}
	return s
}

// Valid says whether s is an apk release Parse reads.
func Valid(s string) bool {
	_, ok := Parse(s)
	return ok
}
