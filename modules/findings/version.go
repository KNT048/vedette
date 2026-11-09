package findings

import (
	"cmp"
	"strconv"
	"strings"
)

const (
	maxVersionLen  = 128
	maxVersionSegs = 16
	maxSegDigits   = 18
)

// Tri is a three-valued answer. The zero value is Unknown: when a version cannot
// be compared the library never guesses "affected" or "not affected".
type Tri uint8

// The three answers of a comparison that may be undecidable.
const (
	Unknown Tri = iota
	No
	Yes
)

func (t Tri) String() string {
	switch t {
	case No:
		return "no"
	case Yes:
		return "yes"
	}
	return "unknown"
}

// qual orders the part of a version after the numeric release: pre-releases
// (class -1) < plain release (0) < post-releases (1). build metadata and
// distribution revisions are ignored (they parse as a plain release).
type qual struct {
	class int
	sub   int
	num   uint64
}

type version struct {
	rel []uint64
	q   qual
}

var preRelease = map[string]int{
	"dev": 1, "snapshot": 1, "nightly": 1, "alpha": 2, "beta": 3, "pre": 4, "preview": 4, "rc": 5, "cr": 5,
}

var postRelease = map[string]bool{
	"p": true, "pl": true, "patch": true, "sp": true, "update": true, "u": true, "hotfix": true, "hf": true, "rev": true, "r": true,
}

var releaseWord = map[string]bool{
	"ga": true, "final": true, "release": true, "stable": true, "lts": true, "esr": true, "rtm": true,
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isLower(b byte) bool { return b >= 'a' && b <= 'z' }

const sepChars = " -_+~."

// parseVersion understands real vendor strings: "7.2.4", "v2.4.57", "1.1.1w",
// "7.0.0 build 1234", "10.0.19045.3693", "DSM 7.1.1-42962", "8.9p1", "1.0-rc1".
// ok is false when the string has no usable numeric release or an unknown
// qualifier, so callers get "unknown" instead of a guess.
func parseVersion(s string) (version, bool) {
	if s == "" || len(s) > maxVersionLen {
		return version{}, false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	i := 0
	for i < len(s) && !isDigit(s[i]) {
		i++
	}
	if i == len(s) {
		return version{}, false
	}
	if pre := s[:i]; pre != "" && pre != "v" {
		last := pre[len(pre)-1]
		if last != ' ' && last != '-' {
			return version{}, false
		}
		for j := 0; j < len(pre); j++ {
			if !isLower(pre[j]) && pre[j] != ' ' && pre[j] != '_' && pre[j] != '-' {
				return version{}, false
			}
		}
	}
	var rel []uint64
	for {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j-i > maxSegDigits || len(rel) >= maxVersionSegs {
			return version{}, false
		}
		n, err := strconv.ParseUint(s[i:j], 10, 64)
		if err != nil {
			return version{}, false
		}
		rel = append(rel, n)
		i = j
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			i++
			continue
		}
		break
	}
	q, ok := parseQual(s[i:])
	if !ok {
		return version{}, false
	}
	return version{rel: rel, q: q}, true
}

func parseQual(tail string) (qual, bool) {
	rest := strings.TrimLeft(tail, sepChars)
	if rest == "" {
		return qual{}, true
	}
	var sep byte
	if rest != tail {
		sep = tail[0]
	}
	if sep == '+' || isDigit(rest[0]) { // build metadata, distro revision, build number
		return qual{}, true
	}
	k := 0
	for k < len(rest) && isLower(rest[k]) {
		k++
	}
	if k == 0 {
		return qual{}, false
	}
	w, after := rest[:k], rest[k:]
	num := func() (uint64, string, bool) {
		j := 0
		for j < len(after) && isDigit(after[j]) {
			j++
		}
		if j == 0 {
			return 0, after, true
		}
		if j > maxSegDigits {
			return 0, "", false
		}
		n, err := strconv.ParseUint(after[:j], 10, 64)
		return n, after[j:], err == nil
	}
	switch {
	case len(w) == 1 && (w == "a" || w == "b") && after != "" && isDigit(after[0]):
		n, left, ok := num()
		rank := 2 // alpha
		if w == "b" {
			rank = 3
		}
		return qual{-1, rank, n}, ok && tailOK(left)
	case preRelease[w] != 0:
		n, left, ok := num()
		return qual{-1, preRelease[w], n}, ok && tailOK(left)
	case len(w) == 1 && sep == 0 && after == "": // OpenSSL style 1.1.1w
		return qual{1, 1, uint64(w[0]-'a') + 1}, true
	case postRelease[w]:
		n, left, ok := num()
		return qual{1, 0, n}, ok && tailOK(left)
	case w == "build":
		return qual{}, tailOK(after)
	case releaseWord[w]:
		return qual{}, tailOK(after)
	}
	return qual{}, false
}

// tailOK accepts what may follow a qualifier: nothing, build metadata, a number
// (build or revision) or the word "build".
func tailOK(t string) bool {
	if strings.HasPrefix(t, "+") {
		return true
	}
	t = strings.TrimLeft(t, sepChars)
	return t == "" || isDigit(t[0]) || strings.HasPrefix(t, "build")
}

func (v version) compare(o version) int {
	n := max(len(v.rel), len(o.rel))
	for i := 0; i < n; i++ {
		var a, b uint64
		if i < len(v.rel) {
			a = v.rel[i]
		}
		if i < len(o.rel) {
			b = o.rel[i]
		}
		if c := cmp.Compare(a, b); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(v.q.class, o.q.class); c != 0 {
		return c
	}
	if c := cmp.Compare(v.q.sub, o.q.sub); c != 0 {
		return c
	}
	return cmp.Compare(v.q.num, o.q.num)
}

// CompareVersions orders two vendor version strings (-1, 0, 1). ok is false when either
// cannot be parsed; then order is meaningless. Build metadata and distro revisions
// are ignored, so "7.0.0 build 1234" equals "7.0.0" and "7.2" equals "7.2.0".
func CompareVersions(a, b string) (order int, ok bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	return va.compare(vb), true
}

// VersionRange is an NVD cpeMatch range. Empty bounds are absent; no bounds at
// all means every version.
type VersionRange struct {
	StartIncl, StartExcl, EndIncl, EndExcl string
}

// IsZero reports whether the range has no bounds (all versions).
func (r VersionRange) IsZero() bool { return r == VersionRange{} }

// Contains says whether version v lies inside the range. A bound that is
// violated for sure gives No even if another bound cannot be compared; if no
// bound is violated but one cannot be compared, the answer is Unknown.
func (r VersionRange) Contains(v string) Tri {
	if r.IsZero() {
		return Yes
	}
	unknown := false
	check := func(bound string, ok func(c int) bool) bool {
		if bound == "" {
			return true
		}
		c, known := CompareVersions(v, bound)
		if !known {
			unknown = true
			return true
		}
		return ok(c)
	}
	if !check(r.StartIncl, func(c int) bool { return c >= 0 }) ||
		!check(r.StartExcl, func(c int) bool { return c > 0 }) ||
		!check(r.EndIncl, func(c int) bool { return c <= 0 }) ||
		!check(r.EndExcl, func(c int) bool { return c < 0 }) {
		return No
	}
	if unknown {
		return Unknown
	}
	return Yes
}

// String describes the range in plain English for evidence text.
func (r VersionRange) String() string {
	if r.IsZero() {
		return "all versions"
	}
	var parts []string
	if r.StartIncl != "" {
		parts = append(parts, r.StartIncl+" or later")
	}
	if r.StartExcl != "" {
		parts = append(parts, "later than "+r.StartExcl)
	}
	if r.EndIncl != "" {
		parts = append(parts, "up to "+r.EndIncl)
	}
	if r.EndExcl != "" {
		parts = append(parts, "before "+r.EndExcl)
	}
	if r.StartIncl != "" && r.StartIncl == r.EndIncl && len(parts) == 2 {
		return "version " + r.StartIncl
	}
	return strings.Join(parts, ", ")
}
