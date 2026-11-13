package findings

import (
	"cmp"
	"slices"
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
// distribution revisions are ignored (they parse as a plain release). num2 is the
// second number of a release qualifier: Junos "R2-S1" (service release 1 of R2) and
// Ivanti "R2.4" order after "R2" (D-500).
type qual struct {
	class int
	sub   int
	num   uint64
	num2  uint64
}

type version struct {
	rel  []uint64
	q    qual
	tail string // ignored for ordering, see compareTail
}

var preRelease = map[string]int{
	"dev": 1, "snapshot": 1, "nightly": 1, "alpha": 2, "beta": 3, "pre": 4, "preview": 4, "rc": 5, "cr": 5,
}

var postRelease = map[string]bool{
	"p": true, "pl": true, "patch": true, "sp": true, "update": true, "u": true, "hotfix": true, "hf": true, "h": true, "rev": true, "r": true,
}

var releaseWord = map[string]bool{
	"ga": true, "final": true, "release": true, "stable": true, "lts": true, "esr": true, "rtm": true,
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isLower(b byte) bool { return b >= 'a' && b <= 'z' }

const sepChars = " -_+~."

// parseVersion understands real vendor strings: "7.2.4", "v2.4.57", "1.1.1w",
// "7.0.0 build 1234", "10.0.19045.3693", "DSM 7.1.1-42962", "8.9p1", "1.0-rc1",
// PAN-OS "10.2.9-h1", Junos "22.4R2-S1", Ivanti "22.7R2.4".
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
	q, tail, ok := parseQual(s[i:])
	if !ok {
		return version{}, false
	}
	return version{rel: rel, q: q, tail: tail}, true
}

// parseQual reads what follows the numeric release. It returns the ordering
// qualifier and the ignored tail (build number, distro revision, metadata), kept
// so that range decisions at a boundary can tell "7.0.0 build 1234" from "7.0.0".
func parseQual(tail string) (qual, string, bool) {
	rest := strings.TrimLeft(tail, sepChars)
	if rest == "" {
		return qual{}, "", true
	}
	var sep byte
	if rest != tail {
		sep = tail[0]
	}
	if sep == '+' || isDigit(rest[0]) { // build metadata, distro revision, build number
		return qual{}, rest, true
	}
	k := 0
	for k < len(rest) && isLower(rest[k]) {
		k++
	}
	if k == 0 {
		return qual{}, "", false
	}
	w, after := rest[:k], rest[k:]
	// num reads the number of a qualifier ("rc1", "beta.2", "sp 3"); no number is 0.
	num := func() (uint64, string, bool) {
		s := strings.TrimLeft(after, ".-_ ")
		j := 0
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == 0 {
			return 0, after, true
		}
		if j > maxSegDigits {
			return 0, "", false
		}
		n, err := strconv.ParseUint(s[:j], 10, 64)
		return n, s[j:], err == nil
	}
	withTail := func(q qual, left string, ok bool) (qual, string, bool) {
		t, tok := tailOK(left)
		return q, t, ok && tok
	}
	switch {
	case len(w) == 1 && (w == "a" || w == "b") && after != "" && isDigit(after[0]):
		n, left, ok := num()
		rank := 2 // alpha
		if w == "b" {
			rank = 3
		}
		return withTail(qual{class: -1, sub: rank, num: n}, left, ok)
	case preRelease[w] != 0:
		n, left, ok := num()
		return withTail(qual{class: -1, sub: preRelease[w], num: n}, left, ok)
	case len(w) == 1 && sep == 0 && after == "": // OpenSSL style 1.1.1w
		return qual{class: 1, sub: 1, num: uint64(w[0]-'a') + 1}, "", true
	case postRelease[w]:
		n, left, ok := num()
		q := qual{class: 1, num: n}
		if w == "r" && ok && n > 0 { // Junos "R2-S1" (service release), Ivanti "R2.4": a second number
			q.num2, left, ok = releaseSub(left)
		}
		return withTail(q, left, ok)
	case w == "build" || releaseWord[w]:
		t, ok := tailOK(after)
		return qual{}, w + t, ok
	}
	return qual{}, "", false
}

// releaseSub reads the second number of an "R" release: "-S1" or "S1" (Junos service release) or ".4" (Ivanti).
// Anything else is left as it was, with 0.
func releaseSub(left string) (uint64, string, bool) {
	s := strings.TrimPrefix(left, "-")
	if strings.HasPrefix(s, "s") && len(s) > 1 && isDigit(s[1]) {
		s = s[1:]
	} else if strings.HasPrefix(left, ".") && len(left) > 1 && isDigit(left[1]) {
		s = left[1:]
	} else {
		return 0, left, true
	}
	j := 0
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j > maxSegDigits {
		return 0, "", false
	}
	n, err := strconv.ParseUint(s[:j], 10, 64)
	return n, s[j:], err == nil
}

// tailOK accepts what may follow a qualifier: nothing, build metadata, a number
// (build or revision) or the word "build". It returns the normalised tail.
func tailOK(t string) (string, bool) {
	plus := strings.HasPrefix(t, "+")
	t = strings.TrimLeft(t, sepChars)
	return t, plus || t == "" || isDigit(t[0]) || strings.HasPrefix(t, "build")
}

// buildOf splits an ignored tail into its leading word ("", "build") and its
// numbers: "48.47" gives (""; 48, 47), "build 1234" gives ("build"; 1234). ok is
// false for anything else (words, letters mixed with digits), which is opaque.
func buildOf(t string) (kind string, nums []uint64, ok bool) {
	i := 0
	for i < len(t) && isLower(t[i]) {
		i++
	}
	kind, rest := t[:i], t[i:]
	for {
		rest = strings.TrimLeft(rest, sepChars)
		if rest == "" {
			break
		}
		j := 0
		for j < len(rest) && isDigit(rest[j]) {
			j++
		}
		if j == 0 || j > maxSegDigits || len(nums) >= maxVersionSegs {
			return "", nil, false
		}
		n, err := strconv.ParseUint(rest[:j], 10, 64)
		if err != nil {
			return "", nil, false
		}
		nums = append(nums, n)
		rest = rest[j:]
	}
	return kind, nums, len(nums) > 0
}

// compareTail orders two ignored tails: identical tails are equal; two numeric
// tails of the same shape ("-48.47" and "-49.15", "build 1234" and "build 1300",
// "_351" and "_361", "-10-12" and "-10-13") are compared number by number. Any
// other pair (one side empty, different shapes, opaque text) is not decidable.
func compareTail(a, b string) (int, bool) {
	if a == b {
		return 0, true
	}
	ka, na, okA := buildOf(a)
	kb, nb, okB := buildOf(b)
	if !okA || !okB || ka != kb || len(na) != len(nb) {
		return 0, false
	}
	return slices.Compare(na, nb), true
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
	if c := cmp.Compare(v.q.num, o.q.num); c != 0 {
		return c
	}
	return cmp.Compare(v.q.num2, o.q.num2)
}

// CompareVersions orders two vendor version strings (-1, 0, 1). ok is false when either
// cannot be parsed; then order is meaningless. Build metadata and distro revisions
// are ignored for this order, so "7.0.0 build 1234" equals "7.0.0" and "7.2" equals
// "7.2.0". Range decisions use a stricter comparison (VersionRange.Contains).
func CompareVersions(a, b string) (order int, ok bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	return va.compare(vb), true
}

// compareBound is CompareVersions for range decisions: when the releases and
// qualifiers are equal, the ignored tails decide, and tails that cannot be
// compared make the answer undecidable instead of "equal".
func compareBound(a, b string) (int, bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	if c := va.compare(vb); c != 0 {
		return c, true
	}
	return compareTail(va.tail, vb.tail)
}

// buildOfRelease reports whether v is a build of exactly the release named by bound: the same release and
// qualifier, v with a build tail and bound with none ("13.1-49.13" and "13.1", "7.0.0 build 1234" and "7.0.0").
// Only a lower inclusive bound may use it: whether such a build is before an upper bound "13.1" is unclear.
func buildOfRelease(v, bound string) bool {
	vv, okV := parseVersion(v)
	vb, okB := parseVersion(bound)
	return okV && okB && vv.compare(vb) == 0 && vb.tail == "" && vv.tail != ""
}

// isPlaceholder reports whether s is an all-zero version ("0", "0.0.0"): agents
// and appliances use it for "unknown", so it is never evidence of a real version.
func isPlaceholder(s string) bool {
	v, ok := parseVersion(s)
	if !ok {
		return false
	}
	for _, n := range v.rel {
		if n != 0 {
			return false
		}
	}
	return true
}

// relString renders the numeric release of a parsed version ("8.9").
func relString(v version) string {
	parts := make([]string, len(v.rel))
	for i, n := range v.rel {
		parts[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(parts, ".")
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
// bound is violated but one cannot be compared, the answer is Unknown. Versions
// that differ only in an ignored build tail, and placeholder versions ("0"), are
// Unknown at a bound. With no bounds every version is inside, known or not.
func (r VersionRange) Contains(v string) Tri {
	if r.IsZero() {
		return Yes
	}
	if isPlaceholder(v) {
		return Unknown
	}
	unknown := false
	check := func(bound string, ok func(c int) bool) bool {
		if bound == "" {
			return true
		}
		c, known := compareBound(v, bound)
		if !known {
			unknown = true
			return true
		}
		return ok(c)
	}
	if r.StartIncl != "" && buildOfRelease(v, r.StartIncl) {
		r.StartIncl = "" // "13.1-49.13" is a build of the 13.1 release, so it is "13.1 or later" (D-500)
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
