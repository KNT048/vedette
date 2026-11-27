package feeds

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Record notation: versions a CNA writes inside CVE JSON 5's version fields in a notation of its own. Read into the bounds the fields
// would give (entryRows reads them like any other), so a record in one of these notations is not a whole product lost:
//
//   - GitHub's advisory comparators in "version" ("= 8.9.6.1", "< 8.9.6.4", ">= 2.0, < 2.3.1"): the grammar of GitHub's
//     vulnerable_version_range, "=", "<", "<=", ">", ">=", two clauses joined by a comma (or a blank) are both required (AND); at most
//     one lower and one upper bound, or one "=" alone (comparatorBounds).
//   - The product's name in front of the version ("openssl-1.1.0", "iOS 12.3", "react-router >= 7.0.0, < 7.12.0", an npm package's
//     scoped name "@xmldom/xmldom < 0.8.12" of product "xmldom"): dropped when it is the entry's product, alone or after its vendor
//     (withoutProduct). Another name (another package of the same advisory, a marketing name) is not dropped.
//   - A list after lessThan or lessThanOrEqual with one fixed (or last affected) release per release train ("1.20.4,2.0.2,2.1.2"):
//     one row per train (trainEnds), only when every item is a plain dotted number of the same length and each lies on its own train.
//     A list of one train ("10.0.111, 10.0.400": .NET's records write the SDK's numbers on the runtime) stays unusable: it cannot be
//     a fix per train, and reading it as one would call fixed runtimes affected.
//
// Anything else stays as written: the product is unusable for the generic comparison and kept in vendor rows (statedRows), never
// dropped from the record's other versions.

// notedVersion is one affected version of an entry as entryRows reads it, after recordNotation: start (exclusive when startExcl),
// end (lessThan, or lessThanOrEqual when incl; "*" is no end), bounded when it is a range.
type notedVersion struct {
	start     string
	startExcl bool
	end       string
	incl      bool
	bounded   bool
}

// recordNotation reads one affected version of entry a (the notations above). ok is false when a notation is recognised but does not
// read (the entry is then unusable); a version in no notation is returned as written.
func recordNotation(a cnaAffected, v cnaVersion) (out []notedVersion, ok bool) {
	n := notedVersion{start: withoutProduct(strings.TrimSpace(v.Version), a)}
	switch {
	case v.LessThan != nil:
		n.end, n.bounded = withoutProduct(strings.TrimSpace(*v.LessThan), a), true
	case v.LessThanOrEqual != nil:
		n.end, n.incl, n.bounded = withoutProduct(strings.TrimSpace(*v.LessThanOrEqual), a), true, true
	}
	if strings.ContainsAny(n.start, "<>=") {
		if n.bounded {
			return nil, false // a comparator beside lessThan: which one bounds the range is a guess
		}
		c, ok := comparatorBounds(n.start)
		if !ok {
			return nil, false
		}
		return []notedVersion{c}, true
	}
	if n.bounded && strings.Contains(n.end, ",") {
		if len(v.Changes) > 0 {
			return nil, false
		}
		return trainEnds(n)
	}
	return []notedVersion{n}, true
}

// comparatorRE is one or two clauses of GitHub's advisory grammar: an operator and a version, a comma or blanks between them.
var comparatorRE = regexp.MustCompile(`^(<=|>=|<|>|=)\s*([^\s,<>=|]+)\s*(?:,?\s*(<=|>=|<|>|=)\s*([^\s,<>=|]+)\s*)?$`)

// commitRE is a git commit written as a version (no device reports one).
var commitRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// comparatorBounds reads a version written in GitHub's advisory grammar.
func comparatorBounds(s string) (notedVersion, bool) {
	m := comparatorRE.FindStringSubmatch(s)
	if m == nil {
		return notedVersion{}, false
	}
	var n notedVersion
	lower, upper := false, false
	for i := 1; i+1 < len(m); i += 2 {
		op, ver := m[i], m[i+1]
		if op == "" {
			continue
		}
		if !comparedVersion(ver) {
			return notedVersion{}, false
		}
		switch op {
		case "=":
			if m[3] != "" {
				return notedVersion{}, false // "=" with another clause
			}
			return notedVersion{start: ver}, true
		case ">", ">=":
			if lower {
				return notedVersion{}, false
			}
			lower, n.start, n.startExcl = true, ver, op == ">"
		case "<", "<=":
			if upper {
				return notedVersion{}, false
			}
			upper, n.end, n.incl = true, ver, op == "<="
		}
	}
	if !upper {
		n.end = "*" // ">= 1.2.0": every later version
	}
	n.bounded = true
	return n, true
}

// comparedVersion is a version a comparator may bound: one entryRows compares (cnaVersionOK), starting with a number (a "v" before it
// is part of the version as written), not a git commit or a branch name.
func comparedVersion(s string) bool {
	d := strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	return cnaVersionOK(s) && d != "" && d[0] >= '0' && d[0] <= '9' && !(commitRE.MatchString(d) && strings.ContainsAny(d, "abcdef"))
}

// withoutProduct is s without the entry's product name in front ("openssl-1.1.0" of product OpenSSL is "1.1.0"): the name ends where
// a comparator or a dotted version begins after a blank, hyphen or underscore, and it is the entry's product, its vendor and product,
// or an npm package whose name after its scope is the product. Anything else is returned as written.
func withoutProduct(s string, a cnaAffected) string {
	i := versionStart(s)
	if i <= 0 || !strings.ContainsAny(s[i:], ".<>=") {
		return s // "Office 2016", "Android-11": an edition's name, not a release of the product
	}
	name := strings.TrimRight(s[:i], " -_")
	product := nameKey(a.Product)
	if product == "" {
		return s
	}
	keys := []string{nameKey(name)}
	if scope, pkg, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		keys = append(keys, nameKey(pkg))
	}
	for _, k := range keys {
		if k == product || k == nameKey(a.Vendor)+product {
			return s[i:]
		}
	}
	return s
}

// versionStart is where a version or comparator begins after a name in s: an operator, or a digit ("v" and a digit) right after a
// blank, hyphen or underscore. -1 when there is none.
func versionStart(s string) int {
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '<' || c == '>' || c == '=' {
			return i
		}
		sep := s[i-1] == ' ' || s[i-1] == '-' || s[i-1] == '_'
		digit := c >= '0' && c <= '9' || (c == 'v' || c == 'V') && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'
		if sep && digit {
			return i
		}
	}
	return -1
}

// nameKey is a name compared case- and punctuation-blind ("Notepad-Plus-Plus" is "notepadplusplus").
func nameKey(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// trainEndRE is a plain dotted release, as a per-train list writes each item.
var trainEndRE = regexp.MustCompile(`^[0-9]{1,9}(?:\.[0-9]{1,9}){1,5}$`)

// trainEnds reads a list of releases after lessThan (lessThanOrEqual) as one release per train: the train of "1.20.4" is 1.20. The
// first row runs from the entry's start to the lowest release; each next one from the train after the one before it ("1.21") to its
// own release, so a train no item names between two listed ones stays affected (the affected side wins). Read only when every item
// is a plain dotted number of the same length and each lies on a train of its own, above the entry's start.
func trainEnds(n notedVersion) ([]notedVersion, bool) {
	items := strings.Split(n.end, ",")
	type item struct {
		s    string
		nums []int
	}
	ends := make([]item, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if !trainEndRE.MatchString(it) {
			return nil, false
		}
		nums, ok := leadNums(it)
		if !ok || len(ends) > 0 && len(nums) != len(ends[0].nums) {
			return nil, false
		}
		ends = append(ends, item{it, nums})
	}
	if len(ends) < 2 {
		return nil, false
	}
	slices.SortFunc(ends, func(a, b item) int { return slices.Compare(a.nums, b.nums) })
	for i := 1; i < len(ends); i++ {
		if slices.Compare(train(ends[i-1].nums), train(ends[i].nums)) >= 0 {
			return nil, false // two items of one train: not a fix per train
		}
	}
	start := n.start
	switch strings.ToLower(start) {
	case "", "0", "*", "n/a", "unspecified":
	default:
		if c, ok := cmpLead(start, ends[0].s); !ok || c >= 0 {
			return nil, false
		}
	}
	out := []notedVersion{{start: start, end: ends[0].s, incl: n.incl, bounded: true}}
	for i := 1; i < len(ends); i++ {
		out = append(out, notedVersion{start: nextTrain(ends[i-1].nums), end: ends[i].s, incl: n.incl, bounded: true})
	}
	return out, true
}

// train is the release train of a release's numbers: all but the last.
func train(nums []int) []int { return nums[:len(nums)-1] }

// nextTrain is the train after the one of a release's numbers ("1.20.4" -> "1.21").
func nextTrain(nums []int) string {
	t := slices.Clone(train(nums))
	t[len(t)-1]++
	parts := make([]string, len(t))
	for i, x := range t {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ".")
}
