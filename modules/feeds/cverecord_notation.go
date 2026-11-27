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
//     (withoutProduct). Another name (another package of the same advisory, a marketing name) is not dropped, nor a name before a
//     range written with a hyphen in a bound ("lessThan": "Tika 1.0-1.23").
//   - A range written with a hyphen in "version" ("1.0-1.23", "14.1.0-14.1.0.5", after the product's name too): from the first
//     release through the second (hyphenRead), as CISA's ADP rewrites such entries in its enrichment ("4.0.0-4.2.7" -> version 4.0.0,
//     lessThanOrEqual 4.2.7) and NVD's configurations read them. A package revision or build after the hyphen stays one release.
//   - A list after lessThan or lessThanOrEqual with one fixed (or last affected) release per release train ("1.20.4,2.0.2,2.1.2"):
//     one row per train (trainEnds), only when every item is a plain dotted number of the same length and the trains go strictly up as
//     written (or strictly down, in a list of three or more).
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
// reads is the product's version scheme (entryRows).
func recordNotation(a cnaAffected, v cnaVersion, reads func(start, end string, incl bool) bool) (out []notedVersion, ok bool) {
	n := notedVersion{start: withoutProduct(strings.TrimSpace(v.Version), a)}
	switch {
	case v.LessThan != nil:
		n.end, n.bounded = withoutProduct(strings.TrimSpace(*v.LessThan), a), true
	case v.LessThanOrEqual != nil:
		n.end, n.incl, n.bounded = withoutProduct(strings.TrimSpace(*v.LessThanOrEqual), a), true, true
	default:
		switch kind, from, to := hyphenRead(withoutName(strings.TrimSpace(v.Version), a), v.VersionType, reads); kind {
		case hyphenRange:
			return []notedVersion{{start: from, end: to, incl: true, bounded: true}}, true
		case hyphenOne:
			return []notedVersion{{start: from}}, true
		case hyphenUnsure:
			return nil, false
		}
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
	return cnaVersionOK(s) && d != "" && d[0] >= '0' && d[0] <= '9' && (!commitRE.MatchString(d) || !strings.ContainsAny(d, "abcdef"))
}

// withoutProduct is s without the entry's product name in front (withoutName), unless what follows the name is a range written with a
// hyphen ("Tika 1.0-1.23"): a bound or a fixed release cannot be a range, so it stays as written (unusable). recordNotation reads
// such a range in "version" itself.
func withoutProduct(s string, a cnaAffected) string {
	rest := withoutName(s, a)
	if kind, _, _ := hyphenRead(rest, "", nil); rest != s && kind != hyphenNone {
		return s
	}
	return rest
}

// withoutName is s without the entry's product name in front ("openssl-1.1.0" of product OpenSSL is "1.1.0"): the name ends where a
// comparator or a dotted version begins after a blank, hyphen or underscore, and it is the entry's product, its vendor and product,
// or an npm package whose name after its scope is the product. Anything else is returned as written.
func withoutName(s string, a cnaAffected) string {
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

// hyphenRE is two releases joined by one hyphen: dotted numbers, each may have a "v" in front, the second may end in a letter release
// ("1.1.0-1.1.0g").
var hyphenRE = regexp.MustCompile(`^([vV]?)([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})-([vV]?)([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})([a-z]{0,2})$`)

// How hyphenRead reads a version written with a hyphen.
type hyphenKind int

const (
	hyphenNone   hyphenKind = iota // no range: another text, or one release with a package revision or build after the hyphen
	hyphenRange                    // the first release through the second
	hyphenOne                      // the same release written twice ("6.2.0-6.2.0"): that release
	hyphenUnsure                   // a range or a release with a revision; read either way it may be narrower than the record means
)

// revisionTypes are the versionType words of package schemes in which a hyphen starts the package's revision ("1.0-1.5": release 1.5
// of 1.0).
var revisionTypes = map[string]bool{"rpm": true, "deb": true, "dpkg": true, "debian": true}

// hyphenRead reads a version "A-B" of an entry's "version" field (no lessThan), A and B dotted numbers. CVE JSON 5 has no range
// notation inside "version" (a range is version + lessThan or lessThanOrEqual), yet CNAs write one there ("1.0-1.23",
// "14.1.0-14.1.0.5", "3.9.0-5.4.1"), and the same notation writes a release with its package revision or build ("0.6.9-5",
// "9.3.1-2.1", "3.1.1-190328", "4.15.0-38.41"). Read from the record's shape only:
//   - one release: a versionType whose scheme puts a revision after the hyphen (rpm, deb), a version the product's scheme reads as one
//     release (reads: NetScaler's "14.1-73.37"), a single number after the hyphen (a revision or build), B below A ("9.3.1-2.1": a
//     revision is below its own release);
//   - the same release twice: that release;
//   - a range from A through B: B a letter release of A ("1.1.0-1.1.0g"), or A zero ("0-0.7.0", "0.0-2.2": the earliest version),
//     or B above A with the same first number ("12.0.0-12.1.1", "17.1-17.12"), or B of three numbers or more above A ("1.0.0-6.6.1";
//     a revision of three numbers after a release does not occur in a "version" field of the CVE list);
//   - unsure: B of two numbers with a higher first number ("5.1-19.2" a range, "0.154-3.1" a revision), or A a single number other
//     than 0 ("20-30.05.24"). The entry is then unusable, never read narrower than the record means. A range of releases written with
//     a "v" ("v9.20-v9.26") is kept as written, and entryRows refuses it as any range it cannot order.
func hyphenRead(s, versionType string, reads func(start, end string, incl bool) bool) (kind hyphenKind, from, to string) {
	m := hyphenRE.FindStringSubmatch(s)
	if m == nil || revisionTypes[strings.ToLower(strings.TrimSpace(versionType))] || reads != nil && reads(s, s, true) {
		return hyphenNone, "", ""
	}
	x, okX := leadNums(m[2])
	y, okY := leadNums(m[4])
	if !okX || !okY {
		return hyphenNone, "", ""
	}
	from, to = m[1]+m[2], m[3]+m[4]+m[5]
	c := slices.Compare(padded(x, len(y)), padded(y, len(x)))
	switch {
	case c == 0 && m[5] != "":
		kind = hyphenRange // "1.1.0-1.1.0g": a letter-release branch (entryRows' letterBranch)
	case c == 0:
		kind = hyphenOne
	case c > 0 || len(y) == 1:
		return hyphenNone, "", "" // a revision or build of release A
	case !slices.ContainsFunc(x, func(n int) bool { return n != 0 }):
		kind = hyphenRange // "0.0-2.2": from the first release (CVE JSON 5: "0 denotes the earliest possible version")
	case len(x) == 1:
		return hyphenUnsure, "", ""
	case x[0] == y[0] || len(y) >= 3:
		kind = hyphenRange
	default:
		return hyphenUnsure, "", ""
	}
	return kind, from, to
}

// padded is nums with zeros up to n parts ("1.0" is "1.0.0").
func padded(nums []int, n int) []int {
	for len(nums) < n {
		nums = append(nums, 0)
	}
	return nums
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
// own release, so a train no item names between two listed ones stays affected (the affected side wins). An item that is its train's
// first release ("1.46.0" after "1.45.4") gives no row after lessThan (none of that train is affected) and that one release after
// lessThanOrEqual. Read only when every item is a plain dotted number of the same length, above the entry's start, and the trains go
// strictly up as written, or strictly down in a list of three or more. Two items newest first and a list in no order stay unusable:
// "3.11.4, 3.2.0" can be two products' releases (one product's 3.11.4 and another's 3.2.0), and read per train it would call the
// first product's 3.2.1 to 3.2.x unaffected.
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
	if len(ends) >= 3 && slices.Compare(train(ends[0].nums), train(ends[1].nums)) > 0 {
		slices.Reverse(ends) // newest train first ("1.46.0, 1.45.4, 1.43.9")
	}
	for i := 1; i < len(ends); i++ {
		if slices.Compare(train(ends[i-1].nums), train(ends[i].nums)) >= 0 {
			return nil, false // two items of one train, or a list not in train order: not one product's fix per train
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
		from := nextTrain(ends[i-1].nums)
		if c, _ := cmpLead(from, ends[i].s); c == 0 { // the item is its train's first release ("1.46.0" after "1.45.4")
			if !n.incl {
				continue // fixed from the train's first release: no release of that train is affected
			}
			from = ends[i].s // the train's first release is its last affected one
		}
		out = append(out, notedVersion{start: from, end: ends[i].s, incl: n.incl, bounded: true})
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
