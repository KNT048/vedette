package findings

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Record shapes. A CVE's list of rows often carries one row that does not compare with the version beside rows that decide it: a row
// for no version at all (NA), NVD's legacy "and earlier" marker, a release named by a word, a bound in a notation the comparison does
// not read. Each rule below reads what the row's shape says (CPE 2.3 name matching, NISTIR 7695/7696; CVE JSON 5 version ranges; OSV's
// introduced/fixed), never the product it names, so that such a row neither makes the whole CVE undecided nor drops a row that could
// say "affected". A bound in a notation the comparison does not read stays Unknown: one release may carry two numberings (a network
// OS whose 3.x releases are its older 15.x ones), so only a row inside one other branch is set aside (otherBranch).

// naVersionApart says application row c is about no version (its version is NA, "-") while the install has a version and the same
// list versions the product elsewhere (a row of the same product with a range or a version): CPE name matching (NISTIR 7696) makes NA
// and a value DISJOINT, so the row is not about this install. Alone, an NA row may be NVD's way to name a product whose release is in its
// name ("suite_2016:-") or that has no release numbers (a subscription build), so it stays Unknown. Only applications: NVD writes "-" on an
// operating system or firmware ("o") for a device's firmware of no stated version, which may be any of them. An NA row that names a
// build (pinsBuild: an edition, a system, an architecture) is apart only beside a versioned row of that same build (sameBuild): "-" with
// "subscription", or with "macos" beside a range for "android", is how NVD lists that build with no version, so it stays.
func naVersionApart(c CPE, ver string, rows []Affected) bool {
	if c.Part.Kind != Value || c.Part.Value != "a" || c.Version.Kind != NA || !versionKnown(ver) {
		return false
	}
	return slices.ContainsFunc(rows, func(o Affected) bool {
		oc, err := o.cpe()
		return err == nil && oc.Version.Kind != NA && sameProduct(c, oc) && (!pinsBuild(c) || sameBuild(c, oc)) && versionEvidence(o)
	})
}

// buildAttrs are the CPE attributes that name a build of a product rather than a release (fields: edition, language, sw_edition,
// target_sw, target_hw, other); the update belongs to the release.
const buildAttrs = 5

// pinsBuild says c names a build: an attribute of buildAttrs is not ANY.
func pinsBuild(c CPE) bool {
	f := c.fields()
	return slices.ContainsFunc(f[buildAttrs:], func(a *Attr) bool { return a.Kind != Any })
}

// sameBuild says two CPEs pin the same build attributes (buildAttrs): they name the same build of the product.
func sameBuild(a, b CPE) bool {
	fa, fb := a.fields(), b.fields()
	for i := buildAttrs; i < len(fa); i++ {
		if *fa[i] != *fb[i] {
			return false
		}
	}
	return true
}

// earlierMarker says row af (version ANY, no range, nothing pinned) only repeats NVD's legacy "and earlier": the same list has a row of
// the same product that ends and has no start ("5.14 and earlier": a bare "*" beside "up to 5.14"). Such a pair never means "every
// version": the bounded row would then say nothing. The bounded row decides; a range that starts somewhere does not make a bare row a
// marker (it may be "every version" beside a later line's range), nor does one pinned to a build (a system, an edition): the bare row
// still speaks for the other builds. A record row that only says "affected" (AffectedOnly) is neither.
func earlierMarker(c CPE, af Affected, rows []Affected) bool {
	if af.AffectedOnly || !af.Range.IsZero() || !everyVersion(c) {
		return false
	}
	for _, o := range rows {
		r := o.Range
		if o.AffectedOnly || !endBound(r) || r.StartIncl+r.StartExcl != "" && !isPlaceholder(r.StartIncl+r.StartExcl) {
			continue
		}
		if oc, err := o.cpe(); err == nil && sameProduct(c, oc) && sameBuild(c, oc) { // a range of one build leaves the others' bare row
			return true
		}
	}
	return false
}

// sameProduct says two CPEs name the same part, vendor and product.
func sameProduct(a, b CPE) bool {
	return a.Part == b.Part && a.Vendor == b.Vendor && a.Product == b.Product
}

// wordRelease says row c with range r is one release named by a word with no digit ("preview_release", "beta") while ver is a
// numbered version: no numbered release is that word, so the row cannot hold ver. decide sets it aside, and only a fix ver is past
// may decide beside it.
func wordRelease(c CPE, r VersionRange, ver string) bool {
	if !r.IsZero() || !versionKnown(ver) {
		return false
	}
	lit, ok := c.Version.Literal()
	return ok && lit != "" && !strings.ContainsAny(lit, "0123456789")
}

// pastEnd says ver is after the end of range r: at or after an excluded end, after an included one. False with no end or when the
// end does not compare.
func pastEnd(r VersionRange, ver string) bool {
	end, incl := r.EndExcl, false
	if end == "" {
		end, incl = r.EndIncl, true
	}
	if end == "" {
		return false
	}
	c, ok := compareBound(ver, end)
	return ok && (c > 0 || c == 0 && !incl)
}

// pastRecordFix says the version is after a fix a partial CVE record states, on a release train the record covers (OSV: introduced <= v
// < fixed, whoever the CNA is). A partial list (a CNA that lists what it tested) may skip trains, so a version outside every row proves
// nothing on its own; it does when the version is past a fix the record states on a train it covers.
//
// A fix is an excluded end (CVE JSON 5 lessThan, OSV fixed). An included end (lessThanOrEqual, "through") names the last version the CNA
// knew affected, often the latest release when it wrote the record: a later version is not stated fixed, so it proves nothing. The
// version must be
//   - past the fix of a row that starts on the version's own train (the record speaks for that train: "2.56.0-rc0" before "2.56.1"
//     on 2.56.1), or
//   - past the fix of a row from version 0 or with no start ("before 7.2.9" on 7.4.7), and below the start of no row: a version
//     between the trains the record lists (2.53.0 beside rows for 2.50 and 2.56) stays undecided, since the record may have skipped
//     its train, or
//   - at or past a fix the record states above its rows (LineFix: a lone "unaffected" version above every affected row of the entry,
//     OSV's fixed) on that fix's own release line (its first number: "7.25.2" past "7.24.0", not "8.0.1"), and below the start of no
//     row. A version between the last one listed affected and the fix stays undecided: the record says nothing about it.
//
// A bound that does not compare, or an exact row above the version, keeps the CVE undecided.
func pastRecordFix(in swInfo, v Vuln, key []identity) bool {
	if !versionKnown(in.ver) {
		return false
	}
	train, fromZero, lineFixed, gap := false, false, false, false
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || af.AffectedOnly {
			continue
		}
		if own, _, _ := entryFor(c, in, key); !own {
			continue
		}
		if otherSystem(in, c) {
			continue // that system's build: its fix says nothing about the build the device runs (systemReadings decides such rows)
		}
		r := af.Range
		if r.IsZero() {
			lit, ok := c.Version.Literal()
			if !ok {
				continue // every version, or no version: the rows' Yes or Unknown already decided
			}
			r = VersionRange{StartIncl: lit, EndIncl: lit}
		}
		start := cmp.Or(r.StartIncl, r.StartExcl)
		if start != "" && !isPlaceholder(start) {
			o, ok := compareBound(in.ver, start)
			if !ok {
				return false
			}
			gap = gap || o < 0
		}
		if af.LineFix != "" && sameLine(in.ver, af.LineFix) {
			if o, ok := compareBound(in.ver, af.LineFix); ok && o >= 0 {
				lineFixed = true
			}
		}
		if r.EndExcl == "" || !pastEnd(r, in.ver) {
			continue // no fix stated (an inclusive end, "through 7.24.5", is the last version known affected; an exact row is one release), or not past it
		}
		switch {
		case start == "" || isPlaceholder(start):
			fromZero = true
		case sameTrain(in.ver, start, cmp.Or(r.EndExcl, r.EndIncl)):
			train = true
		}
	}
	return train || (fromZero || lineFixed) && !gap
}

// otherSystem says row c is limited to an operating system (target_sw in osFamilies) the device's own agent reports another one than,
// and whose builds do not run on it (platformsMeet). An unknown device system, a row of every system or a word outside the vocabulary is
// not another system.
func otherSystem(in swInfo, c CPE) bool {
	lit, ok := c.TargetSW.Literal()
	if !ok || c.TargetSW.Kind != Value || in.install.platform == "" {
		return false
	}
	w := osFamilies[strings.ToLower(lit)]
	return w != "" && !platformsMeet(in.install.platform, w)
}

// sameLine says two versions start with the same number (their release line: "7" of "7.25.2" and "7.24.0").
func sameLine(a, b string) bool {
	x, y := leadNumber(a), leadNumber(b)
	return x != "" && x == y
}

// leadNumber is the leading digits of a version without leading zeros ("7" of "7.25.2"), "" when it starts with none.
func leadNumber(s string) string {
	s = strings.TrimSpace(s)
	j := 0
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j == 0 {
		return ""
	}
	return cmp.Or(strings.TrimLeft(s[:j], "0"), "0")
}

// sameTrain says ver, the start and the end of a range share their first two numbers (major.minor): the range is a fix of ver's train.
func sameTrain(ver, start, end string) bool {
	v, s, e := majorMinor(ver), majorMinor(start), majorMinor(end)
	return v != nil && s != nil && e != nil && *v == *s && *v == *e
}

// majorMinor is the first two numbers of a version that starts with them ("2.56" of "2.56.0-rc0"), nil when it does not start with two
// dotted numbers (an epoch "1:2.3", a word, a single number).
func majorMinor(s string) *[2]uint64 {
	var out [2]uint64
	rest := strings.TrimSpace(s)
	for i := range out {
		j := 0
		for j < len(rest) && isDigit(rest[j]) {
			j++
		}
		if j == 0 || j > 9 {
			return nil
		}
		n, _ := strconv.ParseUint(rest[:j], 10, 64)
		out[i], rest = n, rest[j:]
		if i == 0 {
			if !strings.HasPrefix(rest, ".") {
				return nil
			}
			rest = rest[1:]
		}
	}
	return &out
}

// exactRow is the release a row names when it is one release: an NVD configuration with no range and a version (and no update, which
// the generic order does not read: "1.8.0" with "update471" is not release 1.8.0), or a record row from a release to the same release
// included. upd says the row has an update the release cannot be told without; ok is false for any other row.
func exactRow(af Affected) (rel string, upd, ok bool) {
	r := af.Range
	if r.StartIncl != "" && r.StartIncl == r.EndIncl && r.StartExcl == "" && r.EndExcl == "" {
		return r.StartIncl, false, true
	}
	if !r.IsZero() {
		return "", false, false
	}
	c, err := af.cpe()
	if err != nil {
		return "", false, false
	}
	lit, okV := c.Version.Literal()
	if !okV {
		return "", false, false
	}
	return lit, c.Update.Kind != Any && c.Update.Kind != NA, true
}

// exactListProves says the rows of the line's own that said "not affected" (nos) prove it, as trainCleared reads a vendor's rows: a
// row that is one release is read two ways (the exact releases affected, or the newest affected release of its train: every earlier
// release of the train is affected too), and NVD's lists never say which, nor what an unlisted release is. Only the vendor's own
// complete record (VendorList from the product's own CNA: every unlisted version unaffected; NVD's copy of a release it lists is read
// with it) says that. So, by the exact rows of the
// version's own train (major.minor, majorMinor):
//   - one later than the version (or one whose place cannot be told: another notation, an update in the train, unless the version is
//     past a range of its own train that ends at or before it): only the vendor's complete record that also shows it is an exact
//     list (two releases of the train, or a range of it) proves;
//   - only earlier ones: a range of the train that ends at or before the version (a stated fix), the fix the record states above its
//     rows (LineFix) at or before the version, or the vendor's complete record;
//   - none, only rows of other trains: the ranges, as before, or the vendor's complete record.
//
// Rows with no exact release decide as they always did.
func exactListProves(ver string, nos []Affected) bool {
	vt := majorMinor(ver)
	type exact struct {
		rel   string
		place int // 1 earlier than the version, -1 later, -2 not told (another notation, an update in the train), 0 another train
	}
	var exacts []exact
	// the releases the vendor's own complete record lists: NVD's copy of the same release is covered by the record's word
	stated := map[string]bool{}
	for _, af := range nos {
		if rel, _, ok := exactRow(af); ok && af.VendorList && af.VendorCNA {
			stated[strings.ToLower(rel)] = true
		}
	}
	told, ranges, rangeInTrain, endedInTrain, lineFixed := true, false, false, false, false
	for _, af := range nos {
		// the fix the record states above its rows, which bounds its own line only (as pastRecordFix reads it): the version is of
		// that line, at or past it
		if af.LineFix != "" && sameLine(ver, af.LineFix) {
			if c, ok := compareBound(ver, af.LineFix); ok && c >= 0 {
				lineFixed = true
			}
		}
		rel, upd, ok := exactRow(af)
		if !ok {
			ranges = true
			end := cmpOr(af.Range.EndExcl, af.Range.EndIncl)
			for _, b := range []string{af.Range.StartIncl, af.Range.StartExcl, end} {
				if t := majorMinor(b); b != "" && vt != nil && t != nil && *t == *vt {
					rangeInTrain = true
				}
			}
			if t := majorMinor(end); end != "" && vt != nil && t != nil && *t == *vt && pastEnd(af.Range, ver) {
				endedInTrain = true
			}
			continue
		}
		told = told && (af.VendorList && af.VendorCNA || stated[strings.ToLower(rel)])
		e := exact{rel: rel, place: -2}
		switch rt := majorMinor(rel); {
		case vt == nil || rt == nil:
		case *rt != *vt:
			e.place = 0
		case upd: // a release of the train told apart by its update, which the generic order does not read
		default:
			if c, ok := compareBound(ver, rel); ok {
				e.place = map[bool]int{true: 1, false: -1}[c > 0]
			}
		}
		exacts = append(exacts, e)
	}
	if len(exacts) == 0 {
		return true
	}
	later, earlier := false, false
	distinct := map[string]bool{}
	for _, e := range exacts {
		switch e.place {
		case -1:
			later = true
		case -2: // a release whose place is not told: later, unless the version is past a stated fix of its own train
			later = later || !endedInTrain
		case 1:
			earlier = true
		}
		if e.place != 0 {
			distinct[e.rel] = true
		}
	}
	switch {
	case later:
		return told && (len(distinct) >= 2 || rangeInTrain)
	case lineFixed:
		return true
	case earlier:
		return told || endedInTrain
	}
	return told || ranges
}

// laterExactInTrain says a row of own is one release of the version's own train later than it (exactRow, majorMinor): the newest
// affected release of the train, perhaps, which is why a range beside it does not decide the version (exactListProves).
func laterExactInTrain(own []Affected, ver string) bool {
	vt := majorMinor(ver)
	return vt != nil && slices.ContainsFunc(own, func(af Affected) bool {
		rel, upd, ok := exactRow(af)
		rt := majorMinor(rel)
		if !ok || upd || rt == nil || *rt != *vt {
			return false
		}
		c, okC := compareBound(ver, rel)
		return okC && c < 0
	})
}

// unlistedLine says version in.ver, outside every row of v that names the line (decide's "not affected"), is on a release line the rows
// do not speak for while a row starts a later line above it. NVD's configurations and a CNA's version list often name only the release
// lines the vendor still supports ("8.0.0" before "8.0.21", "9.0.0" before "9.0.10"): a line older than one of them that no row covers
// (3.1 beside rows for 2.3, 8.0 and 9.0, or a line below every row) was not evaluated, and being outside the rows says nothing about
// it. Such a version is no proof of "not affected": the CVE stays undecided (ranges_start_at_branch_only), never a finding on that
// basis. The rows speak for the version (false) when
//   - a row is of a list that states what every unlisted version is (VendorList: the product's own CNA, defaultStatus), or the product's
//     own CNA states it in the record whatever rows the match reads (Vuln.UnlistedUnaffected);
//   - the version is past the fix of a row of its own release line: a range that starts at or below it on the line the range's start
//     and end share (at least their first number: "20.0.0" before "20.19.4" is line 20, "8.0.0" before "8.0.21" line 8.0) or on the
//     train its end is on, a range from version 0 or with no start whose end is on the version's line (as the record's other ranges
//     name lines: "153.8.0" past "before 153.3.0" beside a range from 154.0.0), or a fixed release the record states above its rows
//     (LineFix) on its line that it is at or past;
//   - a row is one release of the version's own train: the line is listed (exactListProves reads such a list);
//   - no range starts above it (a line newer than every listed one, past every fix), or the lowest start above it is a release inside
//     a line ("2.4.17" before "2.4.60", "17.12.10"): the record states where the flaw came in, and an older version is before it.
//
// Only the version's numbers are read (CVE JSON 5 versions with lessThan or lessThanOrEqual, NVD's versionStart/versionEnd): a bound
// that does not read as numbers starts no line, and a start that does not compare with the version is set aside.
func unlistedLine(in swInfo, v Vuln, key []identity) bool {
	if !versionKnown(in.ver) || v.RangesFrom == RangesCVEOrg { // a complete CVE record states what every unlisted version is
		return false
	}
	for _, name := range v.UnlistedUnaffected { // the product's own CNA states every version its record does not list unaffected
		if c, err := (Affected{CPE: name}).cpe(); err == nil {
			if o, _, _ := entryFor(c, in, key); o {
				return false
			}
		}
	}
	var own []Affected // the rows that name the line, as decide reads them
	// line is how many leading numbers name a release line in the rows' own ranges: the fewest that the start and end of a range on one
	// line share ("7.6.0" to "7.6.2": 2), else 1 (every range spans lines, as "141.0.0" to "153.4.0" does: major lines)
	line := 0
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || af.Lost {
			continue
		}
		if o, _, _ := entryFor(c, in, key); !o || otherSystem(in, c) || naVersionApart(c, in.ver, v.Affected) || earlierMarker(c, af, v.Affected) {
			continue
		}
		own = append(own, af)
		if start := cmp.Or(af.Range.StartIncl, af.Range.StartExcl); start != "" && !isPlaceholder(start) {
			if _, _, exact := exactRow(af); !exact {
				if n := sharedNumbers(start, cmp.Or(af.Range.EndExcl, af.Range.EndIncl)); n > 0 && (line == 0 || n < line) {
					line = n
				}
			}
		}
	}
	line = max(line, 1)
	var lowest string   // the lowest start of a range above the version
	lowestLine := false // that start is the first release of a line
	for _, af := range own {
		if af.VendorList && !af.AffectedOnly {
			return false
		}
		if af.LineFix != "" && sameLine(in.ver, af.LineFix) {
			if o, ok := compareBound(in.ver, af.LineFix); ok && o >= 0 {
				return false
			}
		}
		if rel, _, ok := exactRow(af); ok {
			if sameTrain(in.ver, rel, rel) {
				return false
			}
			continue // one release of another line: no line statement, above or below
		}
		r := af.Range
		start, end := cmp.Or(r.StartIncl, r.StartExcl), cmp.Or(r.EndExcl, r.EndIncl)
		if start == "" || isPlaceholder(start) {
			if !af.AffectedOnly && pastEnd(r, in.ver) && onEndLine(in.ver, end, line) {
				return false
			}
			continue
		}
		o, ok := compareBound(in.ver, start)
		switch {
		case !ok:
			continue
		case o >= 0: // the range starts at or below the version, which is outside it: past its end
			if !af.AffectedOnly && pastEnd(r, in.ver) && onRowLine(in.ver, start, end, line) {
				return false
			}
			continue
		}
		switch l, ok := compareBound(start, lowest); {
		case lowest == "" || ok && l < 0:
			lowest, lowestLine = start, firstOfLine(start, end)
		case ok && l == 0:
			lowestLine = lowestLine || firstOfLine(start, end)
		}
	}
	return lowest != "" && lowestLine
}

// rowLine is the count of leading numbers that name the release line of a range from start to end: the numbers both share, at least the
// first ("20.0.0" to "20.19.4": 1; "8.0.0" to "8.0.21": 2; "1.0.0" to "2.3.4": 1), the numbers of start alone with no end less its
// last. 0 when start does not read as numbers.
func rowLine(start, end string) (int, []uint64) {
	s, ok := parseVersion(start)
	if !ok || len(s.rel) == 0 {
		return 0, nil
	}
	n := len(s.rel) - 1
	if e, ok := parseVersion(end); ok && end != "" {
		n = 0
		for n < min(len(s.rel), len(e.rel)) && s.rel[n] == e.rel[n] {
			n++
		}
	}
	return max(n, 1), s.rel
}

// firstOfLine says start, the lower bound of a range to end, is the first release of its line (every number after the line's is 0:
// "8.0.0" of 8.0, "20.0.0" of 20, "2.3" of 2.3), not a release inside it where a flaw came in ("2.4.17" to "2.4.60").
func firstOfLine(start, end string) bool {
	n, rel := rowLine(start, end)
	if rel == nil {
		return false
	}
	return !slices.ContainsFunc(rel[min(n, len(rel)):], func(x uint64) bool { return x != 0 })
}

// onRowLine says ver is on a release line the range from start to end speaks for: the line of its start (rowLine: "20.20.0" of
// "20.0.0" to "20.19.4"), or the line its end is on, line numbers long (onEndLine: "7.4.8" of "6.4.0" to "7.4.7" beside ranges of
// major.minor lines, "153.8.0" of "141.0.0" to "153.4.0" beside ranges of major lines).
func onRowLine(ver, start, end string, line int) bool {
	n, rel := rowLine(start, end)
	pv, ok := parseVersion(ver)
	if !ok {
		return false
	}
	if rel != nil && len(pv.rel) >= n && len(rel) >= n && slices.Equal(pv.rel[:n], rel[:n]) {
		return true
	}
	return onEndLine(ver, end, line)
}

// sharedNumbers is how many leading numbers start and end share ("7.6.0" and "7.6.2": 2, "6.4.0" and "7.4.7": 0); 0 when either does
// not read as numbers.
func sharedNumbers(start, end string) int {
	s, okS := parseVersion(start)
	e, okE := parseVersion(end)
	if !okS || !okE || end == "" {
		return 0
	}
	n := 0
	for n < min(len(s.rel), len(e.rel)) && s.rel[n] == e.rel[n] {
		n++
	}
	return n
}

// onEndLine says ver is on the release line of end, the fix a range ends at: they share the first n numbers, or with n 0 every number
// of end but its last, at least the first ("7.4.8" and "7.4.7", "8.0.25" and "8.0.21", "1.5" and "1.2"). A range with no start reads
// with n the line its record's other ranges name ("153.8.0" past "before 153.3.0" beside a range from 154.0.0 to 156.0.0: line 153).
func onEndLine(ver, end string, n int) bool {
	pv, okV := parseVersion(ver)
	pe, okE := parseVersion(end)
	if !okV || !okE || end == "" || len(pe.rel) == 0 {
		return false
	}
	if n == 0 {
		n = max(len(pe.rel)-1, 1)
	}
	return len(pv.rel) >= n && len(pe.rel) >= n && slices.Equal(pv.rel[:n], pe.rel[:n])
}
