package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Readings. A record can leave one input open that the box cannot settle: which build of the product a line is, or whether a list a
// third party wrote names every affected release train or only those it tested. The matcher then stops with an undecided reason,
// even when every reading the record supports gives the same answer for the installed version. everyReading enumerates the readings
// the record itself supports, evaluates the version under each with the comparators decide already uses, and decides only when all
// of them agree; when they disagree the CVE stays undecided with today's reason. A reading is never invented: a version beyond every
// row of a list that states no fix and no unaffected release above its rows stays undecided, and so does a list of exact releases.
//
// What the other scanners do, and what is kept from it: OSV and Grype read a version outside every range as not affected, and Grype
// matches a CPE whose edition the package does not state against every edition NVD lists (any reading that says affected wins).
// Vedette keeps its stricter stance (a partial list proves nothing outside its rows, an unstated edition is a question) and lifts it
// only where every reading agrees, so neither a missed flaw nor a false alarm comes from the choice of reading.

// agreement is a verdict every reading of the record gave, and the sentence that says which readings were read.
type agreement struct {
	t      Tri
	within VersionRange // the range a Yes rests on
	says   string       // "decided under every reading: …", for the evidence
}

// everyReading decides v for the line when decide left it Unknown (or a partial list's No proved nothing) only because the record
// admits more than one reading and all of them give the same verdict. ok is false when a reading disagrees, a row does not compare,
// or no ambiguity this function knows applies. A "not affected" of a CVE on an exploited list is never decided here: only a person
// closes those, so they stay possible.
func everyReading(in swInfo, v Vuln, key []identity, name string) (agreement, bool) {
	if !versionKnown(in.ver) {
		return agreement{}, false
	}
	if a, ok := fixPointsReadings(in, v, key, name); ok {
		return a, true
	}
	if v.listed() {
		return agreement{}, false
	}
	if a, ok := fixTrainReadings(in, v, key, name); ok {
		return a, true
	}
	return agreement{}, false
}

// fixPointsReadings reads a product whose rows state only fixed releases (OSV's fixed with introduced 0): every row of the product
// that names the line ends at an excluded end (CVE JSON 5 lessThan, NVD's versionEndExcluding) and starts nowhere, at 0, or at the first
// release of the end's own release line ("140.0" before "140.12.0": the row says which line the fix is of, not where the flaw came in).
// The rows may pin an edition or channel the box cannot settle for the line, and each value is one reading; as in pinnedInside, NVD's
// NA ("-") is the plain edition, one edition alone says nothing about the editions it leaves out, and a system or architecture pin is
// never read this way (a build no row names would be a reading with no row at all). A version lower than every fixed release the product's rows state, on every line, is affected whichever build
// it is: no reading has a fix at or below it, and each says the flaw is there from the start. A row about another build than the one
// the box derived for the line (judge) is no reading of it; when no row is one, nothing is decided. This only ever says "affected".
func fixPointsReadings(in swInfo, v Vuln, key []identity, name string) (agreement, bool) {
	sib := siblingsOf(&v)
	var fixes []string
	var within *VersionRange
	var builds []string               // the editions the rows that read the line pin, one entry per distinct set
	applies, anyBuild := false, false // anyBuild: a row that reads the line pins no edition
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			continue
		}
		if own, _, _ := entryFor(c, in, key); !own {
			continue
		}
		r := af.Range
		start := cmp.Or(r.StartIncl, r.StartExcl)
		if c.Version.Kind != Any || r.EndExcl == "" || r.EndIncl != "" || r.StartExcl != "" ||
			start != "" && !isPlaceholder(start) && !lineStart(start, r.EndExcl) {
			return agreement{}, false // an exact release, an inclusive end, no end, or a lower bound of its own: not fix points only
		}
		o, ok := compareBound(in.ver, r.EndExcl)
		if !ok || o >= 0 {
			return agreement{}, false // at or past a fix the product states, or a fix that does not compare
		}
		fixes = append(fixes, r.EndExcl)
		j, ok := in.install.judge(c, in.cpe, in.hasCPE, sib)
		if !ok {
			continue // a row about another build than the line's: no reading of it
		}
		applies = true
		vals, liftable := pinnedValues(j, in)
		if !liftable {
			return agreement{}, false // a system or architecture pin: a build no row names is a reading too, with no row at all
		}
		if len(vals) == 0 {
			anyBuild = true
		} else if set := strings.Join(vals, " "); !slices.Contains(builds, set) {
			builds = append(builds, set)
		}
		if start == "" || isPlaceholder(start) {
			if fromZero := (VersionRange{EndExcl: r.EndExcl}); within == nil || widerEnd(fromZero, *within) {
				within = &fromZero
			}
		}
	}
	if !applies || within == nil || !anyBuild && len(builds) < 2 {
		return agreement{}, false // one pinned edition alone says nothing of the editions it leaves out (pinnedInside)
	}
	return agreement{t: Yes, within: *within, says: fmt.Sprintf("decided under every reading: the rows of %s state only fixed releases (%s), "+
		"on every build they name, and version %s is lower than every one of them, so it is affected whichever build it is",
		clean(name), clean(joinVersions(fixes)), clean(in.ver))}, true
}

// lineStart says start is the first release of end's release line: the same first number, nothing but zeros after it ("140.0", "7").
func lineStart(start, end string) bool {
	s := strings.TrimSpace(start)
	lead := leadNumber(s)
	if lead == "" || lead != leadNumber(end) {
		return false
	}
	j := 0
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	return strings.Trim(s[j:], ".0") == ""
}

// joinVersions lists versions once each, in the order given.
func joinVersions(vs []string) string {
	var out []string
	for _, x := range vs {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return strings.Join(out, ", ")
}

// fixTrainReadings reads a CVE record's list that may name only the release trains its writer tested: a partial CVE.org list
// (RangesCVEOrgPartial), or a record's rows read beside NVD's (AffectedOnly) when no NVD row names the line. A version outside every
// row then proves nothing by itself. Two readings of the list:
//   - it names every affected release: the version, outside every row, is not affected;
//   - it names only the trains its writer tested: a row's fixed release (an excluded end, OSV's fixed) is a release of its own train
//     (its first two numbers), so a version of that train at or past it carries the fix, whichever train the row started on.
//
// Both say not affected when the version is on the train of a row's fixed release, at or past it, and no row starts above it on that
// train (a later row of the train would say the fix did not hold). An inclusive end ("through 4.8.2") states the last version known
// affected, not a fix, and a version on another train than every fix stays undecided: the list may have skipped it.
func fixTrainReadings(in swInfo, v Vuln, key []identity, name string) (agreement, bool) {
	var rows []Affected
	listed, beside := recordRows(in, v, key, false), recordRows(in, v, key, true)
	switch {
	case v.RangesFrom == RangesCVEOrgPartial:
		rows = append(listed, beside...) // every row is the record's
	case v.RangesFrom == "" && len(listed) == 0:
		rows = beside // NVD names other products only: the record's rows are the only ones naming the line
	}
	if len(rows) == 0 {
		return agreement{}, false
	}
	vt := majorMinor(in.ver)
	if vt == nil {
		return agreement{}, false
	}
	sib := siblingsOf(&v)
	fix := ""
	for _, af := range rows {
		c, err := af.cpe()
		if err != nil {
			return agreement{}, false
		}
		if t, _ := in.eval(c, af.Range, in.ver, sib); t != No {
			return agreement{}, false // inside a row (decide said so) or a row that does not compare
		}
		r := af.Range
		if r.IsZero() {
			lit, ok := c.Version.Literal()
			if !ok {
				return agreement{}, false // every version, or none: not this shape
			}
			r = VersionRange{StartIncl: lit, EndIncl: lit}
		}
		if start := cmp.Or(r.StartIncl, r.StartExcl); start != "" && !isPlaceholder(start) {
			st := majorMinor(start)
			o, ok := compareBound(in.ver, start)
			if !ok {
				return agreement{}, false
			}
			if st != nil && *st == *vt && o < 0 {
				return agreement{}, false // a row of the version's own train starts above it
			}
		}
		if r.EndExcl == "" {
			continue
		}
		if et := majorMinor(r.EndExcl); et == nil || *et != *vt {
			continue
		}
		if o, ok := compareBound(in.ver, r.EndExcl); ok && o >= 0 && (fix == "" || compareOr(r.EndExcl, fix) > 0) {
			fix = r.EndExcl
		}
	}
	if fix == "" {
		return agreement{}, false
	}
	t := *vt
	return agreement{t: No, says: fmt.Sprintf("version %s of %s is at or past %s, the release the CVE.org record states fixed on its own release "+
		"train (%d.%d); decided under every reading: whether the record lists every affected release or only the trains its writer tested, "+
		"this version carries the fix", clean(in.ver), clean(name), clean(fix), t[0], t[1])}, true
}

// recordRows are the rows of v that name the line itself (entryFor own) and are CVE record rows of the kind asked: read beside NVD's
// (AffectedOnly) when beside is true, the others otherwise.
func recordRows(in swInfo, v Vuln, key []identity, beside bool) []Affected {
	var out []Affected
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA || af.AffectedOnly != beside {
			continue
		}
		if own, _, _ := entryFor(c, in, key); own && !naVersionApart(c, in.ver, v.Affected) {
			out = append(out, af)
		}
	}
	return out
}

// compareOr is compareBound with a bound that does not compare read as equal.
func compareOr(a, b string) int {
	o, _ := compareBound(a, b)
	return o
}
