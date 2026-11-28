package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Readings. A record can leave one input open that the box cannot settle, such as whether a list a third party wrote names every
// affected release train or only those it tested. The matcher then stops with an undecided reason,
// even when every reading the record supports gives the same answer for the installed version. everyReading enumerates the readings
// the record itself supports, evaluates the version under each with the comparators decide already uses, and decides only when all
// of them agree; when they disagree the CVE stays undecided with today's reason. A reading is never invented: a version beyond every
// row of a list that states no fix and no unaffected release above its rows stays undecided, and so does a list of exact releases.
//
// What the other scanners do, and what is kept from it: OSV and Grype read a version outside every range as not affected, and Grype
// matches a CPE whose edition the package does not state against every edition NVD lists (any reading that says affected wins).
// Vedette keeps its stricter stance (a partial list proves nothing outside its rows, an unstated edition is a question) and lifts it
// only where every reading agrees, so neither a missed flaw nor a false alarm comes from the choice of reading. A product whose rows
// state only fixes from the first version on is already decided by the rows (decide, pinnedInside); a fix scoped to a release line
// ("140.0" before "140.12.0") says the line got a fix, not that older lines carried the flaw, so a version below it stays undecided.

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
	if v.listed() {
		return agreement{}, false
	}
	if a, ok := systemReadings(in, v, key, name); ok {
		return a, true
	}
	if !versionKnown(in.ver) {
		return agreement{}, false
	}
	if a, ok := fixTrainReadings(in, v, key, name); ok {
		return a, true
	}
	return agreement{}, false
}

// fixTrainReadings reads a CVE record's list that may name only the release trains its writer tested: a partial CVE.org list
// (RangesCVEOrgPartial), or a record's rows read beside NVD's (AffectedOnly) when no NVD row names the line. A version outside every
// row then proves nothing by itself. Two readings of the list:
//   - it names every affected release: the version, outside every row, is not affected;
//   - it names only the trains its writer tested: a row's fixed release (an excluded end, OSV's fixed) is a release of its own train
//     (its first two numbers), so a version of that train at or past it carries the fix, whichever train the row started on.
//
// Both say not affected when the version is on the train of a row's fixed release, at or past it, no row starts above it on that
// train and no row lists a release of that train at or after the fix as affected (a later row of the train would say the fix did not
// hold). An inclusive end ("through 4.8.2") states the last version known affected, not a fix, and a version on another train than
// every fix stays undecided: the list may have skipped it.
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
	var through []string // inclusive ends (the last release known affected) on the version's train
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
		if r.EndIncl != "" {
			if et := majorMinor(r.EndIncl); et != nil && *et == *vt {
				through = append(through, r.EndIncl)
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
	for _, last := range through {
		if compareOr(last, fix) >= 0 {
			return agreement{}, false // a release of the train at or after the fix is listed affected: the fix did not hold, no later one is stated
		}
	}
	t := *vt
	return agreement{t: No, says: fmt.Sprintf("version %s of %s is at or past %s, the release the CVE.org record states fixed on its own release "+
		"train (%d.%d); decided under every reading: whether the record lists every affected release or only the trains its writer tested, "+
		"this version carries the fix", clean(in.ver), clean(name), clean(fix), t[0], t[1])}, true
}

// systemReadings reads a list that is not complete (a partial CVE.org list, or a record's rows read beside NVD's) whose every row of the
// line's own product is limited to an operating system (CPE target_sw; the record's platforms are stored as target_sw): a version
// outside such a list proves nothing, but a system does, when the statement comes from who knows the product's builds. Whether the list
// names every affected version or only some, it names the systems the product is affected on, and none of them is one the device's own
// agent reports (installOf: the agent's OS, never a scan's guess). The rows count when the vendor's own CNA wrote them
// (Affected.VendorCNA), or when NVD's own analysis of the CVE agrees: it has rows, and every one of them is limited to a system the
// device does not run either. A third party's record alone names the system it tested on ("as demonstrated on Linux"), so it decides
// nothing.
//
// Both sides must read in the target_sw vocabulary (osFamilies) and not meet (platformsMeet). A row for every system, for the build of
// no named system, for a host application or for a word outside the vocabulary, a row only the exploited list's key reaches, one that
// may name the line, the line's own CPE stating a system, a vendor's own rows (Schemed, Lines) or a device whose system is not known
// keep the CVE possible.
func systemReadings(in swInfo, v Vuln, key []identity, name string) (agreement, bool) {
	have := in.install.platform
	if have == "" || in.install.platformWhy == "" || in.hasCPE && in.cpe.TargetSW.Kind != Any || len(v.Schemed) > 0 || len(v.Lines) > 0 {
		return agreement{}, false
	}
	switch {
	case v.RangesFrom == RangesCVEOrgPartial:
	case v.RangesFrom == "" && len(recordRows(in, v, key, false)) == 0:
	default:
		return agreement{}, false // a complete list, or NVD's own rows of the line: decide already read their systems
	}
	// other is the family name of the system row c is limited to when the device does not run it, "" otherwise
	other := func(c CPE) string {
		lit, ok := c.TargetSW.Literal()
		if !ok || c.TargetSW.Kind != Value {
			return ""
		}
		w := osFamilies[strings.ToLower(lit)]
		if w == "" || platformsMeet(have, w) {
			return ""
		}
		return osFamilyNames[w]
	}
	var systems []string
	third := false               // a row of the line is a third party's
	nvdRows, nvdOther := 0, true // NVD's own rows of the CVE, and whether each is limited to a system the device does not run
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			return agreement{}, false // which product the row is about is not known
		}
		own, byKey, known := entryFor(c, in, key)
		if !own && (byKey || !known) {
			return agreement{}, false
		}
		if v.RangesFrom == "" && !af.AffectedOnly { // NVD's row (of another product: recordRows found none of the line's)
			nvdRows++
			nvdOther = nvdOther && other(c) != ""
			continue
		}
		if !own {
			continue // the record's row of another product
		}
		n := other(c)
		if n == "" {
			return agreement{}, false
		}
		third = third || !af.VendorCNA
		if !slices.Contains(systems, n) {
			systems = append(systems, n)
		}
	}
	if len(systems) == 0 || third && (nvdRows == 0 || !nvdOther) {
		return agreement{}, false
	}
	slices.Sort(systems)
	who := "the CVE record lists"
	if third {
		who = "the CVE record and NVD list"
	}
	return agreement{t: No, says: fmt.Sprintf("%s %s for %s on %s only, and %s; decided under every reading: whether the record "+
		"lists every affected version or only some, it does not list this system", who, v.CVE, clean(name), orList(systems),
		in.install.platformWhy)}, true
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
