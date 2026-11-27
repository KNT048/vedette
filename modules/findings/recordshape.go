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
// operating system or firmware ("o") for a device's firmware of no stated version, which may be any of them.
func naVersionApart(c CPE, ver string, rows []Affected) bool {
	if c.Part.Kind != Value || c.Part.Value != "a" || c.Version.Kind != NA || !versionKnown(ver) {
		return false
	}
	return slices.ContainsFunc(rows, func(o Affected) bool {
		oc, err := o.cpe()
		return err == nil && oc.Version.Kind != NA && sameProduct(c, oc) && versionEvidence(o)
	})
}

// earlierMarker says row af (version ANY, no range, nothing pinned) only repeats NVD's legacy "and earlier": the same list has a row of
// the same product that ends and has no start ("5.14 and earlier": a bare "*" beside "up to 5.14"). Such a pair never means "every
// version": the bounded row would then say nothing. The bounded row decides; a range that starts somewhere does not make a bare row a
// marker (it may be "every version" beside a later line's range). A record row that only says "affected" (AffectedOnly) is neither.
func earlierMarker(c CPE, af Affected, rows []Affected) bool {
	if af.AffectedOnly || !af.Range.IsZero() || !everyVersion(c) {
		return false
	}
	for _, o := range rows {
		r := o.Range
		if o.AffectedOnly || !endBound(r) || r.StartIncl+r.StartExcl != "" && !isPlaceholder(r.StartIncl+r.StartExcl) {
			continue
		}
		if oc, err := o.cpe(); err == nil && sameProduct(c, oc) {
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
// nothing on its own; it does when the version is
//   - past the end of a row that starts on the version's own train (the record speaks for that train: "2.56.0-rc0" before "2.56.1"
//     on 2.56.1), or
//   - past the end of a row from version 0 or with no start ("before 7.2.9" on 7.4.7), and below the start of no row: a version
//     between the trains the record lists (2.53.0 beside rows for 2.50 and 2.56) stays undecided, since the record may have skipped
//     its train.
//
// A bound that does not compare, or an exact row above the version, keeps the CVE undecided.
func pastRecordFix(in swInfo, v Vuln, key []identity) bool {
	if !versionKnown(in.ver) {
		return false
	}
	train, fromZero, gap := false, false, false
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || af.AffectedOnly {
			continue
		}
		if own, _, _ := entryFor(c, in, key); !own {
			continue
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
		if !pastEnd(r, in.ver) || r.StartIncl != "" && r.StartIncl == r.EndIncl {
			continue // not past it, or one exact release (no fix stated)
		}
		switch {
		case start == "" || isPlaceholder(start):
			fromZero = true
		case sameTrain(in.ver, start, cmp.Or(r.EndExcl, r.EndIncl)):
			train = true
		}
	}
	return train || fromZero && !gap
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
