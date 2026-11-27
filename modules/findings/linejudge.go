package findings

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// Release-line verdicts (M-13). A vendor that states per release line whether a CVE affects it (Node.js's security working group:
// "22.x" vulnerable, "^22.23.4" patched) is read here, in one place, before the vendor's scheme rows and NVD's ranges: the line of the
// device's version (the product's trains, after its version_map) is looked up in the vendor's rows. Only explicit vendor rows
// (affected, fixed, unaffected) and the vendor's documented convention for a line it does not list ("not listed means not affected" for
// a line it supported when the CVE was published, from a fresh source) change a decision. A line the vendor no longer assessed, or
// whose status is not public yet, decides nothing here: the CVE record's own statement (CNA, NVD) decides as before.

// LineRow is one release line a vendor line source states for the CVE (feeds_line_status).
type LineRow struct {
	Source, Product, Line, Status   string // Product: the catalogue key; Status: affected, fixed, unaffected, hidden
	Introduced, LastAffected, Fixed string
	Explicit                        bool
	Platforms                       []string // the platforms the row is limited to ("win32"); empty for every platform
}

// LineCover says a vendor line source speaks about the CVE for a product (feeds_line_cve): a line it does not list is read by its
// convention (Absent), only while the source is fresh and its statement is not older than the CVE.
type LineCover struct {
	Source, Product, Ref string
	StatedAt             time.Time
	Absent               string // unaffected_if_supported, unknown
	Stale                bool
}

// LineSupport is one release line of a product: released, and assessed by its vendor until AssessedUntil (zero: still assessed).
type LineSupport struct {
	Source, Product, Line   string
	Released, AssessedUntil time.Time
}

// AbsentUnaffectedIfSupported is the convention "a supported line the vendor does not list is not affected" (feeds line-sources.json).
const AbsentUnaffectedIfSupported = "unaffected_if_supported"

// RangeVendorLine is the range origin of a finding a vendor's release-line statement decided (fnd_finding.range_origin).
const RangeVendorLine = "vendor_line"

type lineVerdict uint8

const (
	lineNone        lineVerdict = iota // no vendor line source speaks: today's path decides
	lineAffected                       // the vendor lists the line affected and the version inside its affected releases
	lineFixed                          // the vendor lists the line and the version at or past its fix (or before the flaw came in)
	lineUnaffected                     // the vendor states the line unaffected, or its convention does for a line it assessed
	lineNotAssessed                    // the vendor no longer assessed the line when the CVE was published: decides nothing
	lineHidden                         // the vendor's status of the line is not public yet: decides nothing
)

// lineRead is lineJudge's answer for one software line.
type lineRead struct {
	verdict    lineVerdict
	product    productid.Product
	line, ver  string
	row        LineRow   // the vendor's row that decided (affected, fixed, explicit unaffected)
	cover      LineCover // the cover of the deciding source
	convention bool      // unaffected by the source's convention, no row of its own
	support    LineSupport
}

// decides says the verdict changes the decision: only the vendor's explicit rows and its fresh convention do.
func (r lineRead) decides() bool {
	return r.verdict == lineAffected || r.verdict == lineFixed || r.verdict == lineUnaffected
}

// within is the vendor's affected range of the line, as the matcher's evidence names it.
func (r lineRead) within() VersionRange {
	return VersionRange{StartIncl: r.row.Introduced, EndIncl: r.row.LastAffected, EndExcl: r.row.Fixed}
}

// lineJudge is the release-line verdict of entry v for software line s of device a. A distribution's package is never read here (the
// distribution's data decides it), nor a version that says nothing. The NVD rule: an explicit "fixed" or "unaffected" holds unless an
// NVD row that covers the version names the line itself (starts on it or lists one of its releases); a convention's "unaffected" holds
// only when no NVD row covers the version. On a disagreement the affected side wins.
func lineJudge(a Asset, s Software, in swInfo, v Vuln) lineRead {
	if len(v.LineCovers) == 0 || !in.given || !versionKnown(in.ver) || in.pkgBuilt() || distroBuilt(in) && linuxDistro(cmpOr(a.OS, in.osName)) != "" {
		return lineRead{}
	}
	p, ok := productid.ResolveStored(s.Vendor, s.Product, s.Display, s.CPE)
	if !ok {
		return lineRead{}
	}
	covers := map[string]LineCover{}
	for _, c := range v.LineCovers {
		if c.Product == p.Key {
			covers[c.Source] = c
		}
	}
	if len(covers) == 0 {
		return lineRead{}
	}
	ver := p.Canonical(in.ver)
	line := p.Line(ver)
	if line == "" {
		return lineRead{}
	}
	out := lineRead{product: p, line: line, ver: ver}
	listed := false
	best := lineRead{}
	rank := map[lineVerdict]int{lineAffected: 4, lineFixed: 3, lineUnaffected: 2, lineHidden: 1}
	for _, r := range v.Lines {
		c, ok := covers[r.Source]
		if !ok || r.Product != p.Key || r.Line != line {
			continue
		}
		listed = true
		if len(r.Platforms) > 0 { // listed for some platforms only: the device's platform is not read here, so it decides nothing
			continue
		}
		got := lineNone
		switch r.Status {
		case "hidden":
			got = lineHidden
		case "unaffected":
			got = lineUnaffected
		default: // affected, fixed: the line's affected releases
			switch (VersionRange{StartIncl: r.Introduced, EndIncl: r.LastAffected, EndExcl: r.Fixed}).Contains(ver) {
			case Yes:
				got = lineAffected
			case No:
				got = lineFixed
			}
		}
		if got != lineNone && rank[got] > rank[best.verdict] {
			best = out
			best.verdict, best.row, best.cover = got, r, c
		}
	}
	switch {
	case best.verdict == lineFixed || best.verdict == lineUnaffected:
		if nvdNamesLine(in, v, p, line) {
			return lineRead{}
		}
		return best
	case best.verdict != lineNone:
		return best
	case listed:
		return lineRead{}
	}
	// the line is not listed: the source's convention, for a line its vendor assessed when the CVE was published
	if v.Published.IsZero() {
		return lineRead{}
	}
	var assessed, notAssessed lineRead
	for _, c := range covers {
		sup, ok := supportOf(v.LineSupport, p.Key, line)
		if !ok {
			continue
		}
		if !sup.Released.After(v.Published) && (sup.AssessedUntil.IsZero() || sup.AssessedUntil.After(v.Published)) {
			if c.Absent == AbsentUnaffectedIfSupported && !c.Stale && !c.StatedAt.Before(utcDay(v.Published)) {
				assessed = out
				assessed.verdict, assessed.cover, assessed.convention, assessed.support = lineUnaffected, c, true, sup
			}
			continue
		}
		notAssessed = out
		notAssessed.verdict, notAssessed.cover, notAssessed.support = lineNotAssessed, c, sup
	}
	if assessed.verdict == lineUnaffected {
		if nvdCovers(in, v) {
			return lineRead{}
		}
		return assessed
	}
	return notAssessed
}

// supportOf is the support of a product's line, the earliest release and the latest end any support source gives.
func supportOf(sup []LineSupport, product, line string) (LineSupport, bool) {
	var out LineSupport
	found := false
	for _, s := range sup {
		if s.Product != product || s.Line != line || s.Released.IsZero() {
			continue
		}
		if !found {
			out, found = s, true
			continue
		}
		if s.Released.Before(out.Released) {
			out.Released = s.Released
		}
		if s.AssessedUntil.IsZero() || !out.AssessedUntil.IsZero() && s.AssessedUntil.After(out.AssessedUntil) {
			out.AssessedUntil = s.AssessedUntil
		}
	}
	return out, found
}

// utcDay is t's day (UTC midnight): a statement of the CVE's publication day covers it.
func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// nvdNamesLine says an NVD row (or the CVE record's, where NVD has none) covers the version and names the device's release line
// itself: it starts on the line or lists one of its releases. A row from version 0, or from an older line, only passes through.
func nvdNamesLine(in swInfo, v Vuln, p productid.Product, line string) bool {
	t, within, _, _ := decide(in, v, keyIDs(v))
	if t != Yes {
		return false
	}
	start := cmp.Or(within.StartIncl, within.StartExcl)
	return start != "" && p.Line(p.Canonical(start)) == line
}

// lineDecision is judge's reading of a line verdict that decides: the tri-state, the vendor's affected range of the line, and the
// sentence of a "not affected" proof.
func lineDecision(a Asset, s Software, v Vuln, r lineRead) (Tri, VersionRange, string) {
	if r.verdict == lineAffected {
		return Yes, r.within(), ""
	}
	who, product := lineWho(r), cmp.Or(clean(r.product.Display), clean(s.Display))
	var why string
	switch {
	case r.convention:
		why = fmt.Sprintf("%s lists %s for other release lines of %s only, and states that a line it supported then and does not list is not affected (%s %s was supported when %s was published)",
			who, v.CVE, product, product, clean(r.line), v.CVE)
	case r.verdict == lineUnaffected:
		why = fmt.Sprintf("%s states that release line %s of %s is not affected by %s", who, clean(r.line), product, v.CVE)
	case r.row.Introduced != "" && (VersionRange{EndExcl: r.row.Introduced}).Contains(r.ver) == Yes:
		why = fmt.Sprintf("%s lists %s on release line %s of %s from version %s on; version %s is older", who, v.CVE, clean(r.line), product, clean(r.row.Introduced), clean(r.ver))
	case r.row.Fixed != "":
		why = fmt.Sprintf("%s fixed %s on release line %s of %s in %s; version %s is at or past it", who, v.CVE, clean(r.line), product, clean(r.row.Fixed), clean(r.ver))
	default:
		why = fmt.Sprintf("%s lists %s on release line %s of %s up to %s; version %s is later", who, v.CVE, clean(r.line), product, clean(r.row.LastAffected), clean(r.ver))
	}
	if ref := clean(r.cover.Ref); ref != "" {
		why += " (" + ref + ")"
	}
	return No, VersionRange{}, "Not affected: " + why + ". Vedette closed this by itself and reopens it if a later match says the device is affected."
}

// lineAffectedNote is the evidence of a finding a vendor's line statement decided.
func lineAffectedNote(a Asset, s Software, v Vuln, r lineRead) string {
	product := cmp.Or(clean(r.product.Display), clean(s.Display))
	runs := fmt.Sprintf("%s runs %s %s", clean(a.Name), product, clean(r.ver))
	if s.Source == "agent" {
		runs = fmt.Sprintf("The agent on %s reports %s %s installed", clean(a.Name), product, clean(r.ver))
	}
	who := lineWho(r)
	ref := ""
	if u := clean(r.cover.Ref); u != "" {
		ref = " (" + u + ")"
	}
	if r.row.Fixed == "" && r.row.LastAffected == "" {
		return fmt.Sprintf("%s. %s lists release line %s as affected by %s and names no fixed release for it yet%s"+suspectedClause, runs, who, clean(r.line), v.CVE, ref)
	}
	if r.row.Fixed == "" {
		return fmt.Sprintf("%s. %s lists release line %s as affected by %s up to %s%s, so this device has the flaw until it moves to a later release.", runs, who, clean(r.line), v.CVE, clean(r.row.LastAffected), ref)
	}
	return fmt.Sprintf("%s. %s fixed %s in %s for release line %s%s, so this device has the flaw until it installs that release or a later one.", runs, who, v.CVE, clean(r.row.Fixed), clean(r.line), ref)
}

// lineWho names the vendor source in a sentence.
func lineWho(r lineRead) string {
	if n, ok := lineSourceNames[r.cover.Source]; ok {
		return n
	}
	return "The vendor (" + strings.ReplaceAll(clean(r.cover.Source), "-", " ") + ")"
}

// lineSourceNames are the names the texts give the built-in line sources.
var lineSourceNames = map[string]string{"nodejs-security-wg": "The Node.js security team"}

// lineFix is FixOf from a vendor's line statement: its fixed release of the device's line. ok is false when no line source decides the
// line affected with a fix.
func lineFix(a Asset, s Software, v Vuln) (Fix, bool) {
	r := lineJudge(a, s, swInfoOn(s, a), v)
	switch {
	case r.verdict != lineAffected:
		return Fix{}, false
	case r.row.Fixed != "":
		return Fix{Kind: FixUpdate, Version: r.row.Fixed}, true
	case r.row.LastAffected == "":
		return Fix{Kind: FixNoneYet}, true
	}
	return Fix{}, false
}
