package feeds

import (
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// RangeScheme is the version scheme of the product a range names (core/productid's catalogue product of its CPE or of its record
// key, ByRangeName), with the range read in it: its bounds as a versionscheme.Span, and its fixed release when it states one. ok is
// false when the product has no scheme, a bound does not read in it, the row names one version in its CPE (pinnedInCPE), or it is a CVE
// record's row that states no version at all (recordBounded): then the row says only what its words say. The matcher reads a row kept in a vendor's notation (Range.Generic false) only through this;
// the brief shows each row's train and fixed release. A row that states unaffected versions (Range.Unaffected) or holds only on some
// models (Range.ModelLimited) is no affected range: false, StatementScheme reads those.
func RangeScheme(r Range) (s *versionscheme.Scheme, sp versionscheme.Span, fixed *versionscheme.Version, ok bool) {
	if r.Unaffected() || r.ModelLimited() {
		return nil, versionscheme.Span{}, nil, false
	}
	return rangeScheme(r)
}

// StatementScheme reads, in its product's version scheme, a CVE record row that only supports a "not affected" verdict: a range the
// vendor states unaffected (unaffected true: Juniper's "0 lessThan 24.4R1", whatever the model) or an affected range that holds only on
// some models (ModelLimited, unaffected false: a version outside every such range of a product whose unlisted versions are unaffected
// is not affected, one inside it is not known to be). ok is false for any other row, and as RangeScheme's for one that does not read.
func StatementScheme(r Range) (s *versionscheme.Scheme, sp versionscheme.Span, unaffected, ok bool) {
	if !r.Unaffected() && !r.ModelLimited() {
		return nil, versionscheme.Span{}, false, false
	}
	s, sp, _, ok = rangeScheme(r)
	return s, sp, r.Unaffected(), ok
}

func rangeScheme(r Range) (s *versionscheme.Scheme, sp versionscheme.Span, fixed *versionscheme.Version, ok bool) {
	p, found := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	if !found || p.Scheme == "" || r.StartExcl != "" || pinnedInCPE(r) || r.Origin != OriginNVD && !recordBounded(r) {
		return nil, versionscheme.Span{}, nil, false
	}
	s, found = versionscheme.Lookup(p.Scheme)
	if !found {
		return nil, versionscheme.Span{}, nil, false
	}
	sp, ok = s.Span(r.StartIncl, r.EndExcl, r.EndIncl)
	if !ok {
		return nil, versionscheme.Span{}, nil, false
	}
	switch {
	case r.Fixed != "" && sp.End != nil && !sp.EndIncl && (r.Fixed == r.EndExcl):
		fixed = sp.End
	case r.Fixed != "":
		v, ok := s.Parse(r.Fixed)
		if !ok {
			return nil, versionscheme.Span{}, nil, false
		}
		fixed = &v
	case r.Origin != OriginNVD && r.DefaultStatus == DefaultUnaffected && sp.End != nil && !sp.EndIncl && r.EndExcl != r.StartIncl:
		fixed = sp.End // the versions from the end on are unaffected: the vendor's fixed release
	}
	return s, sp, fixed, true
}

// pinnedInCPE says a row without bounds names its version in its CPE (NVD's "cpe:2.3:o:vmware:esxi:8.0:update_3:…"): not every
// version, and not a range a scheme reads (the CPE's version and update are NVD's words, not the vendor's notation).
func pinnedInCPE(r Range) bool {
	if r.StartIncl != "" || r.EndIncl != "" || r.EndExcl != "" {
		return false
	}
	f := cpeFields(r.CPE)
	return len(f) > 6 && (f[5] != "*" || f[6] != "*" && f[6] != "")
}

// BriefFix is the fixed release a vendor states for one release train of a product, as its version scheme reads the CVE's ranges.
type BriefFix struct {
	Vendor, Product string // the range's product, as stored ("vmware", "esxi")
	Origin          string // who stated it (OriginCNA, OriginADP, OriginNVD)
	Train           string // "8.0 U3"
	Release         string // "8.0 U3d (build 24585383)"
}

// describedRows are the ranges a CVE record states only in its description, for a record row r of a product whose vendor writes its
// fixed releases there (versionscheme Described: Synology's records name "DiskStation Manager (DSM)" with no version, and say "Synology
// DiskStation Manager (DSM) before 7.2.1-69057-10, 7.2.2-72806-7 and 7.3.2-86009-2 allows …"). Each release of the list that the
// product's scheme reads is the fixed release of its line: one row from the start of that line to it (origin and product of r, kept in
// the vendor's notation, unaffected from the fix on). A line the description says is not affected ("(7.2.1-69057 is not affected)") is an
// empty row (unaffectedLine): the vendor's own word. A line older than every line the list names gets no row: a fix the vendor ships
// on that line for another CVE does not say this CVE leaves it unaffected (Synology patches lines past their support for selected
// critical flaws only), and the list does not say it is affected either, so the row without a version stays the generic comparison's
// (a question). A line between two named ones, or after the last, is left to what the other rows say. Nothing when the description
// does not name the product right before "before", or names no release the scheme reads; the list ends at the first word that is no
// release ("and Synology Unified Controller").
func describedRows(r Range, description string) []Range {
	fixed, unaffected := describedList(r, description)
	if len(fixed) == 0 {
		return nil
	}
	out := make([]Range, 0, len(fixed)+len(unaffected))
	for _, f := range fixed {
		out = append(out, Range{CVE: r.CVE, Origin: r.Origin, Part: r.Part, Vendor: r.Vendor, Product: r.Product, CPE: r.CPE, StartIncl: f.Train,
			EndExcl: f.text, Fixed: f.text, VersionType: VendorNotation + "text", DefaultStatus: DefaultUnaffected, Platforms: []string{}})
	}
	named := map[string]bool{}
	for _, f := range fixed {
		named[versionscheme.LineStart(f.Version).Train] = true
	}
	for _, l := range unaffected {
		if t := versionscheme.LineStart(l).Train; !named[t] {
			named[t] = true
			out = append(out, unaffectedLine(r, l))
		}
	}
	return out
}

// statedUnaffected are the empty rows of the lines a record's description says are not affected ("before 7.2.2-72806-5 and
// 7.3.1-86003-1 (7.2.1-69057 is not affected)"), for a record row r that states its versions as rows: the rows name the other lines.
func statedUnaffected(r Range, description string) []Range {
	_, unaffected := describedList(r, description)
	out := make([]Range, 0, len(unaffected))
	for _, l := range unaffected {
		out = append(out, unaffectedLine(r, l))
	}
	return out
}

// unaffectedLine is the row saying no release of line l is affected: from the line's start to that same start (versionscheme Span reads
// it as empty), in r's product and origin.
func unaffectedLine(r Range, l versionscheme.Version) Range {
	t := versionscheme.LineStart(l).Train
	return Range{CVE: r.CVE, Origin: r.Origin, Part: r.Part, Vendor: r.Vendor, Product: r.Product, CPE: r.CPE, StartIncl: t, EndExcl: t,
		VersionType: VendorNotation + "text", DefaultStatus: DefaultUnaffected, Platforms: []string{}}
}

// describedFix is one fixed release of a description's list, with the text it is written in.
type describedFix struct {
	versionscheme.Version
	text string
}

// describedList reads the description of a record row r of a Described product: the fixed releases the list after "<product>
// before" names, and the lines a parenthesis right after the list says are not affected ("(7.2.1-69057 is not affected)", "(7.1.1 and
// 7.2.1 are not affected)"). Both empty when the description does not say them in this form.
func describedList(r Range, description string) (fixed []describedFix, unaffected []versionscheme.Version) {
	p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	if !ok || p.Scheme == "" || len(description) > 4000 {
		return nil, nil
	}
	s, ok := versionscheme.Lookup(p.Scheme)
	if !ok || !s.Described {
		return nil, nil
	}
	lower := strings.ToLower(description)
	at := -1
	for _, name := range describedNames(p) {
		if i := strings.Index(lower, strings.ToLower(name)); i >= 0 && (at < 0 || i < at) {
			if m := describedBefore.FindStringIndex(lower[i+len(name):]); m != nil && m[0] == 0 {
				at = i + len(name) + m[1]
			}
		}
	}
	if at < 0 {
		return nil, nil
	}
	rest := description[at:]
	for {
		tok := describedRelease.FindString(rest)
		v, ok := s.Parse(strings.TrimRight(tok, ".,"))
		if tok == "" || !ok || v.LineStart {
			break
		}
		fixed = append(fixed, describedFix{Version: v, text: strings.TrimRight(tok, ".,")})
		rest = rest[len(tok):]
		sep := describedSep.FindString(rest)
		if sep == "" {
			break
		}
		rest = rest[len(sep):]
	}
	if len(fixed) == 0 {
		return nil, nil
	}
	m := describedNotAffected.FindStringSubmatch(rest)
	if m == nil {
		return fixed, nil
	}
	for _, tok := range describedListSep.Split(strings.TrimSpace(m[1]), -1) {
		v, ok := s.Parse(tok)
		if !ok {
			return fixed, nil // a word that is no release: the parenthesis says something else
		}
		unaffected = append(unaffected, versionscheme.LineStart(v))
	}
	return fixed, unaffected
}

var (
	describedBefore      = regexp.MustCompile(`^(?:\s*\([^)]{1,40}\))?\s+before\s+`)
	describedRelease     = regexp.MustCompile(`^[0-9][0-9A-Za-z.\-]{0,39}`)
	describedSep         = regexp.MustCompile(`^(?:\s*,\s*(?:and\s+)?|\s+and\s+)`)
	describedNotAffected = regexp.MustCompile(`^\s*\(([0-9][0-9A-Za-z.,\- ]{0,120}?)\s+(?:is|are)\s+not\s+affected\s*\)`)
	describedListSep     = regexp.MustCompile(`\s*,\s*(?:and\s+)?|\s+and\s+`)
)

// describedNames are the names a description may give the product: its display name, its own product name and its other names.
func describedNames(p productid.Product) []string {
	out := []string{p.Display, p.Product}
	for _, a := range p.Also {
		if _, pr, ok := strings.Cut(a, "|"); ok {
			out = append(out, pr)
		}
	}
	return out
}
