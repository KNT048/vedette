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
// the brief shows each row's train and fixed release.
func RangeScheme(r Range) (s *versionscheme.Scheme, sp versionscheme.Span, fixed *versionscheme.Version, ok bool) {
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
	case r.Origin != OriginNVD && r.DefaultStatus == DefaultUnaffected && sp.End != nil && !sp.EndIncl:
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
// the vendor's notation, unaffected from the fix on). Nothing when the description does not name the product right before "before",
// or names no release the scheme reads; the list ends at the first word that is no release ("and Synology Unified Controller").
func describedRows(r Range, description string) []Range {
	p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	if !ok || p.Scheme == "" || len(description) > 4000 {
		return nil
	}
	s, ok := versionscheme.Lookup(p.Scheme)
	if !ok || !s.Described {
		return nil
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
		return nil
	}
	var out []Range
	rest := description[at:]
	for {
		tok := describedRelease.FindString(rest)
		v, ok := s.Parse(strings.TrimRight(tok, ".,"))
		if tok == "" || !ok || v.LineStart {
			break
		}
		fixed := strings.TrimRight(tok, ".,")
		out = append(out, Range{CVE: r.CVE, Origin: r.Origin, Part: r.Part, Vendor: r.Vendor, Product: r.Product, CPE: r.CPE, StartIncl: v.Train,
			EndExcl: fixed, Fixed: fixed, VersionType: VendorNotation + "text", DefaultStatus: DefaultUnaffected, Platforms: []string{}})
		rest = rest[len(tok):]
		sep := describedSep.FindString(rest)
		if sep == "" {
			break
		}
		rest = rest[len(sep):]
	}
	return out
}

var (
	describedBefore  = regexp.MustCompile(`^(?:\s*\([^)]{1,40}\))?\s+before\s+`)
	describedRelease = regexp.MustCompile(`^[0-9][0-9A-Za-z.\-]{0,39}`)
	describedSep     = regexp.MustCompile(`^(?:\s*,\s*(?:and\s+)?|\s+and\s+)`)
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
