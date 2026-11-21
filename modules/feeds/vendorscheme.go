package feeds

import (
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// RangeScheme is the version scheme of the product a range names (core/productid's catalogue product of its CPE or of its record
// key, ByRangeName), with the range read in it: its bounds as a versionscheme.Span, and its fixed release when it states one. ok is
// false when the product has no scheme, a bound does not read in it, or the row names one version in its CPE (pinnedInCPE): then the
// row says only what its words say. The matcher reads a row kept in a vendor's notation (Range.Generic false) only through this;
// the brief shows each row's train and fixed release.
func RangeScheme(r Range) (s *versionscheme.Scheme, sp versionscheme.Span, fixed *versionscheme.Version, ok bool) {
	p, found := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	if !found || p.Scheme == "" || r.StartExcl != "" || pinnedInCPE(r) {
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
