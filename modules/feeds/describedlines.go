package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// describedProduct says r names a product whose vendor may state its fixed releases in a record's description (versionscheme
// Described: Synology's DSM).
func describedProduct(r Range) bool {
	p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	if !ok || p.Scheme == "" {
		return false
	}
	s, ok := versionscheme.Lookup(p.Scheme)
	return ok && s.Described
}

// describedVendors is the vendor names, as ranges store them, of every product of a Described scheme.
var describedVendors = sync.OnceValue(func() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(v string) {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, p := range productid.Products() {
		if s, ok := versionscheme.Lookup(p.Scheme); !ok || !s.Described {
			continue
		}
		add(productid.Norm(p.Vendor))
		for _, c := range p.CPEs {
			if f := strings.Split(c.Base(), ":"); len(f) == 3 {
				add(f[1])
			}
		}
		for _, a := range p.Also {
			if v, _, ok := strings.Cut(a, "|"); ok {
				add(productid.Norm(v))
			}
		}
	}
	return out
})

// lineFixes are the fixed releases the CVEs name for one product: per CVE, per release line (the line's start Train, "7.2.1"), the
// latest fixed release its rows or its description name on that line.
type lineFixes map[string]map[string]versionscheme.Version

// add notes v as a fixed release cve names.
func (f lineFixes) add(cve string, v versionscheme.Version) {
	if v.LineStart {
		return
	}
	line := versionscheme.LineStart(v).Train
	if f[cve] == nil {
		f[cve] = map[string]versionscheme.Version{}
	}
	if prev, ok := f[cve][line]; ok {
		if c, ok := versionscheme.Compare(prev, v); !ok || c >= 0 {
			return
		}
	}
	f[cve][line] = v
}

// patchedWith is the lines the vendor still patched when it fixed cve: the lines of every CVE that names, on a line cve also names, a
// fixed release at or after cve's (the same batch of fixes, or a later one), cve's own lines left out. Synology names the fixed release
// of every line it maintains in each record, so a line patched beside a fix as late as cve's was maintained then; a line whose last fix
// came with earlier releases only (out of support, or a record published late) is not among them. Never a date: a CVE's publication
// can lag its advisory by a year.
func (f lineFixes) patchedWith(cve string) []versionscheme.Version {
	own := f[cve]
	if len(own) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []versionscheme.Version
	for other, lines := range f {
		if other == cve || !laterOrSame(lines, own) {
			continue
		}
		for line, v := range lines {
			if _, named := own[line]; !named && !seen[line] {
				seen[line] = true
				out = append(out, versionscheme.LineStart(v))
			}
		}
	}
	slices.SortFunc(out, func(a, b versionscheme.Version) int { return strings.Compare(a.Train, b.Train) })
	return out
}

// laterOrSame says lines names, on a line own names too, a fixed release at or after own's.
func laterOrSame(lines, own map[string]versionscheme.Version) bool {
	for line, v := range lines {
		if mine, ok := own[line]; ok {
			if c, ok := versionscheme.Compare(v, mine); ok && c >= 0 {
				return true
			}
		}
	}
	return false
}

// describedFixes reads, for every product of a Described scheme (by catalogue key), the fixed releases each CVE of the catalogue
// names: the end of each of its rows a scheme reads (NVD's rows in the vendor's notation, the record's bounded rows) and the list of
// its description when a record row states no version.
func (s *Store) describedFixes(ctx context.Context) (map[string]lineFixes, error) {
	vendors, err := json.Marshal(describedVendors())
	if err != nil {
		return nil, fmt.Errorf("feeds: described fixes: %w", err)
	}
	rows, err := readRanges(ctx, s.db.Reader(), `WHERE r.vendor IN (SELECT value FROM json_each(?))`, string(vendors))
	if err != nil {
		return nil, err
	}
	out := map[string]lineFixes{}
	fixesOf := func(r Range) (lineFixes, bool) {
		p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
		if !ok || !describedProduct(r) {
			return nil, false
		}
		if out[p.Key] == nil {
			out[p.Key] = lineFixes{}
		}
		return out[p.Key], true
	}
	var silent []Range
	for _, r := range rows {
		f, ok := fixesOf(r)
		if !ok {
			continue
		}
		if r.Origin != OriginNVD && !recordBounded(r) {
			silent = append(silent, r)
			continue
		}
		if _, sp, _, ok := RangeScheme(r); ok && sp.End != nil && !sp.EndIncl && r.EndExcl != r.StartIncl {
			f.add(r.CVE, *sp.End)
		}
	}
	if len(silent) == 0 {
		return out, nil
	}
	desc, err := s.descriptionsOf(ctx, silent)
	if err != nil {
		return nil, err
	}
	for _, r := range silent {
		f, _ := fixesOf(r)
		fixed, _ := describedList(r, desc[r.CVE])
		for _, v := range fixed {
			f.add(r.CVE, v.Version)
		}
	}
	return out, nil
}
