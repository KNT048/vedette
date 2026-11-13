package findings

import (
	"slices"
	"strings"
)

// FixedIn is what NVD's affected versions say about the fix of one finding, for the device it is on (D-488): the
// "What to do" part of a finding page. It is only ever built from a range with an end bound; no range, no FixedIn,
// and the page keeps CISA's required action and the vendor's advisory.
type FixedIn struct {
	// Kind is "fixed" (the device's version is inside a range that ends before Fixed), "up_to" (inside a range that
	// ends at Fixed, itself affected: NVD names no fixed release) or "branches" (the version is not known).
	Kind     string        `json:"kind"`
	Version  string        `json:"version"` // the device's version; "" for branches
	Fixed    string        `json:"fixed"`   // fixed (kind fixed), last affected (kind up_to), "" for branches
	Branches []FixedBranch `json:"branches"`
	More     int           `json:"more"`   // branches left out of Branches
	Source   string        `json:"source"` // always FixedInSource
}

// FixedBranch is the first fixed release of one release line ("7.4" -> "7.4.3"); Branch is "" when the line cannot be
// told from the version.
type FixedBranch struct {
	Branch string `json:"branch"`
	Fixed  string `json:"fixed"`
}

// FixedInSource labels where the fixed versions come from.
const FixedInSource = "NVD affected versions"

const maxFixedBranches = 5

// FixedInFor says which release fixes v on device a, from the NVD ranges in v.Affected, or nil when they do not say.
// It reads the software the same way the matcher does (the entries that apply, evalAffected for a known version) and
// invents nothing: a range with no end bound, an exact-version entry or a version outside every range gives nil.
func FixedInFor(a Asset, v Vuln) *FixedIn {
	multi := isMultiProduct(v.Product)
	var key []identity
	if n := (identity{vendor: norm(v.Vendor), product: norm(v.Product)}); !multi && n.ok() {
		key = []identity{n}
	}
	for _, s := range a.Software {
		if !keyedTo(s, v) {
			continue
		}
		in := newSWInfo(s, []Vuln{v}, a.OS)
		if f := fixedInSoftware(in, v, key); f != nil {
			return f
		}
	}
	return nil
}

func fixedInSoftware(in swInfo, v Vuln, key []identity) *FixedIn {
	known := in.given && versionKnown(in.ver)
	var excl, incl *FixedIn
	var ends []string // EndExcl of every applicable range, for the branches list
	for _, af := range v.Affected {
		r := af.Range
		if r.IsZero() {
			continue // all versions or one exact version: no fixed release in it
		}
		c, err := ParseCPE(af.CPE)
		if err != nil || c.Part.Kind == NA || c.Version.Kind != Any || c.Update.Kind != Any {
			continue
		}
		own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids)
		byKey, _ := appliesTo(c, CPE{}, false, key)
		if !own && !byKey || !byKey && distroRelease(c) {
			continue
		}
		if !known {
			if r.EndExcl != "" {
				ends = append(ends, r.EndExcl)
			}
			continue
		}
		if t, _ := evalAffected(c, r, in.ver, in.cpe, in.hasCPE); t != Yes {
			continue
		}
		switch {
		case r.EndExcl != "" && excl == nil:
			excl = &FixedIn{Kind: "fixed", Version: clean(in.ver), Fixed: clean(r.EndExcl)}
		case r.EndIncl != "" && incl == nil:
			incl = &FixedIn{Kind: "up_to", Version: clean(in.ver), Fixed: clean(r.EndIncl)}
		}
	}
	var f *FixedIn
	switch {
	case excl != nil:
		f = excl
	case incl != nil:
		f = incl
	case !known && len(ends) > 0:
		f = branches(ends)
	default:
		return nil
	}
	f.Source = FixedInSource
	if f.Branches == nil {
		f.Branches = []FixedBranch{}
	}
	return f
}

// branches lists the fixed releases newest first, one per distinct version, at most maxFixedBranches.
func branches(ends []string) *FixedIn {
	slices.SortStableFunc(ends, func(a, b string) int {
		if c, ok := compareBound(a, b); ok {
			return -c
		}
		return 0
	})
	ends = slices.Compact(ends)
	var all []FixedBranch
	seen := map[string]bool{}
	for _, e := range ends { // newest first: the first of a line is its highest fix, the safe one to name
		b := branchOf(e)
		if b != "" && seen[b] {
			continue
		}
		seen[b] = true
		all = append(all, FixedBranch{Branch: b, Fixed: clean(e)})
	}
	f := &FixedIn{Kind: "branches", Branches: all}
	if len(all) > maxFixedBranches {
		f.Branches, f.More = all[:maxFixedBranches], len(all)-maxFixedBranches
	}
	return f
}

// branchOf is the release line of a plain dotted version: the version without its last number ("7.4.3" -> "7.4").
// Anything else ("22.4R2", "15.2(4)m3") has no line we can name.
func branchOf(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	return strings.Join(parts[:len(parts)-1], ".")
}
