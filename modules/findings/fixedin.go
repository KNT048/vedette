package findings

import (
	"regexp"
	"slices"
	"strings"
)

// FixedIn is what NVD's affected versions say about the fix of one finding, for the device it is on (D-488): the
// "What to do" part of a finding page. It is only ever built from a range with an end bound; no range, no FixedIn,
// and the page keeps CISA's required action and the vendor's advisory.
type FixedIn struct {
	// Kind is "fixed" (the device's version is inside a range that ends before Fixed, and Fixed is outside every
	// range that applies), "up_to" (inside a range that ends at Fixed, itself affected: NVD names no fixed release),
	// "branches" (the version is not known, or not readable) or "distro" (a package of the distribution, whose security
	// updates carry the fix under their own numbers: an agent read it from the device's package database, or the version
	// carries a distribution marker, "2.4.52-1ubuntu4", on Ubuntu/Debian).
	Kind     string        `json:"kind"`
	Version  string        `json:"version"` // the device's version; "" when it has none (branches), the unreadable text when it has one Vedette cannot read
	Fixed    string        `json:"fixed"`   // fixed (kind fixed), last affected (kind up_to), the upstream fixed release when NVD names one (kind distro: the backport may keep the package's number below it), "" otherwise
	Branches []FixedBranch `json:"branches"`
	More     int           `json:"more"`   // release lines with a fix left out of Branches
	NoFix    int           `json:"no_fix"` // release lines NVD gives no fixed release for (a range ending at an affected version)
	// Distro is the distribution ("Ubuntu", "Debian") the device runs, "" when it runs none Vedette names. Kind distro: whose
	// updates to install ("" = "your distribution's"). Other kinds: set only when the row's origin is not known to be the
	// package database (a person typed it, a scan read it, or an agent row stored before inventory kept the flag), so the
	// page names the upstream number and adds "if you installed it from <distro>'s packages, install its security updates instead".
	Distro string `json:"distro"`
	// DistroFixed, DistroRelease and DistroPro (D-516, kind distro only): the version of the distribution's package that fixes
	// the CVE on the device's release ("1:9.6p1-3ubuntu13.5" for Ubuntu "24.04"), and whether only Ubuntu Pro has it; Version
	// is then the device's full package version. "" when the distribution's data does not say.
	DistroFixed   string `json:"distro_fixed"`
	DistroRelease string `json:"distro_release"`
	DistroPro     bool   `json:"distro_pro"`
	Source        string `json:"source"` // FixedInSource, FixedInSourceCVEOrg (D-556), or DistroSource when DistroFixed is set
}

// FixedBranch is the fix of one release line, the line named by the start of its range ("7.4" -> "7.4.3"); Branch is
// "" when the range has no start or it is not a plain dotted version.
type FixedBranch struct {
	Branch string `json:"branch"`
	Fixed  string `json:"fixed"`
}

// FixedInSource labels where the fixed versions come from; FixedInSourceCVEOrg when NVD has none and they come from the
// CNA's CVE.org record (D-556).
const (
	FixedInSource       = "NVD affected versions"
	FixedInSourceCVEOrg = "CVE.org affected versions (from the CVE record's CNA)"
)

const maxFixedBranches = 5

// FixedInFor says which release fixes v on device a, from the NVD ranges in v.Affected, or nil when they do not say.
// It reads the software the same way the matcher does (the entries that apply, evalAffected) and invents nothing: a
// fixed release is named only when it lies outside EVERY applicable entry (an iPhone range ending at 18.3 does not
// make the iPadOS-only 17.7.6 a fix), and a distribution's package is told to take the distribution's security updates
// (the upstream number only as a reference). Of several software rows of the product,
// the one with the most definite answer wins.
func FixedInFor(a Asset, v Vuln) *FixedIn {
	multi := isMultiProduct(v.Product)
	var key []identity
	if n := (identity{vendor: norm(v.Vendor), product: norm(v.Product)}); !multi && n.ok() {
		key = []identity{n}
	}
	var best *FixedIn
	rank := func(f *FixedIn) int {
		switch {
		case f == nil:
			return 0
		case f.DistroFixed != "": // the distribution's own fixed package: the most definite answer (D-516)
			return 6
		case f.Kind == "fixed":
			return 5
		case f.Kind == "up_to":
			return 4
		case f.Kind == "distro":
			return 3
		case f.Version == "":
			return 2
		}
		return 1
	}
	for _, s := range deviceSoftware(a) {
		if !keyedTo(s, v) {
			continue
		}
		in := newSWInfo(s, a.OS)
		if f, ok := windowsFixedIn(in, v); ok { // D-546
			if rank(f) > rank(best) {
				best = f
			}
			continue
		}
		if f := fixedInSoftware(in, v, key); rank(f) > rank(best) {
			best = f
		}
	}
	return best
}

type fixedEntry struct {
	c CPE
	r VersionRange
}

// boundsReadable says every bound the range has is a version Vedette can compare.
func boundsReadable(r VersionRange) bool {
	for _, b := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
		if b != "" && !versionKnown(b) {
			return false
		}
	}
	return true
}

// fixedParts are the entries of v that apply to the software (ents), those that carry a readable range (usable), and outside: X
// is a version that none of the applicable entries lists or cannot judge.
type fixedParts struct {
	ents, usable []fixedEntry
	outside      func(string) bool
}

func fixedPartsOf(in swInfo, v Vuln, key []identity) fixedParts {
	var ents []fixedEntry // every entry that applies to the software, whatever its range
	for _, af := range v.Affected {
		c, err := ParseCPE(af.CPE)
		if err != nil || c.Part.Kind == NA {
			continue
		}
		own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids)
		byKey, _ := appliesTo(c, CPE{}, false, key)
		if !own && !byKey || !byKey && distroRelease(c) {
			continue
		}
		ents = append(ents, fixedEntry{c, af.Range})
	}
	// usable are the entries that carry a range with readable bounds: the only ones a fix can be read from.
	var usable []fixedEntry
	for _, e := range ents {
		if !e.r.IsZero() && e.c.Version.Kind == Any && e.c.Update.Kind == Any && boundsReadable(e.r) {
			usable = append(usable, e)
		}
	}
	outside := func(x string) bool {
		for _, e := range ents {
			if t, _ := evalAffected(e.c, e.r, x, in.cpe, in.hasCPE); t != No {
				return false
			}
		}
		return true
	}
	return fixedParts{ents, usable, outside}
}

func fixedInSoftware(in swInfo, v Vuln, key []identity) *FixedIn {
	if d, ok := distroVerdict(in, v); ok { // D-516: the distribution's word on its own package
		if d.kind != distroNeeded {
			return nil // fixed here or not affected: nothing to install
		}
		return &FixedIn{Kind: "distro", Version: clean(in.pkgVer), Distro: d.name, DistroFixed: clean(d.fixed), DistroRelease: d.release,
			DistroPro: d.pro, Branches: []FixedBranch{}, Source: DistroSource(d.name)}
	}
	p := fixedPartsOf(in, v, key)
	usable, outside := p.usable, p.outside
	// A package of the distribution: an agent read it from the package database, or its version says so (D-488). A row
	// whose origin is not known keeps the upstream answer with the condition (Distro below).
	distro := in.given && (in.packaged || distroMarked(in.ver) && distroName(in) != "")
	var f *FixedIn
	if in.given && versionKnown(in.ver) {
		f = fixedForVersion(in, usable, outside, distro)
	} else {
		f = fixedBranches(in, usable, outside)
		if f != nil && distro {
			f = &FixedIn{Kind: "distro", Version: f.Version, Distro: distroName(in)}
		}
	}
	if f == nil {
		return nil
	}
	f.Source = FixedInSource
	if v.fromCVEOrg() {
		f.Source = FixedInSourceCVEOrg
	}
	if f.Kind != "distro" {
		f.Distro = distroName(in)
	}
	if f.Branches == nil {
		f.Branches = []FixedBranch{}
	}
	return f
}

func fixedForVersion(in swInfo, usable []fixedEntry, outside func(string) bool, distro bool) *FixedIn {
	var excl, incl []string // end bounds of the ranges the device's version is inside
	for _, e := range usable {
		if t, _ := evalAffected(e.c, e.r, in.ver, in.cpe, in.hasCPE); t != Yes {
			continue
		}
		if e.r.EndExcl != "" {
			excl = append(excl, e.r.EndExcl)
		} else if e.r.EndIncl != "" {
			incl = append(incl, e.r.EndIncl)
		}
	}
	if len(excl)+len(incl) == 0 {
		return nil // inside no range, or inside only ranges with no end
	}
	asc := func(l []string) []string {
		slices.SortStableFunc(l, func(a, b string) int {
			if c, ok := compareBound(a, b); ok {
				return c
			}
			return 0
		})
		return l
	}
	fixed := ""
	for _, x := range asc(excl) { // the nearest release that no entry lists
		if outside(x) {
			fixed = clean(x)
			break
		}
	}
	if distro { // apt/dnf fix it with backports under their own numbers; the upstream release is only a reference
		return &FixedIn{Kind: "distro", Version: clean(in.ver), Fixed: fixed, Distro: distroName(in)}
	}
	if fixed != "" {
		return &FixedIn{Kind: "fixed", Version: clean(in.ver), Fixed: fixed}
	}
	if len(incl) > 0 {
		l := asc(incl)
		return &FixedIn{Kind: "up_to", Version: clean(in.ver), Fixed: clean(l[len(l)-1])}
	}
	return nil
}

// fixedBranches lists the fix of each release line (the line named by its range's start), for a device whose version
// is missing or unreadable.
func fixedBranches(in swInfo, usable []fixedEntry, outside func(string) bool) *FixedIn {
	type line struct{ label, fixed string }
	var fixes []line
	noFix := map[string]bool{}
	for _, e := range usable {
		label := lineOf(e.r)
		if e.r.EndExcl != "" {
			if outside(e.r.EndExcl) {
				fixes = append(fixes, line{label, e.r.EndExcl})
			}
		} else if e.r.EndIncl != "" {
			noFix[label+"|"+e.r.EndIncl] = true
		}
	}
	slices.SortStableFunc(fixes, func(a, b line) int {
		if c, ok := compareBound(a.fixed, b.fixed); ok {
			return -c
		}
		return 0
	})
	f := &FixedIn{Kind: "branches"}
	if in.given {
		f.Version = clean(in.ver)
	}
	// One entry per fixed release (an iPhone range and an iPadOS range often end at the same one), named by the lowest
	// line that shares it; a line with a fix is not also counted as "no fix named".
	have := map[string]bool{}
	var all []FixedBranch
	for _, l := range fixes { // newest first: the first of a line is its highest fix, the safe one to name
		have[l.label] = true
	}
	for _, l := range fixes {
		if k := len(all) - 1; k >= 0 && all[k].Fixed == clean(l.fixed) {
			if c, ok := compareBound(strings.ReplaceAll(l.label, ".x", ".0"), strings.ReplaceAll(all[k].Branch, ".x", ".0")); ok && c < 0 || all[k].Branch != "" && l.label == "" {
				all[k].Branch = l.label
			}
			continue
		}
		if l.label != "" && slices.ContainsFunc(all, func(b FixedBranch) bool { return b.Branch == l.label }) {
			continue
		}
		all = append(all, FixedBranch{Branch: l.label, Fixed: clean(l.fixed)})
	}
	for k := range noFix {
		if label, _, _ := strings.Cut(k, "|"); label != "" && have[label] {
			delete(noFix, k) // that line has a fix in another range
		}
	}
	if len(all) == 0 {
		return nil
	}
	f.Branches, f.NoFix = all, len(noFix)
	if len(all) > maxFixedBranches {
		f.Branches, f.More = all[:maxFixedBranches], len(all)-maxFixedBranches
	}
	return f
}

// distroName is the distribution the device runs ("Ubuntu", "Debian"), "" when it runs none we know.
func distroName(in swInfo) string {
	if in.osVer == "" {
		return ""
	}
	switch in.os.vendor {
	case "canonical":
		return "Ubuntu"
	case "debian":
		return "Debian"
	}
	return ""
}

var distroMark = regexp.MustCompile(`(?i)ubuntu|[+~.-]deb\d|\.(el|fc)\d`)

// distroMarked says the version string is a distribution package's ("2.4.52-1ubuntu4", "1.1.1n-0+deb11u5", "1.2-3.el9").
func distroMarked(v string) bool { return distroMark.MatchString(v) }

// lineOf names the release line of a range by its start ("7.0.0" -> "7.0"), "" when it has none or it is not a plain
// dotted version.
func lineOf(r VersionRange) string {
	start := r.StartIncl
	if start == "" {
		start = r.StartExcl
	}
	parts := strings.Split(start, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	if len(parts) == 2 && parts[1] == "0" {
		return parts[0] + ".x" // "17.0" is the whole 17 line, not release 17.0
	}
	return parts[0] + "." + parts[1]
}

// GroupFix is the one release that closes every vulnerability of one installed software on a device (D-490, "one upgrade, one line").
// Kind is "fixed" (Fixed is outside the affected range of ALL the vulnerabilities of the software), "none" (NVD's ranges name no
// release that clears them all: the advisory decides), "up_to" (NVD names no fixed release, Fixed is the last affected one) or
// "distro" (the distribution's security updates carry the fix: an agent read it from the package database, or its version carries a
// distribution marker on Ubuntu/Debian). Software is the id of the software row it is about.
type GroupFix struct {
	Kind, Software, Version, Fixed, Distro string
	// Closed holds the CVEs the release closes: for kind fixed every vulnerability of the software (the release is outside all their ranges); otherwise those the device is affected by through a range that has an end.
	Closed map[string]bool
}

// FixedInForAll is FixedInFor for the vulnerabilities of the software of one device. It does not take the highest release
// FixedInFor names for each (a release that fixes one can still be inside the range of another: 26.3 for CVE A, in [26.0, 26.7.1) of
// CVE B), and it is not limited to the ranges the device is inside: it takes the nearest end bound ABOVE the device's version, of any
// range of any of the vulnerabilities, that is outside the affected ranges of all of them (a phone on 18.2 is cleared by 26.7.1 when
// every 18.x and 26.x before it is still inside some range). A vulnerability belongs to the software row it matches (keyedTo), so one
// phone is one group whatever names CISA gives the CVEs. The map is by CVE; a CVE the device is not affected by through a range with
// an end is not in it. A CVE that matches several software rows takes the group that closes the most.
func FixedInForAll(a Asset, vulns []Vuln) map[string]*GroupFix {
	out := map[string]*GroupFix{}
	for _, s := range deviceSoftware(a) {
		in := newSWInfo(s, a.OS)
		if !in.given || !versionKnown(in.ver) {
			continue
		}
		var mine []Vuln
		for _, v := range vulns {
			if keyedTo(s, v) {
				mine = append(mine, v)
			}
		}
		g := groupFixOf(in, mine)
		if _, ok := winDevice(in); ok {
			g = windowsGroupFix(in, mine) // D-546
		}
		if g == nil {
			continue
		}
		g.Software = s.ID
		for cve := range g.Closed {
			if o := out[cve]; o == nil || len(g.Closed) > len(o.Closed) {
				out[cve] = g
			}
		}
	}
	return out
}

func groupFixOf(in swInfo, vulns []Vuln) *GroupFix {
	closed := map[string]bool{}
	var ends []string // every readable end bound of every applicable range: the releases a fix can be
	haveExcl := false
	var parts []fixedParts
	for _, v := range vulns {
		var key []identity
		if n := (identity{vendor: norm(v.Vendor), product: norm(v.Product)}); !isMultiProduct(v.Product) && n.ok() {
			key = []identity{n}
		}
		p := fixedPartsOf(in, v, key)
		parts = append(parts, p)
		for _, e := range p.usable {
			for _, b := range []string{e.r.EndExcl, e.r.EndIncl} {
				if b != "" {
					ends = append(ends, b)
				}
			}
			if t, _ := evalAffected(e.c, e.r, in.ver, in.cpe, in.hasCPE); t == Yes && (e.r.EndExcl != "" || e.r.EndIncl != "") {
				closed[v.CVE] = true
				haveExcl = haveExcl || e.r.EndExcl != ""
			}
		}
	}
	if len(closed) == 0 {
		return nil
	}
	g := &GroupFix{Version: clean(in.ver), Distro: distroName(in), Closed: closed}
	if in.packaged || distroMarked(in.ver) && g.Distro != "" {
		g.Kind = "distro"
		return g
	}
	cmp := func(a, b string) int {
		if c, ok := compareBound(a, b); ok {
			return c
		}
		return 0
	}
	slices.SortStableFunc(ends, cmp)
	for _, x := range ends {
		if c, ok := compareBound(x, in.ver); !ok || c <= 0 {
			continue // not above the device's version
		}
		clears := true
		for _, p := range parts {
			clears = clears && p.outside(x)
		}
		if clears { // it is outside the ranges of all of them, so it closes each, whether or not the device was inside the range yet
			g.Kind, g.Fixed = "fixed", clean(x)
			for _, v := range vulns {
				g.Closed[v.CVE] = true
			}
			return g
		}
	}
	if !haveExcl { // only ranges that end at an affected release: NVD names no fix
		g.Kind, g.Fixed = "up_to", clean(ends[len(ends)-1])
		return g
	}
	g.Kind = "none"
	return g
}
