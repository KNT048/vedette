package findings

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// FixedIn is what NVD's affected versions say about the fix of one finding, for the device it is on: the
// "What to do" part of a finding page. It is only ever built from a range with an end bound; no range, no FixedIn,
// and the page keeps CISA's required action and the vendor's advisory.
type FixedIn struct {
	// Kind is "fixed" (the device's version is inside a range that ends before Fixed, and Fixed is outside every
	// range that applies), "up_to" (inside a range that ends at Fixed, itself affected: NVD names no fixed release),
	// "branches" (the version is not known, or not readable), "end_listed" (inside a range that ends before Fixed, but NVD lists
	// releases of Fixed itself as affected: Fixed is not a fix, the advisory names it, M2-4) or "distro" (a package of the distribution, whose security
	// updates carry the fix under their own numbers: an agent read it from the device's package database, or the version
	// carries a distribution marker, "2.4.52-1ubuntu4", on Ubuntu/Debian). A Windows release row may also give "feature_update"
	// (the device's release no longer gets monthly updates: Fixed is the build of Branches[0].Branch, a later release of its line,
	// that has the fix) or "esu" (Fixed is above the last revision the release gets without Extended Security Updates).
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
	// DistroFixed, DistroRelease and DistroPro (kind distro only): the version of the distribution's package that fixes
	// the CVE on the device's release ("1:9.6p1-3ubuntu13.5" for Ubuntu "24.04"), and whether only Ubuntu Pro has it; Version
	// is then the device's full package version. "" when the distribution's data does not say.
	DistroFixed   string `json:"distro_fixed"`
	DistroRelease string `json:"distro_release"`
	DistroPro     bool   `json:"distro_pro"`
	Source        string `json:"source"` // FixedInSource, FixedInSourceCVEOrg, or DistroSource when DistroFixed is set
}

// FixedBranch is the fix of one release line, the line named by the start of its range ("7.4" -> "7.4.3"); Branch is
// "" when the range has no start or it is not a plain dotted version.
type FixedBranch struct {
	Branch string `json:"branch"`
	Fixed  string `json:"fixed"`
}

// FixedInSource labels where the fixed versions come from; FixedInSourceCVEOrg when NVD has none and they come from the
// CNA's CVE.org record.
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
// the one with the most definite answer wins. When the matcher matches the entry on a row only NVD's list ties to it (viaNVD,
// #910: a Chrome row for CISA's "Chromium V8"), the fix is that row's, the one the finding is about.
func FixedInFor(a Asset, v Vuln) *FixedIn { return newDevRows(a).fixedInFor(v) }

// devRows is a device's software as the fix readers read it, built once per device: deviceSoftware's rows, each row's swInfo (with
// the device's OS) and, when a reader needs them, each row's vendors (rowVendors). RowFixes, FixedInForAll and FixedInFor answer from it
// instead of rebuilding the rows (and the Windows coverage filter) for every finding of the device.
type devRows struct {
	a       Asset
	sws     []Software
	infos   []swInfo
	keys    [][]string // rowKeys of each row
	vendors [][]string // rowVendors of each row; nil until nvdRows needs them
}

func newDevRows(a Asset) *devRows {
	sws := deviceSoftware(a)
	infos, keys := make([]swInfo, len(sws)), make([][]string, len(sws))
	for i, s := range sws {
		infos[i], keys[i] = newSWInfo(s, a.OS), rowKeys(s)
	}
	return &devRows{a: a, sws: sws, infos: infos, keys: keys}
}

// rowVendors is rowVendors of every row, computed once.
func (d *devRows) rowVendors() [][]string {
	if d.vendors == nil {
		d.vendors = make([][]string, len(d.sws))
		for i, s := range d.sws {
			d.vendors[i] = rowVendors(s)
		}
	}
	return d.vendors
}

// fixedInFor is FixedInFor on the device's rows read once.
func (d *devRows) fixedInFor(v Vuln) *FixedIn {
	if id, ok := d.nvdRows([]Vuln{v})[v.CVE]; ok {
		for i, s := range d.sws {
			if s.ID != id {
				continue
			}
			in := d.infos[i]
			if f, ok := windowsFixedIn(in, v); ok {
				return f
			}
			return fixedInSoftware(in, v, nil)
		}
	}
	key := keyIDs(v)
	var best *FixedIn
	rank := func(f *FixedIn) int {
		switch {
		case f == nil:
			return 0
		case f.DistroFixed != "": // the distribution's own fixed package: the most definite answer
			return 7
		case f.Kind == "fixed":
			return 6
		case f.Kind == "up_to":
			return 5
		case f.Kind == "end_listed": // M2-4, review r1 L3: the device's own version decides, above a versionless row's branches
			return 4
		case f.Kind == "distro":
			return 3
		case f.Version == "":
			return 2
		}
		return 1
	}
	vk := keyOf(v)
	for i := range d.sws {
		if !keyedBy(d.keys[i], vk) {
			continue
		}
		in := d.infos[i]
		if f, ok := windowsFixedIn(in, v); ok {
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
	listed       func(string) bool // some applicable entry lists the version as affected (M2-4: a range's end that is itself affected)
}

func fixedPartsOf(in swInfo, v Vuln, key []identity) fixedParts {
	var ents []fixedEntry // every entry that applies to the software, whatever its range
	for _, af := range v.Affected {
		c, err := af.cpe()
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
		// update NA is the release without an update: its range reads as one whose update is ANY
		if !e.r.IsZero() && e.c.Version.Kind == Any && (e.c.Update.Kind == Any || e.c.Update.Kind == NA) && boundsReadable(e.r) {
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
	listed := func(x string) bool {
		for _, e := range ents {
			if t, _ := evalAffected(e.c, e.r, x, in.cpe, in.hasCPE); t == Yes {
				return true
			}
		}
		return false
	}
	return fixedParts{ents, usable, outside, listed}
}

func fixedInSoftware(in swInfo, v Vuln, key []identity) *FixedIn {
	if d, ok := distroVerdict(in, v); ok { // The distribution's word on its own package
		if d.kind != distroNeeded {
			return nil // fixed here or not affected: nothing to install
		}
		return &FixedIn{Kind: "distro", Version: clean(in.pkgVer), Distro: d.name, DistroFixed: clean(d.fixed), DistroRelease: d.release,
			DistroPro: d.pro, Branches: []FixedBranch{}, Source: DistroSource(d.name)}
	}
	p := fixedPartsOf(in, v, key)
	usable, outside := p.usable, p.outside
	// A package of the distribution: an agent read it from the package database, a person gave its package release, or its version
	// says so. A row whose origin is not known keeps the upstream answer with the condition (Distro below).
	distro := in.given && (in.pkgBuilt() || distroMarked(in.ver) && distroName(in) != "")
	var f *FixedIn
	if in.given && versionKnown(in.ver) {
		f = fixedForVersion(in, usable, outside, distro)
		if f != nil && f.Kind == "end_listed" && !p.listed(f.Fixed) {
			f = nil // the end is not proved affected (an entry Vedette cannot judge): say nothing rather than "not the fix"
		}
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
	// M2-4: every end is itself affected through another entry (Junos: "before 20.4", then 20.4:r1 … 20.4:r3-s8 one by one): the
	// end is where NVD's release-by-release list starts, not a fix, and the page says so instead of "fixed version not known".
	// The highest end, as the evidence quotes the widest range (decide, review r1 L2).
	l := asc(excl)
	return &FixedIn{Kind: "end_listed", Version: clean(in.ver), Fixed: clean(l[len(l)-1])}
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

// GroupFix is the one release that closes every vulnerability of one installed software on a device ("one upgrade, one line").
// Kind is "fixed" (Fixed is outside the affected range of ALL the vulnerabilities of the software), "none" (NVD's ranges name no
// release that clears them all: the advisory decides), "up_to" (NVD names no fixed release, Fixed is the last affected one) or
// "distro" (the distribution's security updates carry the fix: an agent read it from the package database, or its version carries a
// distribution marker on Ubuntu/Debian). A Windows release row may give "feature_update" (no monthly update clears it: Fixed
// names the later release of its line that has the fixes; the device needs a feature update) or "esu" (Fixed needs Extended Security
// Updates). Software is the id of the software row it is about.
type GroupFix struct {
	Kind, Software, Version, Fixed, Distro string
	// Closed holds the CVEs the release closes: for kind fixed every vulnerability of the software (the release is outside all their ranges); otherwise those the device is affected by through a range that has an end.
	Closed map[string]bool
	// Ranged holds the CVEs this software itself is inside a range with an end for (Closed before the widening of kind fixed): the
	// only ones the update is proved to fix. A CVE with no range for this software (no NVD data, another product of a "Multiple
	// Products" entry, a range on another row) is not in it.
	Ranged map[string]bool
	// NVDLag (a Windows release's cumulative update, winLatest): Fixed is the newest monthly update Microsoft lists for the release,
	// newer than the update that carries the highest fixed build NVD names. It fixes Closed and the CVEs of the newer updates NVD has
	// not analysed yet, so a count of Closed is a floor.
	NVDLag bool
	// KB is the KB number of Fixed when Microsoft's release information lists that build (a Windows release); "" otherwise.
	KB string
}

// nvdRows is, by CVE, the software row the matcher matches an entry of vulns on when no KEV key of that row reaches it (viaNVD,
// #910): only that row's fix is the finding's.
func (d *devRows) nvdRows(vulns []Vuln) map[string]string {
	have := make(map[string]bool, len(vulns))
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		have[v.CVE], byCVE[v.CVE] = true, v
	}
	sws := d.sws
	need := false // a row the matcher may match through NVD's list; else no need to run it
	for i, named := range nvdCandidatesOf(d.rowVendors(), vulns) {
		for vi := range named {
			need = need || !keyedBy(d.keys[i], keyOf(vulns[vi]))
		}
	}
	if !need {
		return nil
	}
	out := map[string]string{}
	for _, m := range MatchAsset(d.a, vulns, have, time.Time{}).Existing {
		i := slices.IndexFunc(sws, func(s Software) bool { return s.ID == m.SoftwareID })
		if i >= 0 && !keyedBy(d.keys[i], keyOf(byCVE[m.CVE])) {
			out[m.CVE] = m.SoftwareID
		}
	}
	return out
}

// FixedInForAll is FixedInFor for the vulnerabilities of the software of one device. It does not take the highest release
// FixedInFor names for each (a release that fixes one can still be inside the range of another: 26.3 for CVE A, in [26.0, 26.7.1) of
// CVE B), and it is not limited to the ranges the device is inside: it takes the nearest end bound ABOVE the device's version, of any
// range of any of the vulnerabilities, that is outside the affected ranges of all of them (a phone on 18.2 is cleared by 26.7.1 when
// every 18.x and 26.x before it is still inside some range). A vulnerability belongs to the software row it is keyed to, or the one the
// matcher matches it on through NVD's list (nvdRows, #910), so one phone is one group whatever names CISA gives the CVEs. The map is by
// CVE; a CVE the device is not affected by through a range with an end is not in it. A CVE that matches several software rows takes the
// group that closes the most.
func FixedInForAll(a Asset, vulns []Vuln) map[string]*GroupFix {
	return newDevRows(a).fixedInForAll(vulns)
}

// fixedInForAll is FixedInForAll on the device's rows read once.
func (d *devRows) fixedInForAll(vulns []Vuln) map[string]*GroupFix {
	out := map[string]*GroupFix{}
	byNVD := d.nvdRows(vulns)
	vks := make([]entryKey, len(vulns))
	for i, v := range vulns {
		vks[i] = keyOf(v)
	}
	for i, s := range d.sws {
		in := d.infos[i]
		if !in.given || !versionKnown(in.ver) {
			continue
		}
		var mine []Vuln
		nvd := map[string]bool{} // the CVEs only NVD's list ties to the row, which the matcher matches on it (#910)
		for vi, v := range vulns {
			switch {
			case keyedBy(d.keys[i], vks[vi]):
				mine = append(mine, v)
			case byNVD[v.CVE] == s.ID:
				mine = append(mine, v)
				nvd[v.CVE] = true
			}
		}
		g := groupFixOf(in, mine, nvd)
		if _, ok := winDevice(in); ok {
			g = windowsGroupFix(in, mine, time.Time{})
		}
		if g == nil {
			continue
		}
		g.Software = s.ID
		for cve := range g.Closed {
			// A group whose own software is inside a ranged entry for the CVE comes first (review r2 #1: a widened group must not
			// take a CVE from the row whose range it is), then the one that closes the most.
			if o := out[cve]; o == nil || g.Ranged[cve] && !o.Ranged[cve] || g.Ranged[cve] == o.Ranged[cve] && len(g.Closed) > len(o.Closed) {
				out[cve] = g
			}
		}
	}
	return out
}

// groupFixOf is the group of vulns on one row; nvd holds those only NVD's list ties to it (#910), read without CISA's key.
func groupFixOf(in swInfo, vulns []Vuln, nvd map[string]bool) *GroupFix {
	closed := map[string]bool{}
	var ends []string // every readable end bound of every applicable range: the releases a fix can be
	haveExcl := false
	var parts []fixedParts
	for _, v := range vulns {
		key := keyIDs(v)
		if nvd[v.CVE] {
			key = nil
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
	g := &GroupFix{Version: clean(in.ver), Distro: distroName(in), Closed: closed, Ranged: maps.Clone(closed)}
	if in.pkgBuilt() || distroMarked(in.ver) && g.Distro != "" {
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

// RowFix is FindingRow.fix: the one update that fixes a finding together with the other open findings of the same software on
// the same device, so the list can show one item ("Install the latest cumulative update for Windows Server 2025 (from build 26100.1742
// to 26100.2314 or later): fixes 44 exploited vulnerabilities") instead of one row per CVE. Only an update a person can install: GroupFix kinds fixed,
// esu, feature_update and distro (none and up_to name no release).
type RowFix struct {
	Group    string `json:"group"`    // "<device id>/<software id>": the findings with the same group take the same update
	Kind     string `json:"kind"`     // fixed, esu, feature_update or distro (GroupFix.Kind)
	Windows  bool   `json:"windows"`  // a Windows release row: the update is the monthly cumulative update of Windows Update
	Software string `json:"software"` // the software row's display name
	Version  string `json:"version"`  // the installed version
	Fixed    string `json:"fixed"`    // the release or build that fixes them all (feature_update: the release to move to); "" for distro
	Distro   string `json:"distro"`   // distro: "Ubuntu" or "Debian", "" for the distribution's
	Pro      bool   `json:"pro"`      // distro: the fix of at least one of them is in Ubuntu Pro (ESM) only
	// SoftwareID is the id of the software row (GroupFix.Software), so DeviceUpdates can name the row an update is for. Not in the API.
	SoftwareID string `json:"-"`
	// KB is GroupFix.KB, for the sentence of To fix and the assistant (updateSentence). Not in the API.
	KB string `json:"-"`
}

// RowFixes is FixedInForAll as FindingRow.fix, by CVE, for the vulnerabilities of a device's open findings (vulns: only those, as the
// report does, so a release is named against what the device has).
func RowFixes(a Asset, vulns []Vuln) map[string]*RowFix {
	d := newDevRows(a)
	groups := d.fixedInForAll(vulns)
	if len(groups) == 0 {
		return nil
	}
	row := map[string]int{} // software id -> its row (the last of an id, as a map of the rows keeps it)
	for i, s := range d.sws {
		row[s.ID] = i
	}
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	out := make(map[string]*RowFix, len(groups))
	pro := map[string]bool{} // group -> a member's fix is in Ubuntu Pro only
	for cve, g := range groups {
		switch g.Kind {
		case "fixed", "esu", "feature_update", "distro":
		default:
			continue
		}
		// Review r1 #1, r2 #1: only a CVE the group's own software is inside a range with an end for (GroupFix.Ranged). groupFixOf
		// widens a "fixed" release to every entry of the software, also one NVD has no data for, that lists other products or
		// whose range is on another row of the device: those keep their own row, the update proves nothing about them.
		if !g.Ranged[cve] {
			continue
		}
		var s Software
		var in swInfo
		if i, ok := row[g.Software]; ok {
			s, in = d.sws[i], d.infos[i]
		} else {
			in = newSWInfo(s, a.OS)
		}
		_, win := winDevice(in)
		group := a.ID + "/" + g.Software
		if g.Kind == "distro" {
			if f := d.fixedInFor(byCVE[cve]); f != nil && f.DistroPro {
				pro[group] = true
			}
		}
		out[cve] = &RowFix{Group: group, SoftwareID: g.Software, Kind: g.Kind, Windows: win, Software: clean(s.Display), Version: g.Version, Fixed: g.Fixed, Distro: g.Distro, KB: g.KB}
	}
	for _, f := range out {
		f.Pro = pro[f.Group]
	}
	return out
}
