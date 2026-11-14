package findings

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// Windows by its monthly update (D-546, INV-15). agent-intake gives a Windows PC one operating-system row: the release as NVD
// names it with the patched build and the machine's target ("cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:…:x64:*",
// key microsoft|windows). NVD's Windows entries list each release Microsoft services, with a range that ends at the build of
// the fix ("windows_11_23h2 … < 10.0.22631.5189"). windowsDecide reads an entry against that row:
//
//   - the release's own rows decide by the update revision; a range whose bounds are of another build than the release's line
//     (NVD's CVE-2023-36884 lists windows_10_22h2 < 10.0.19044.3324) is read at that build when it is a sibling's, else it says
//     nothing;
//   - no row of its own: the rows of a sibling release (one code base, the same update revision every month: 24H2/25H2,
//     22H2/23H2, Windows 10 2004…22H2) decide with the device's revision at the sibling's build (NVD's CVE-2025-33073 lists
//     24H2 and not 25H2, which shipped after the fix);
//   - neither: only when every row is a Windows release older than the device's (by build) may the entry be ruled out, and only
//     with a proof (the release came out at least 90 days after CISA listed the flaw, so it carries the fix; or NVD's list has
//     stood a year, D-506) and when NVD names the device's release at all; otherwise a "not checked" finding. A release that is
//     older than one the entry lists stays "not checked", with a sentence: Microsoft lists only the releases it still services, so
//     an unlisted older release may be affected and get no fix (review H1);
//   - a target the device's rows do not list (an arm64 PC, rows for x64 only) proves nothing (review L1); a device whose target is
//     not known is affected when it is inside every target's range, outside when outside every one (review M1).
//
// Nothing here closes on a guess: every No is a proof (proofRange or proofRelease), and everything else is a finding.

// winDev is a device's Windows release row.
type winDev struct {
	rel    winrel.Release
	ubr    string // update revision, "4460"
	rev    int    // the same as a number
	target string // "x64", "x86", "arm64"; "" when not known
}

var (
	winVersionRE = regexp.MustCompile(`^10\.0\.([1-9][0-9]{4})\.([1-9][0-9]{0,5})$`)
	winBoundRE   = regexp.MustCompile(`^10\.0\.([1-9][0-9]{4})\.([0-9]{1,6})$`) // a bound without the revision is not read (review r1 LOW-2)
)

// winDevice reads the software as a Windows release row: an operating-system CPE of a release core/winrel lists and a version of
// that release's build with its update revision. false otherwise (a person's "Windows 11", a scan's guess).
func winDevice(in swInfo) (winDev, bool) {
	if !in.hasCPE {
		return winDev{}, false
	}
	p, ok := windowsProduct(in.cpe)
	if !ok {
		return winDev{}, false
	}
	rel, ok := winrel.ByProduct(p)
	m := winVersionRE.FindStringSubmatch(strings.TrimSpace(in.ver))
	if !ok || m == nil || m[1] != strconv.Itoa(rel.Build) {
		return winDev{}, false
	}
	n, _ := strconv.Atoi(m[2])
	d := winDev{rel: rel, ubr: m[2], rev: n}
	if t, ok := in.cpe.TargetHW.Literal(); ok && in.cpe.TargetHW.Kind == Value {
		d.target = t
	}
	return d, true
}

// windowsProduct is the product of an operating-system CPE of Microsoft Windows as NVD writes it ("windows_11_23h2"); false
// otherwise.
func windowsProduct(c CPE) (string, bool) {
	cv, okV := c.Vendor.Literal()
	cp, okP := c.Product.Literal()
	if c.Part.Kind != Value || c.Part.Value != "o" || !okV || !okP || norm(cv) != "microsoft" || !strings.HasPrefix(cp, "windows") {
		return "", false
	}
	return cp, true
}

// winOld are the Windows releases before 10 (6.x and older): NVD names them without build ranges, and every 10.0 build is newer.
var winOld = map[string]bool{
	"windows_2000": true, "windows_xp": true, "windows_vista": true, "windows_7": true, "windows_8": true, "windows_8.1": true,
	"windows_rt": true, "windows_rt_8.1": true, "windows_server_2003": true, "windows_server_2008": true, "windows_server_2012": true,
}

// winFamilyVersions are the releases of the family forms NVD used before it named each release ("windows_10:1607"; "-" is the
// first release, 1507 for Windows 10 and 21H2 for Windows 11): the version → build, client.
var winFamilyVersions = map[string]map[string]int{
	"windows_10": {"-": 10240, "1507": 10240, "1511": 10586, "1607": 14393, "1703": 15063, "1709": 16299, "1803": 17134, "1809": 17763,
		"1903": 18362, "1909": 18363, "2004": 19041, "20h2": 19042, "21h1": 19043, "21h2": 19044, "22h2": 19045},
	"windows_11":     {"-": 22000, "21h2": 22000, "22h2": 22621, "23h2": 22631, "24h2": 26100, "25h2": 26200},
	"windows_server": {"1709": 16299, "1803": 17134, "1903": 18362, "1909": 18363, "2004": 19041, "20h2": 19042},
}

// winListed is what one NVD row of an entry says about which Windows release it names.
type winListed struct {
	build   int  // the release's build; 0 when not known
	server  bool // a server release
	old     bool // a release before Windows 10
	product string
	family  string // "windows", "windows_10", "windows_11", "windows_server": a family row whose release is not known
}

// winListedOf reads row c; false when it is not a Windows row.
func winListedOf(c CPE) (winListed, bool) {
	p, ok := windowsProduct(c)
	if !ok {
		return winListed{}, false
	}
	l := winListed{product: p}
	if r, ok := winrel.ByProduct(p); ok {
		l.build, l.server = r.Build, r.Server
		return l, true
	}
	if winOld[p] {
		l.old, l.server = true, strings.Contains(p, "server")
		return l, true
	}
	if vers, ok := winFamilyVersions[p]; ok || p == "windows" {
		v, lit := c.Version.Literal()
		if c.Version.Kind == NA {
			v, lit = "-", true
		}
		if b := vers[strings.ToLower(v)]; lit && b > 0 {
			l.build, l.server = b, p == "windows_server"
			return l, true
		}
		l.family = p
	}
	return l, true // a Windows release this table does not know, or a family row of every release
}

// mayBe says whether a row whose release is not known may name the device's: a family row of its kind ("windows", windows_10
// with any version for a Windows 10 PC). A release the table does not know is another one: the device's own name is known.
func (l winListed) mayBe(d winDev) bool {
	switch l.family {
	case "windows":
		return true
	case "windows_10":
		return !d.rel.Server && d.rel.Build < 22000
	case "windows_11":
		return !d.rel.Server && d.rel.Build >= 22000
	case "windows_server":
		return d.rel.Server
	}
	return false
}

// sameLine says whether a client build is one code base with the device's release (the same update revision every month).
func (d winDev) sameLine(build int) bool {
	if build == d.rel.Build {
		return true
	}
	if d.rel.Server {
		return false
	}
	r, ok := winrel.ByBuild(build, false)
	return ok && r.Line == d.rel.Line
}

// winVerdict is windowsDecide's answer.
type winVerdict struct {
	t      Tri
	within VersionRange // the range that matched, at the device's build (for the evidence and fixed_in)
	proof  proofKind
	via    string // the sibling releases whose rows decided ("Windows 11 24H2"); "" when the device's own did
	build  int    // Yes: the build of the range that matched (a sibling's when via is set)
	note   string // the evidence of an Unknown that says more than "not checked", or of a proofRelease close
}

// windowsDecide reads entry v against a Windows release row (see the top of this file). ok is false when the software is not one,
// or the entry is not an NVD Windows entry this reads (no NVD data, "Multiple Products", ranges from CVE.org): the ordinary rules
// decide. named says whether NVD names the device's release in any entry of the list (MatchAsset, review H2).
func windowsDecide(in swInfo, v Vuln, named bool, now time.Time) (winVerdict, bool) {
	d, ok := winDevice(in)
	if !ok || len(v.Affected) == 0 || isMultiProduct(v.Product) || v.RangesFrom != "" {
		return winVerdict{}, false
	}
	var own, sib []fixedEntry
	var sibNames []string
	undecidable, allWindows := false, true
	newest := 0 // the highest build of the other releases the entry lists
	var others []string
	for _, af := range v.Affected {
		c, err := ParseCPE(af.CPE)
		if err != nil || c.Part.Kind == NA {
			undecidable, allWindows = true, false
			continue
		}
		l, isWin := winListedOf(c)
		switch {
		case !isWin:
			allWindows = false
			_, okV := c.Vendor.Literal()
			_, okP := c.Product.Literal()
			undecidable = undecidable || !okV || !okP // ANY vendor or product: it may be this device
		case l.build == 0 && !l.old:
			allWindows = false
			undecidable = undecidable || l.mayBe(d)
		case l.old:
			others = appendOnce(others, l.product)
		case l.server == d.rel.Server && l.build == d.rel.Build:
			own = append(own, fixedEntry{c, af.Range})
		case l.server == d.rel.Server && !l.server && d.sameLine(l.build):
			sib = append(sib, fixedEntry{c, af.Range})
			if r, ok := winrel.ByBuild(l.build, false); ok {
				sibNames = appendOnce(sibNames, r.Display)
			}
		default:
			newest = max(newest, l.build)
			others = appendOnce(others, l.product)
		}
	}
	rows, via := own, ""
	if len(rows) == 0 && len(sib) > 0 {
		rows, via = sib, orList(sibNames)
	}
	if len(rows) > 0 {
		w := winRows(rows, d, v)
		w.via = via
		if w.t == No && undecidable {
			w.t, w.proof = Unknown, proofNone // another row may be this release and cannot be read
		}
		return w, true
	}
	switch {
	case !allWindows || undecidable || newest == d.rel.Build:
		return winVerdict{t: Unknown}, true // as before D-546: not checked
	case newest > d.rel.Build:
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s for other Windows releases (%s), newer ones among them, but not for %s. Microsoft lists only the releases it still services, so an older release it no longer updates may be affected and get no fix: check that %s is still supported.",
			v.CVE, winNames(others), d.rel.Display, d.rel.Display)}, true
	case !named:
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s), and has not named %s in any entry yet, so its data cannot tell: compare with Microsoft's advisory.",
			v.CVE, d.rel.Display, winNames(others), d.rel.Display)}, true
	}
	// Every release the entry lists is older than the device's. Both proofs are about the public release: a preview or OEM build below
	// its first public revision (24H2 shipped on Copilot+ PCs as 26100.712 months before its 26100.1742) is neither "out after the
	// fix" nor a release NVD's list was about, so it proves nothing (review r1 M1). The release date proves only with that revision known.
	if d.rel.GARev > 0 && d.rev < d.rel.GARev {
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s), but this machine runs a build from before %s's first public one (10.0.%d.%d), a preview or early build that may lack the fix: install the current updates.",
			v.CVE, d.rel.Display, winNames(others), d.rel.Display, d.rel.Build, d.rel.GARev)}, true
	}
	shipped := v.Source != SourceVulnCheck && !v.DateAdded.IsZero() && !v.DateAdded.Add(winShipMargin).After(d.rel.GA) && d.rel.GARev > 0
	if shipped || settled(v, now) {
		why := fmt.Sprintf("%s came out on %s, after %s listed the flaw (%s), so it carries the fix", d.rel.Display, d.rel.GA.Format("2 Jan 2006"), v.listName(), v.DateAdded.Format("2 Jan 2006"))
		if !shipped {
			why = fmt.Sprintf("NVD's list has stood for over a year since %s listed it", v.listName())
		}
		return winVerdict{t: No, proof: proofRelease, note: fmt.Sprintf("Not affected: NVD lists %s only for Windows releases older than this device's %s (%s), and %s. Vedette closed this by itself and reopens it if a later match says the device is affected.",
			v.CVE, d.rel.Display, winNames(others), why)}, true
	}
	return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s). A later release usually carries the fix, but NVD's list for this entry is less than a year old: compare with Microsoft's advisory.",
		v.CVE, d.rel.Display, winNames(others))}, true
}

// winShipMargin: a release that came out this long after CISA listed a flaw carries its fix. CISA lists a flaw when there is a
// remediation (https://www.cisa.gov/known-exploited-vulnerabilities, "clear remediation guidance"); the margin covers a listing on
// mitigations whose update came a month or two later.
const winShipMargin = 90 * 24 * time.Hour

// winRows decides the device's own (or its siblings') rows. A row of another target than the device's is skipped; when only such
// rows are left, nothing is proved (review L1). A device whose target is not known is Yes when inside every row, No when outside every
// row (review M1).
func winRows(rows []fixedEntry, d winDev, v Vuln) winVerdict {
	var ts []Tri
	var targets []string
	var yes *VersionRange
	yesBuild := 0
	for _, e := range rows {
		tgt, lit := e.c.TargetHW.Literal()
		if e.c.TargetHW.Kind == Value && lit {
			targets = appendOnce(targets, tgt)
			if d.target != "" && tgt != d.target {
				continue
			}
		}
		t, r, b := winEval(e.c, e.r, d)
		ts = append(ts, t)
		if t == Yes && (yes == nil || widerEnd(r, *yes)) {
			yes, yesBuild = &r, b
		}
	}
	every := func(want Tri) bool { return !slices.ContainsFunc(ts, func(t Tri) bool { return t != want }) }
	switch {
	case len(ts) == 0:
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s for %s on %s only, and this device is %s, so NVD's data cannot tell: compare with Microsoft's advisory.",
			v.CVE, d.rel.Display, orList(targets), d.target)}
	case yes != nil && (d.target != "" || every(Yes)):
		return winVerdict{t: Yes, within: *yes, build: yesBuild}
	case every(No):
		return winVerdict{t: No, proof: proofRange}
	}
	return winVerdict{t: Unknown}
}

// winEval reads one row of the device's release line with its update revision. The bounds must be builds of that line
// ("10.0.22631.5189" for a 22621 or 22631 device): the device's revision is compared at the bound's build, and the range that
// matched is given at the device's build, with the bound's build. Anything else the row pins or bounds (another build, a bound
// without the revision, "-", an update) is Unknown, and so is a release row of every version with no range: for a Windows release
// that means NVD recorded no fixed build, not that no update fixes it (review r1 LOW-1).
func winEval(c CPE, r VersionRange, d winDev) (Tri, VersionRange, int) {
	for _, a := range []Attr{c.Update, c.Edition, c.Language, c.SWEdition, c.TargetSW, c.Other} {
		if a.Kind != Any {
			return Unknown, r, 0
		}
	}
	if r.IsZero() {
		lit, ok := c.Version.Literal()
		if c.Version.Kind != Value || !ok {
			return Unknown, r, 0 // every version, or "-": no build to compare (review L2: windows_server_2019:- stays not checked)
		}
		r = VersionRange{StartIncl: lit, EndIncl: lit}
	} else if c.Version.Kind != Any {
		return Unknown, r, 0
	}
	build := 0
	for _, b := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
		if b == "" {
			continue
		}
		m := winBoundRE.FindStringSubmatch(b)
		if m == nil {
			return Unknown, r, 0
		}
		n, _ := strconv.Atoi(m[1])
		if build != 0 && n != build || !d.sameLine(n) {
			return Unknown, r, 0
		}
		build = n
	}
	t := r.Contains(fmt.Sprintf("10.0.%d.%s", build, d.ubr))
	at := func(b string) string {
		if b == "" {
			return ""
		}
		return strings.Replace(b, fmt.Sprintf("10.0.%d", build), fmt.Sprintf("10.0.%d", d.rel.Build), 1)
	}
	return t, VersionRange{StartIncl: at(r.StartIncl), StartExcl: at(r.StartExcl), EndIncl: at(r.EndIncl), EndExcl: at(r.EndExcl)}, build
}

// winNamed says whether any entry of the list names the release NVD calls product (review H2: a release NVD has never named, or a
// name this table has wrong, is never ruled out by the entries that name only others).
func winNamed(vulns []Vuln, product string) bool {
	needle := ":microsoft:" + product + ":"
	for _, v := range vulns {
		for _, af := range v.Affected {
			if strings.Contains(af.CPE, needle) {
				return true
			}
		}
	}
	return false
}

// winCovers says whether s is covered by the device's Windows release row (review M4): a row that is no release row and whose
// every KEV key is CISA's "Microsoft | Windows" (a person's "Windows 11", added as D-504 advised before the agent came). The
// agent's row reads the patched build; the other would keep every Windows entry "not checked" next to it.
func winCovers(s Software) bool {
	if len(s.KevKeys) == 0 || winRow(s) {
		return false
	}
	for _, k := range s.KevKeys {
		if NormalizeKevKey(k) != "microsoft|windows" {
			return false
		}
	}
	return true
}

// winRow says whether s is a Windows release row (winDevice).
func winRow(s Software) bool {
	_, ok := winDevice(newSWInfo(s, ""))
	return ok
}

// withoutCoveredWindows drops the rows the device's Windows release row covers (winCovers); a device without one keeps every row.
func withoutCoveredWindows(sws []Software) []Software {
	if !slices.ContainsFunc(sws, winRow) {
		return sws
	}
	out := make([]Software, 0, len(sws))
	for _, s := range sws {
		if !winCovers(s) {
			out = append(out, s)
		}
	}
	return out
}

// winFix is what installing the fix of a Yes takes (review r1 M2). "fixed": the month's build at the device's build, which Windows
// Update offers. "feature_update": the range came from a later sibling release NVD lists and the device's release is not listed, so
// Microsoft no longer services it: no monthly update fixes it, and fixed is the sibling's build (branch names the sibling). "esu":
// the fix is above the last revision the release gets without Extended Security Updates (Windows 10 22H2 after October 2025).
func winFix(w winVerdict, d winDev) (kind, fixed, branch string) {
	end := w.within.EndExcl
	if w.via != "" && w.build > d.rel.Build {
		r, _ := winrel.ByBuild(w.build, false)
		return "feature_update", strings.Replace(end, fmt.Sprintf("10.0.%d.", d.rel.Build), fmt.Sprintf("10.0.%d.", w.build), 1), r.Display
	}
	if m := winBoundRE.FindStringSubmatch(end); m != nil && d.rel.LastFreeRev > 0 {
		if n, _ := strconv.Atoi(m[2]); n > d.rel.LastFreeRev {
			return "esu", end, d.rel.Display
		}
	}
	return "fixed", end, ""
}

// windowsFixedIn is FixedInFor of a Windows release row (winFix). ok is false when windowsDecide does not read the entry.
func windowsFixedIn(in swInfo, v Vuln) (*FixedIn, bool) {
	w, ok := windowsDecide(in, v, true, time.Time{})
	if !ok {
		return nil, false
	}
	d, _ := winDevice(in)
	switch {
	case w.t != Yes:
		return nil, true
	case w.within.EndExcl != "":
		kind, fixed, branch := winFix(w, d)
		f := &FixedIn{Kind: kind, Version: clean(in.ver), Fixed: clean(fixed), Branches: []FixedBranch{}, Source: FixedInSource}
		if branch != "" {
			f.Branches = []FixedBranch{{Branch: clean(branch), Fixed: clean(fixed)}}
		}
		return f, true
	case w.within.EndIncl != "":
		return &FixedIn{Kind: "up_to", Version: clean(in.ver), Fixed: clean(w.within.EndIncl), Branches: []FixedBranch{}, Source: FixedInSource}, true
	}
	return nil, true
}

// windowsGroupFix is groupFixOf for a Windows release row: one monthly update fixes every entry it is affected by through a range
// with an end, the latest of those ends (kind fixed, or esu when that needs Extended Security Updates). When one of them can only
// be fixed by a feature update, the line is that (kind feature_update, Fixed the release that has the fix): no monthly update
// clears the device. nil when none.
func windowsGroupFix(in swInfo, vulns []Vuln) *GroupFix {
	d, _ := winDevice(in)
	closed := map[string]bool{}
	fixed, kind, branch := "", "fixed", ""
	for _, v := range vulns {
		w, ok := windowsDecide(in, v, true, time.Time{})
		if !ok || w.t != Yes || w.within.EndExcl == "" {
			continue
		}
		closed[v.CVE] = true
		k, _, b := winFix(w, d)
		switch {
		case k == "feature_update":
			kind, branch = k, b
		case k == "esu" && kind == "fixed":
			kind = k
		}
		if c, ok := compareBound(w.within.EndExcl, fixed); fixed == "" || ok && c > 0 {
			fixed = w.within.EndExcl
		}
	}
	if len(closed) == 0 {
		return nil
	}
	if kind == "feature_update" {
		fixed = branch
	}
	return &GroupFix{Kind: kind, Version: clean(in.ver), Fixed: clean(fixed), Closed: closed}
}

// winNames names releases for a sentence: "windows 10 1809, windows 11 23h2 and 2 more".
func winNames(products []string) string {
	names := make([]string, 0, len(products))
	for _, p := range products {
		if r, ok := winrel.ByProduct(p); ok {
			names = append(names, r.Display)
		} else {
			names = append(names, strings.ReplaceAll(p, "_", " "))
		}
	}
	if len(names) > 3 {
		return clean(strings.Join(names[:3], ", ")) + fmt.Sprintf(" and %d more", len(names)-3)
	}
	return clean(strings.Join(names, ", "))
}

func appendOnce(l []string, s string) []string {
	if slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}
