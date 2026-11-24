package findings

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/winrel"
)

// Windows by its monthly update (INV-15). agent-intake gives a Windows PC one operating-system row: the release as NVD
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
//     stood a year) and when NVD names the device's release at all; otherwise a "not checked" finding. A release that is
//     older than one the entry lists stays "not checked", with a sentence: Microsoft lists only the releases it still services, so
//     an unlisted older release may be affected and get no fix (review H1);
//   - a target the device's rows do not list (an arm64 PC, rows for x64 only) proves nothing (review L1); a device whose target is
//     not known is affected when it is inside every target's range, outside when outside every one (review M1);
//   - when the rows above say Unknown or are not there, a flaw of Windows Microsoft published in or before the month of the update the
//     build carries, read from the list's own fix builds, is ruled out (winBuildMonth and winMonthRule below).
//
// Nothing here closes on a guess: every No is a proof (proofRange or proofRelease), and everything else is a finding.

// winDev is a device's Windows release row.
type winDev struct {
	rel winrel.Release
	ubr string // update revision, "4460", as the device reports it
	// rev is the revision the device is compared at: ubr as a number, or, for a hotpatch Microsoft lists for the release, the
	// revision of the same month's monthly update (core/winrel.Baseline): the hotpatch has that month's security fixes, below its build
	rev int
	// hot is the hotpatch the device runs and base the month's update it is compared at (Baseline); hot.Rev == 0 when none
	hot, base winrel.Update
	target    string // "x64", "x86", "arm64"; "" when not known
	ltsc      bool   // the device's OS name says LTSC or LTSB
	cpe       CPE    // the row's own CPE: an NVD row's NA covers only what it leaves unstated (winUnpinned, #901)
}

// ended says Microsoft no longer services the device's release (core/winrel Ended), unless an LTSC/LTSB edition of it still is and
// the device runs one.
func (d winDev) ended() bool { return d.rel.Ended && (!d.rel.LTSC || !d.ltsc) }

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
	os := strings.ToLower(in.osName)
	base, hot, isHot := winrel.Baseline(rel.Build, rel.Server, n)
	if isHot {
		n = base.Rev
	}
	d := winDev{rel: rel, ubr: m[2], rev: n, hot: hot, base: base, ltsc: strings.Contains(os, "ltsc") || strings.Contains(os, "ltsb"), cpe: in.cpe}
	if t, ok := in.cpe.TargetHW.Literal(); ok && in.cpe.TargetHW.Kind == Value {
		d.target = t
	}
	return d, true
}

// winUnknownBuild is the build of a Windows row whose build core/winrel does not know: a Microsoft row with a full Windows 10.0
// version (an Insider Preview build, or a release newer than the table and the releases learned from Microsoft's list) and no CPE of a known release, as agent-intake's
// windowsRow writes it ("Windows (build 26300)"). Vedette cannot place such a build among the releases NVD lists.
func winUnknownBuild(s Software, in swInfo) (int, bool) {
	if _, ok := winDevice(in); ok || productid.Norm(s.Vendor) != "microsoft" {
		return 0, false
	}
	m := winVersionRE.FindStringSubmatch(strings.TrimSpace(in.ver))
	if m == nil {
		return 0, false
	}
	b, _ := strconv.Atoi(m[1])
	if _, ok := winrel.ByBuild(b, false); ok {
		return 0, false
	}
	if _, ok := winrel.ByBuild(b, true); ok {
		return 0, false
	}
	return b, true
}

// winrelNewest is the highest build core/winrel lists.
func winrelNewest() int {
	n := 0
	for _, r := range winrel.Releases() {
		n = max(n, r.Build)
	}
	return n
}

// windowsProduct is the product of an operating-system CPE of Microsoft Windows as NVD writes it ("windows_11_23h2"); false
// otherwise.
func windowsProduct(c CPE) (string, bool) {
	cv, okV := c.Vendor.Literal()
	cp, okP := c.Product.Literal()
	if c.Part.Kind != Value || c.Part.Value != "o" || !okV || !okP || productid.Norm(cv) != "microsoft" || !strings.HasPrefix(cp, "windows") {
		return "", false
	}
	return cp, true
}

// winOld are the Windows releases before 10 (6.x and older): NVD names them without build ranges, and every 10.0 build is newer.
// With NT 4.0, the 9x line and NVD's older name of Server 2003 too, so an entry naming only such releases (CVE-2002-0367:
// windows_2000, windows_nt) is read as "only older releases" by the older-releases proof instead of "not checked".
// windows_nt is old only at an NT version before 10 (winOldNT); "windows_nt:*" or "windows_nt:-" names every NT release, Windows 10, 11
// and Server 2025 (NT 10.0) among them, so it is a family row (review r1 #1 of #801).
var winOld = map[string]bool{
	"windows_2000": true, "windows_xp": true, "windows_vista": true, "windows_7": true, "windows_8": true, "windows_8.1": true,
	"windows_rt": true, "windows_rt_8.1": true, "windows_server_2003": true, "windows_server_2008": true, "windows_server_2012": true,
	"windows_95": true, "windows_98": true, "windows_98se": true, "windows_me": true, "windows_2003_server": true,
}

// winOldNT are the Windows NT versions before Windows 2000 as NVD writes them (windows_nt:4.0).
var winOldNT = map[string]bool{"3.1": true, "3.5": true, "3.51": true, "4.0": true}

// winOldNames are the display names of the winOld releases, for a sentence.
var winOldNames = map[string]string{
	"windows_2000": "Windows 2000", "windows_xp": "Windows XP", "windows_vista": "Windows Vista", "windows_7": "Windows 7", "windows_8": "Windows 8",
	"windows_8.1": "Windows 8.1", "windows_rt": "Windows RT", "windows_rt_8.1": "Windows RT 8.1", "windows_server_2003": "Windows Server 2003",
	"windows_server_2008": "Windows Server 2008", "windows_server_2012": "Windows Server 2012", "windows_95": "Windows 95", "windows_98": "Windows 98",
	"windows_98se": "Windows 98 SE", "windows_me": "Windows Me", "windows_2003_server": "Windows Server 2003", "windows_nt": "Windows NT 4.0 or older",
}

// winRevised are the CVEs whose fix Microsoft later extended to Windows 10 and later releases, after NVD's list named only older ones:
// no "only older releases are listed" proof ever closes them, whatever NVD's list says at the time (review r1 #2 of #801). CVE-2013-3900
// (WinVerifyTrust padding, an opt-in fix, EnableCertPaddingCheck): Microsoft's revised advisory and the CVE.org record name Windows 10,
// 11, Server 2016 to 2025 (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900).
var winRevised = map[string]bool{"CVE-2013-3900": true}

// winGoneProducts are Microsoft products of an old Windows that no Windows 10 or later release ships or can install: a row of one at a
// stated version does not keep a pre-2015 entry "not checked"; the value is its name for a sentence. Interix (Subsystem for
// UNIX-based Applications) is "no longer available" from Windows 8.1 and Server 2012 R2
// (https://learn.microsoft.com/en-us/archive/technet-wiki/10224.posix-and-unix-support-in-windows; CVE-2004-0210). A product still shipped,
// Internet Explorer 11 among them, does keep it.
var winGoneProducts = map[string]string{"interix": "Interix"}

// winListedMargin: the old-list proof waits this long after CISA (or VulnCheck) listed the flaw: a listing of an old CVE is when Microsoft and NVD
// revisit it, so a list naming only old releases may still grow (review r1 #2 of #801).
const winListedMargin = 90 * 24 * time.Hour

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
	if p == "windows_nt" {
		if v, lit := c.Version.Literal(); lit && c.Version.Kind == Value && winOldNT[v] {
			l.old = true
			return l, true
		}
		l.family = "windows" // every NT release, NT 10.0 among them (review r1 #1)
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
		if r, ok := winrel.ByProduct(p + "_" + strings.ToLower(v)); lit && ok && r.Server == (p == "windows_server") && p != "windows" { // windows_11:26h2, a release learned from Microsoft's list
			l.build, l.server = r.Build, r.Server
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
	// later: version evidence behind an Unknown (the finding stands though its basis stays product): winLaterNote's (NVD gives
	// the fix build of the release of the other kind on the same build, and the device's revision is below it), or an ended release NVD's
	// list brackets with releases of its kind before and after it (review r2 H2 of #939: no update brings it the fix).
	later bool
}

// windowsDecide reads entry v against a Windows release row (see the top of this file). ok is false when the software is not one,
// or the entry is not an NVD Windows entry this reads (no NVD data, "Multiple Products", ranges from CVE.org): the ordinary rules
// decide. named says whether NVD names the device's release in any entry of the list (MatchAsset, review H2).
func windowsDecide(in swInfo, v Vuln, named bool, now time.Time) (winVerdict, bool) {
	d, ok := winDevice(in)
	if !ok || len(v.Affected) == 0 || isMultiProduct(v.Product) || v.RangesFrom != "" {
		return winVerdict{}, false
	}
	// A build below the first public build of a release learned from Microsoft's list is an Insider or
	// preview build of that code base (Dev Channel 26300 builds before 26H2's 26300.9457, Canary 28000.x before 26H1's 28000.1575):
	// Microsoft publishes no fixes for it, so neither its own rows nor its siblings' decide
	if winrel.Learned(d.rel) && d.rel.GARev > 0 && d.rev < d.rel.GARev {
		return winVerdict{t: Unknown, note: fmt.Sprintf("This machine runs build 10.0.%d.%s, below the first public build of %s (10.0.%d.%d): an Insider or preview build, for which Microsoft publishes no fixes, so Vedette does not check %s on it.",
			d.rel.Build, d.ubr, d.rel.Display, d.rel.Build, d.rel.GARev, v.CVE)}, true
	}
	var own, sib []fixedEntry
	var sibNames []string
	undecidable, allWindows := false, true
	newest := 0 // the highest build of the other releases the entry lists
	var others []string
	var below, above []string // review r2 H2 of #939: other releases of the device's kind (client or server), by build
	unknownWin := false       // a Windows row of a release the table does not know, or a family row
	successor := false        // a listed release newer by build that may follow the device's (review r1 L3 of #951)
	var pinned []string       // rows of another product at one stated version, no range ("interix 2.2"): the old-list proof only
	looseOther := false       // rows of another product at any version or in a range
	listedYear := 0           // the latest year one of the listed other releases came out (winOldYear for the ones before Windows 10)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			undecidable, allWindows = true, false
			continue
		}
		l, isWin := winListedOf(c)
		switch {
		case !isWin:
			allWindows = false
			vn, okV := c.Vendor.Literal()
			p, okP := c.Product.Literal()
			undecidable = undecidable || !okV || !okP                                                     // ANY vendor or product: it may be this device
			ms := okV && productid.Norm(vn) == "microsoft" && c.Part.Kind == Value && c.Part.Value == "a" // review r2 #4: Microsoft's own application
			if ver, okVer := c.Version.Literal(); ms && okP && winGoneProducts[p] != "" && c.Version.Kind == Value && okVer && af.Range.IsZero() {
				pinned = appendOnce(pinned, winGoneProducts[p]+" "+clean(ver))
			} else {
				looseOther = true
			}
		case l.build == 0 && !l.old:
			allWindows, unknownWin = false, true
			if !l.server && !d.rel.Server && l.family == "" && strings.HasPrefix(l.product, "windows_11_") {
				above = appendOnce(above, l.product) // a release newer than the table (windows_11_26h1)
			}
			undecidable = undecidable || l.mayBe(d)
		case l.old:
			others = appendOnce(others, l.product)
			listedYear = max(listedYear, winOldYear)
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
			// a release learned from Microsoft's list on another client line (26H1, 28000, for new devices only) does not follow the
			// device's release: it says nothing about whether Microsoft still services the device's (review r1 L3 of #951)
			if r, ok := winrel.ByBuild(l.build, l.server); l.build > d.rel.Build && (!ok || !winrel.Learned(r) || r.Server || r.Line == d.rel.Line) {
				successor = true
			}
			if l.server == d.rel.Server && l.build < d.rel.Build {
				below = appendOnce(below, l.product) // review r2 H2 of #939: a release of the same kind before the device's
			} else if l.server == d.rel.Server {
				above = appendOnce(above, l.product)
			}
			if r, ok := winrel.ByBuild(l.build, l.server); ok {
				listedYear = max(listedYear, r.GA.Year())
			} else {
				listedYear = 9999 // not known: the CVE-year proof does not hold
			}
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
		if w.t == Unknown { // The release's own rows cannot tell, its build's month can (never over a Yes or a No)
			if m, ok := winMonthRule(d, in.winBuild, v, now); ok {
				return m, true
			}
		}
		return w, true
	}
	// review r1 #2 of #801: a CVE whose fix Microsoft extended to later releases after NVD's list named only older ones is never ruled
	// out by "only older releases are listed", whatever that list says at the time.
	if winRevised[v.CVE] && len(others) > 0 {
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s for %s, but Microsoft later extended this flaw's fix to newer Windows releases (an update setting you may have to turn on): compare %s with Microsoft's advisory.",
			v.CVE, winNames(others), d.rel.Display)}, true
	}
	// WIN-NOISE-2: Microsoft fixed the flaw in or before the month of the update this build carries. It comes before the old-list
	// and older-releases proofs, which hold without the build's month (a preview build, a release NVD gives no fix builds for), and names
	// the build and the month.
	if m, ok := winMonthRule(d, in.winBuild, v, now); ok {
		return m, true
	}
	// A flaw whose CVE id is from before Windows 10 came out (2015), listed by NVD only for releases before Windows 10, is
	// taken as not one of any 10.0 build, preview or not: Windows 10 and every later release shipped after the CVE existed, and Microsoft's
	// advisory, which NVD's list follows, named no 10.0 release for it. That holds only while the list is not being revisited: not within
	// winListedMargin of CISA's (or VulnCheck's) listing, when Microsoft and NVD look at an old CVE again, and never for a CVE Microsoft
	// is known to have extended to 10.0 (winRevised, CVE-2013-3900); NVD's later changes reach the box with the daily nvd-kev update and
	// reopen the finding. Rows of a Microsoft product no 10.0 release has, at one stated version (winGoneProducts: CVE-2004-0210's
	// Interix 2.2), do not name this release either; any other product, a family row (windows_nt at any version) or a release the table
	// does not know keep it "not checked".
	listedLongAgo := !v.DateAdded.IsZero() && !now.IsZero() && !v.DateAdded.Add(winListedMargin).After(now)
	if y := cveYear(v.CVE); named && listedLongAgo && newest == 0 && len(others) > 0 && !undecidable && !unknownWin && !looseOther && y > 0 && y < winTenYear {
		also := ""
		if len(pinned) > 0 {
			also = fmt.Sprintf(" and %s", orList(pinned))
		}
		return winVerdict{t: No, proof: proofRelease, note: fmt.Sprintf("Not affected: NVD lists %s only for Windows releases before Windows 10 (%s)%s. The CVE dates from %d, before Windows 10 came out, and no Windows 10 or later release is listed for it, so this device's %s is not affected. Vedette closed this by itself and reopens it if a later match says the device is affected.",
			v.CVE, winNames(others), also, y, d.rel.Display)}, true
	}
	if note := winLaterNote(d, in.winBuild, v); note != "" { // Fixed after the build's month, in an update NVD names
		return winVerdict{t: Unknown, note: note, later: true}, true
	}
	switch {
	case d.rel.Ended && !d.rel.LTSC && d.rel.LastFreeRev == 0 && len(below) > 0 && len(above) > 0: // whatever else the list names (another product, a release the table lacks); never one an LTSC edition or paid ESU still services (check of r2 H2)
		// review r2 H2 of #939: NVD's list brackets the device's release with releases of its kind before and after it, all fixed by
		// monthly updates, and Microsoft no longer services the device's release: no update brings the fix to it, so it has the flaw
		return winVerdict{t: Unknown, later: true, note: fmt.Sprintf("Microsoft no longer updates %s. NVD lists %s for the Windows releases before and after it (%s), which Microsoft fixed with updates %s never gets, so this device has the flaw: move to a serviced release.",
			d.rel.Display, v.CVE, winNames(append(slices.Clone(below), above...)), d.rel.Display)}, true
	case !allWindows || undecidable || newest == d.rel.Build:
		return winVerdict{t: Unknown}, true // not checked
	case newest > d.rel.Build && !successor:
		return winVerdict{t: Unknown}, true // only releases of other lines are newer by build: not checked, no "still supported?" note
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
	if d.rel.GARev == 0 { // review r2 LOW-1: no first public revision known, no proof from the list at any revision
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s), but Vedette does not know the first public build of %s, so it cannot tell whether this machine's build carries the fix: compare with Microsoft's advisory.",
			v.CVE, d.rel.Display, winNames(others), d.rel.Display)}, true
	}
	if d.rev < d.rel.GARev {
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s), but this machine runs a build from before %s's first public one (10.0.%d.%d), a preview or early build that may lack the fix: install the current updates.",
			v.CVE, d.rel.Display, winNames(others), d.rel.Display, d.rel.Build, d.rel.GARev)}, true
	}
	if winrel.Learned(d.rel) { // review r1 M1 of #951: Vedette does not know when Microsoft stops servicing a release learned from its list
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s). Vedette learned %s from Microsoft's release list and cannot tell whether Microsoft still services it, so a list that leaves it out proves nothing: compare with Microsoft's advisory.",
			v.CVE, d.rel.Display, winNames(others), d.rel.Display)}, true
	}
	shipped := v.Source != SourceVulnCheck && !v.DateAdded.IsZero() && !v.DateAdded.Add(winShipMargin).After(d.rel.GA)
	// NVD's list has also stood a year when the CVE itself is two calendar years old or more: Microsoft, its own CNA, gives a
	// Windows CVE its id in the year it publishes the advisory NVD's list follows, so a CVE-2018 entry CISA lists in 2026 has had NVD's
	// list since 2018 (CISA's listing date says nothing about it).
	// The CVE must also predate the device's release (review r1 #3 of #801): a CVE-2024 entry fixed in a late-2024 update whose list names
	// Server 2022 and not Server 2025 says nothing about a Server 2025 on its GA build.
	// And not within winListedMargin of CISA's listing, when Microsoft and NVD revisit an old CVE (review r1 #2).
	// And every release the list names came out in or before the CVE's year (review r2 #1 of #801): a list naming a later release
	// (CVE-2010 with windows_server_2022) was written or grown after the CVE's year, so its age is not the CVE's.
	old := cveYear(v.CVE) > 0 && listedLongAgo && cveYear(v.CVE)+2 <= now.Year() && cveYear(v.CVE) < d.rel.GA.Year() && listedYear > 0 && listedYear <= cveYear(v.CVE)
	if shipped || settled(v, now) || old {
		why := fmt.Sprintf("%s came out on %s, after %s listed the flaw (%s), so it carries the fix", d.rel.Display, orgtime.CalendarDay(d.rel.GA), v.listName(), orgtime.CalendarDay(v.DateAdded))
		switch {
		case shipped:
		case settled(v, now):
			why = fmt.Sprintf("NVD's list has stood for over a year since %s listed it", v.listName())
		default:
			why = fmt.Sprintf("the CVE dates from %d, so NVD's list has stood for over a year", cveYear(v.CVE))
		}
		return winVerdict{t: No, proof: proofRelease, note: fmt.Sprintf("Not affected: NVD lists %s only for Windows releases older than this device's %s (%s), and %s. Vedette closed this by itself and reopens it if a later match says the device is affected.",
			v.CVE, d.rel.Display, winNames(others), why)}, true
	}
	if y := cveYear(v.CVE); y > 0 && !listedLongAgo && y+2 <= now.Year() && y < d.rel.GA.Year() {
		return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s), but %s listed this old flaw less than 90 days ago, when Microsoft and NVD may still add releases to it: compare with Microsoft's advisory.",
			v.CVE, d.rel.Display, winNames(others), v.listName())}, true
	}
	return winVerdict{t: Unknown, note: fmt.Sprintf("NVD lists %s only for Windows releases older than %s (%s). A later release usually carries the fix, but NVD's list for this entry is less than a year old: compare with Microsoft's advisory.",
		v.CVE, d.rel.Display, winNames(others))}, true
}

// winOldYear is the latest year a release before Windows 10 came out (Windows 8.1 and Server 2012 R2, October 2013).
const winOldYear = 2013

// winTenYear is the year Windows 10, the first 10.0 release, came out (29 July 2015, core/winrel).
const winTenYear = 2015

// cveYear is the year of a CVE id ("CVE-2008-4250" → 2008); 0 when it is not one.
func cveYear(cve string) int {
	if !ValidCVE(cve) {
		return 0
	}
	y, _ := strconv.Atoi(cve[4:8])
	return y
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
		if t == Yes && (yes == nil || explainsBetter(r, *yes)) {
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
// without the revision, "-" as the version, an update) is Unknown, and so is a release row of every version with no range: for a
// Windows release that means NVD recorded no fixed build, not that no update fixes it (review r1 LOW-1). An attribute NA ("-": the
// software edition of "windows_server_2025:*:*:*:*:-:*:x64:*") pins nothing the device states, so it reads (winUnpinned, #901).
func winEval(c CPE, r VersionRange, d winDev) (Tri, VersionRange, int) {
	if !winUnpinned(c, d) {
		return Unknown, r, 0
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
	t := r.Contains(fmt.Sprintf("10.0.%d.%d", build, d.rev))
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
// every KEV key is CISA's "Microsoft | Windows" (a person's "Windows 11", added by hand before the agent came). The
// agent's row reads the patched build; the other would keep every Windows entry "not checked" next to it.
func winCovers(s Software) bool {
	if len(s.KevKeys) == 0 || winRow(s) {
		return false
	}
	for _, k := range s.KevKeys {
		if productid.NormalizeKey(k) != "microsoft|windows" {
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

// winFix is what installing the fix of a Yes takes (review r1 M2, r2 MEDIUM-2). "fixed": the month's build at the device's build,
// which Windows Update offers (a serviced 24H2 read through 25H2's rows takes 10.0.26100.<revision>). "esu": the fix is above the
// last revision the release gets without Extended Security Updates (Windows 10 22H2 after October 2025). "feature_update": the
// device's release has ended (core/winrel) and the range came from a later sibling NVD lists instead of it, or only the release's
// LTSC edition is still serviced and the device does not run it (Windows 10 21H2 Pro on NVD's windows_10_21h2 rows of LTSC 2021):
// no update for it fixes this; fixed is the build NVD names and branch where it is.
func winFix(w winVerdict, d winDev) (kind, fixed, branch string) {
	end := w.within.EndExcl
	if m := winBoundRE.FindStringSubmatch(end); m != nil && d.rel.LastFreeRev > 0 {
		if n, _ := strconv.Atoi(m[2]); n > d.rel.LastFreeRev {
			return "esu", end, d.rel.Display
		}
	}
	switch {
	case w.via != "" && d.ended():
		r, _ := winrel.ByBuild(w.build, false)
		return "feature_update", strings.Replace(end, fmt.Sprintf("10.0.%d.", d.rel.Build), fmt.Sprintf("10.0.%d.", w.build), 1), r.Display
	case w.via == "" && d.ended() && d.rel.LTSC:
		return "feature_update", end, d.rel.Display + " LTSC"
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

// WIN-NOISE-2: Windows updates are cumulative. Each month Microsoft ships one update per release line, and
// NVD's ranges of the flaws it fixes end at that update's build ("windows_11_24h2 < 10.0.26100.2033" for the CVEs Microsoft published on
// 8 October 2024). So the list itself says which month's update a build carries, and a flaw of Windows Microsoft fixed in or before that
// month is fixed in the build, whatever releases NVD's entry names.

// monthKey is a calendar month, year*12 + month-1 (UTC).
type monthKey int

func monthKeyOf(t time.Time) monthKey {
	t = t.UTC()
	return monthKey(t.Year()*12 + int(t.Month()) - 1)
}

func (m monthKey) String() string {
	return time.Month(int(m)%12+1).String() + " " + strconv.Itoa(int(m)/12)
}

// winBuild is the month of the update a Windows release row's build carries (winBuildMonth).
type winBuild struct {
	month monthKey // the newest monthly update the build carries; 0: not known
	// otherAt is the build of the other kind on the same build (Windows 11 24H2 for Server 2025) that the device's month corresponds
	// to after Microsoft numbered the two apart: the highest of the lowest fix builds NVD gives that release per month, months up to the
	// device's (the lowest, so a CVE fixed by a later update does not raise it). A row of the other kind ending above it is a fix after
	// the device's month (review r2 #2 of #806). 0: not known.
	otherAt int
}

// winUndated is the month a fix build of a CVE without its published day counts in (year 1, the earliest of all): it may stop the walk,
// never be the build's month (review r2 #5 of #806).
var winUndated = monthKeyOf(time.Time{})

// otherUntil is the first month a row of the other kind on the device's build no longer counts (winKinship): the month the device's
// release came out (core/winrel GA), a fact of the release and not of the entries a match is given (review r1 #1 of #806).
func (d winDev) otherUntil() monthKey { return monthKeyOf(d.rel.GA) }

// winOSComponents are Microsoft products NVD names apart from Windows that ship inside Windows and take its monthly update: for the month
// rule their row is a row of Windows. SMBv1 (server_message_block 1.0, CVE-2017-0143 to 0148): MS17-010 was a Windows security update
// (https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010).
var winOSComponents = map[string]bool{"server_message_block": true}

// winKinship says how row l relates to the device's numbering of update revisions. same: the device's release or a client sibling on
// its line (the same revision every month). other: the release of the other kind on the same build (Windows 11 24H2 for Windows
// Server 2025, Windows 10 1809 for Server 2019): the same monthly update and revision while they are serviced together, but Microsoft
// may number them apart later (Server 2025 went from 26100.7462 in December 2025 to 26100.32230 in January 2026, while
// NVD's 24H2 ranges went on at 26100.7781 in February 2026), so a row of the other kind counts only for months before the device's
// release came out (otherUntil: Server 2025's November 2024).
func winKinship(l winListed, d winDev) (same, other bool) {
	if l.build == 0 || l.old {
		return false, false
	}
	if l.server == d.rel.Server {
		return l.build == d.rel.Build || !l.server && d.sameLine(l.build), false
	}
	return false, l.build == d.rel.Build
}

// winFixRev is the update revision of the fix a row names: its range ends before a build of the device's numbering ("< 10.0.26100.2033":
// a build on the device's line, or exactly the device's build for a row of the other kind), nothing else is pinned and a start bound is
// of the same build. false otherwise.
func winFixRev(c CPE, r VersionRange, d winDev, other bool) (int, bool) {
	if c.Version.Kind != Any || !winUnpinned(c, d) {
		return 0, false
	}
	m := winBoundRE.FindStringSubmatch(r.EndExcl)
	if m == nil || r.EndIncl != "" {
		return 0, false
	}
	build, _ := strconv.Atoi(m[1])
	if other && build != d.rel.Build || !other && !d.sameLine(build) {
		return 0, false
	}
	for _, s := range []string{r.StartIncl, r.StartExcl} {
		if sm := winBoundRE.FindStringSubmatch(s); s != "" && (sm == nil || sm[1] != m[1]) {
			return 0, false
		}
	}
	rev, _ := strconv.Atoi(m[2])
	return rev, rev > 0
}

// winUnpinned says whether row c pins nothing after its version but target hardware (winRows reads that). Update and edition must
// be ANY: on a Windows row they name a service pack or an edition ("windows_7:-:sp1"), and "-" there is "the release without one", a
// restriction the device's build does not settle. Language, software edition, target software and other may also be NA where the
// device's row states no value (naCovers, #901): NVD writes "windows_server_2025:*:*:*:*:-:*:x64:*" for every install of the
// release, and Windows release rows carry no plain-vs-named edition the way application rows do (pinnedAttrs).
func winUnpinned(c CPE, d winDev) bool {
	if c.Update.Kind != Any || c.Edition.Kind != Any {
		return false
	}
	cf, df := c.fields(), d.cpe.fields()
	for _, i := range [...]int{6, 7, 8, 10} { // language, software edition, target software, other; target hardware is winRows'
		if cf[i].Kind != Any && !naCovers(*cf[i], *df[i]) {
			return false
		}
	}
	return true
}

// winBuildMonth reads from the list which month's update the device's build carries. Each row of the device's numbering whose
// range ends at a fix build gives a pair: the month NVD published the CVE (Microsoft publishes a Windows CVE on the Patch Tuesday of its
// fix) and that build. A month's bar is its highest fix build, so a CVE published before its fix (CVE-2023-36884: July 2023, fixed in
// August's 10.0.19044.3324) raises it and an out-of-band build below the month's update does not lower it. Walking the months in order,
// the build carries every month up to the first whose bar is above it, and the month moves forward only when the bar does (review r1 #3
// of #806: a month whose bar is not above the last one taken may be a range copied from the month before, or a late CVE). Not known
// (zero): no fix build in the device's own release (a release NVD gives none for), or the build below the first month's bar. A fix build
// on a CVE whose published day is not known counts in the earliest month of all (year 1), never skipped: above the device's build it
// stops the walk at once (the month is not known), at or below it only raises the bar later months must pass (review r1 #2 of #806). vulns must be the whole stored list (MatchAsset
// reads Asset.winList when the match gets a part of it): a part may miss the month that stops the walk.
func winBuildMonth(vulns []Vuln, d winDev) winBuild {
	own, other, otherLow := map[monthKey]int{}, map[monthKey]int{}, map[monthKey]int{}
	for _, v := range vulns {
		for _, af := range v.Affected {
			if af.parsed == nil && !strings.Contains(af.CPE, ":microsoft:windows") {
				continue // not a Windows row: no parse (review r2 #4 of #806: 6x faster on the whole list)
			}
			c, err := af.cpe()
			if err != nil {
				continue
			}
			l, ok := winListedOf(c)
			if !ok {
				continue
			}
			same, oth := winKinship(l, d)
			if !same && !oth {
				continue
			}
			rev, ok := winFixRev(c, af.Range, d, oth)
			if !ok {
				continue
			}
			bars, m := own, monthKeyOf(v.Published) // no published day: the earliest month of all (year 1), never skipped
			if oth {
				bars = other
				if low, ok := otherLow[m]; !ok || rev < low {
					otherLow[m] = rev
				}
			}
			bars[m] = max(bars[m], rev)
		}
	}
	if len(own) == 0 {
		return winBuild{} // NVD gives no fix build of the device's own release or line
	}
	for m, rev := range other {
		if m < d.otherUntil() {
			own[m] = max(own[m], rev)
		}
	}
	var b winBuild
	hi := 0 // the highest bar taken
	for _, m := range slices.Sorted(maps.Keys(own)) {
		if own[m] > d.rev {
			break
		}
		if own[m] > hi {
			hi = own[m]
			if m != winUndated {
				b.month = m
			}
		}
	}
	if b.month == 0 {
		return winBuild{}
	}
	for m, low := range otherLow {
		if m <= b.month && m != winUndated {
			b.otherAt = max(b.otherAt, low)
		}
	}
	return b
}

// winMonthRule rules entry v out when Microsoft fixed it in or before the month of the update the device's build carries. It
// holds for a flaw of Windows itself: NVD's entry has a Windows row (any release, a family row) or a row of a component that takes
// Windows' monthly update (winOSComponents), and no row of another Microsoft product (.NET, Office, App Installer, Edge, Exchange, SQL
// Server: updated apart from Windows) or of any vendor or product; another vendor's product (a Siemens scanner built on Windows, Go's
// x509 package in CVE-2020-0601) is not this machine and says nothing about it. Never a CVE Microsoft extended later (winRevised: an
// opt-in fix), nor while a row of the device's numbering ends above its build or cannot be read; a family row of every Windows release
// (windows:*, windows_nt at any version but NT 4.0 and older) keeps it open as the old-list proof does, and a row of a release Vedette does not know
// or of another family (windows_10:*, windows_11:*) whose range ends at the device's build or line above its revision too (review r1 #4
// of #806). The CVE's month is the day NVD published it. When the CVE gives a fix build in the device's numbering, that build is below
// the device's and its month may be the build's own (its month's bar counts it). Otherwise the CVE must be from an earlier month (a flaw
// published before its fix, as CVE-2023-36884 on 11 July 2023, fixed on 8 August, is a month ahead at most) and CISA (or VulnCheck) must
// have listed it at least winListedMargin ago (a listing is when Microsoft and NVD revisit an old CVE).
func winMonthRule(d winDev, b winBuild, v Vuln, now time.Time) (winVerdict, bool) {
	if b.month == 0 || v.Published.IsZero() || winRevised[v.CVE] {
		return winVerdict{}, false
	}
	cm := monthKeyOf(v.Published)
	windows, lineFix := false, false
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			return winVerdict{}, false
		}
		l, isWin := winListedOf(c)
		if !isWin {
			vn, okV := c.Vendor.Literal()
			p, okP := c.Product.Literal()
			switch {
			case !okV || !okP:
				return winVerdict{}, false // any vendor or product: it may be this machine
			case productid.Norm(vn) != "microsoft":
				continue // another vendor's product: not this machine
			case !winOSComponents[p]:
				return winVerdict{}, false // a Microsoft product Windows' monthly update does not service
			}
			windows = true
			continue
		}
		windows = true
		if l.family == "windows" || l.build == 0 && !l.old && winEndsAbove(af.Range, d) {
			return winVerdict{}, false
		}
		same, oth := winKinship(l, d)
		if oth && cm >= d.otherUntil() { // numbered apart from the device's: its fix build tells only against the other kind's own builds
			if rev, ok := winFixRev(c, af.Range, d, true); ok && rev > b.otherAt {
				return winVerdict{}, false // the stored data says the fix came after the device's month (review r2 #2 of #806)
			}
			continue
		}
		if !same && !oth {
			continue // another numbering: only the month tells
		}
		if tgt, lit := c.TargetHW.Literal(); same && c.TargetHW.Kind == Value && lit && d.target != "" && tgt != d.target {
			continue // another target (winRows)
		}
		if af.Range.IsZero() && c.Version.Kind != Value {
			continue // every version or "-": NVD recorded no fix build (review r1 LOW-1)
		}
		rev, ok := winFixRev(c, af.Range, d, oth)
		if !ok || d.rev < rev {
			return winVerdict{}, false
		}
		lineFix = true
	}
	listed := !v.DateAdded.IsZero() && !now.IsZero() && !v.DateAdded.Add(winListedMargin).After(now)
	if !windows || cm > b.month || !lineFix && (cm == b.month || !listed) {
		return winVerdict{}, false
	}
	return winVerdict{t: No, proof: proofRelease, note: fmt.Sprintf("Not affected: build %d.%s of %s carries Microsoft's monthly update of %s (the newest month whose fixes NVD lists at or below this build), and Microsoft published %s on %s, in or before that month. Windows updates are cumulative, so this build has the fix. Vedette closed this by itself and reopens it if a later match says the device is affected.",
		d.rel.Build, d.ubr, d.rel.Display, b.month, v.CVE, orgtime.CalendarDay(v.Published))}, true
}

// winEndsAbove says whether a range's end is at the device's build or line and not below its revision, or there without a revision
// (a row Vedette cannot place in a release: it may be the device's, review r1 #4 of #806).
func winEndsAbove(r VersionRange, d winDev) bool {
	for i, e := range []string{r.EndExcl, r.EndIncl} {
		m := winBoundRE.FindStringSubmatch(e)
		if m == nil {
			if strings.HasPrefix(e, fmt.Sprintf("10.0.%d", d.rel.Build)) {
				return true // the device's build without a revision
			}
			continue
		}
		b, _ := strconv.Atoi(m[1])
		rev, _ := strconv.Atoi(m[2])
		if (b == d.rel.Build || !d.rel.Server && d.sameLine(b)) && (rev > d.rev || i == 1 && rev == d.rev) {
			return true
		}
	}
	return false
}

// winLaterNote is the evidence of an entry Microsoft fixed after the month of the device's build when NVD gives the fix build only for the
// release of the other kind on the same build while both took one monthly update (CVE-2024-43572 on a Windows Server 2025 at 26100.1742:
// Windows 11 24H2 fixed in 26100.2033, October 2024): the update that fixes it, by month and build, and the month the build carries,
// or that it is not known. "" otherwise.
func winLaterNote(d winDev, b winBuild, v Vuln) string {
	if v.Published.IsZero() {
		return ""
	}
	cm := monthKeyOf(v.Published)
	if b.month != 0 && cm <= b.month || cm >= d.otherUntil() {
		return ""
	}
	fix, name := 0, ""
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		l, ok := winListedOf(c)
		if !ok {
			continue
		}
		if _, oth := winKinship(l, d); !oth {
			continue
		}
		if rev, ok := winFixRev(c, af.Range, d, true); ok && rev > d.rev && rev > fix {
			fix, name = rev, winNames([]string{l.product})
		}
	}
	if fix == 0 {
		return ""
	}
	carries := fmt.Sprintf("which carries the updates up to %s only", b.month)
	if b.month == 0 { // review r2 #5 of #806: never a placeholder month
		carries = "below that build (Vedette cannot tell which month's update it carries)"
	}
	return fmt.Sprintf("Microsoft fixed %s in its %s update: NVD lists it for %s, fixed in build %d.%d, and %s took the same monthly update then. The agent reports build %d.%s, %s, so this device does not have the fix: install the current cumulative update for %s.",
		v.CVE, cm, name, d.rel.Build, fix, d.rel.Display, d.rel.Build, d.ubr, carries, d.rel.Display)
}

// winNames names releases for a sentence: "windows 10 1809, windows 11 23h2 and 2 more".
func winNames(products []string) string {
	names := make([]string, 0, len(products))
	for _, p := range products {
		if r, ok := winrel.ByProduct(p); ok {
			names = append(names, r.Display)
		} else if n, ok := winOldNames[p]; ok {
			names = append(names, n)
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

// winHotpatchNote is the evidence of a close of a Windows entry on a device that runs a hotpatch (winDevice compares it at its month's
// update): the device's own build is below the fixed build NVD names, so "outside every range" alone would read as a contradiction. It
// names the hotpatch and the update it matches. false when the device runs no hotpatch.
func winHotpatchNote(in swInfo, cve string) (string, bool) {
	d, ok := winDevice(in)
	if !ok || d.hot.Rev == 0 {
		return "", false
	}
	kb := func(u winrel.Update) string {
		if u.KB == "" {
			return ""
		}
		return ", " + u.KB
	}
	return fmt.Sprintf("Not affected: build %d.%s of %s is Microsoft's hotpatch of %s (%d.%d%s), which carries the security fixes of that month's update %d.%d%s, and NVD lists %s as fixed at or below that update. Vedette closed this by itself and reopens it if a later match says the device is affected.",
		d.rel.Build, d.ubr, d.rel.Display, orgtime.CalendarMonth(d.hot.Day), d.rel.Build, d.hot.Rev, kb(d.hot), d.rel.Build, d.base.Rev, kb(d.base), cve), true
}
