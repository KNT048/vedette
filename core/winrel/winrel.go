// Package winrel is the table of Windows 10, 11 and Server (2016 and later) releases: the build a machine reports
// ("10.0.22631"), the name NVD's configurations give the release ("windows_11_23h2", with ranges that end at the patched build,
// "< 10.0.22631.5189"), its general availability and the releases that take the same monthly update. agent-intake reads
// it to give a Windows PC its operating-system row, findings to read NVD's Windows entries against that row.
//
// Sources: Microsoft's release information pages (https://learn.microsoft.com/en-us/windows/release-health/release-information,
// .../windows11-release-information, https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info)
// for builds and dates; NVD's CPE dictionary for the names (checked 2026-11-14, lists which).
//
// A release newer than this table (Windows 11 26H2, build 26300, out 2026-09-29) needs no code change. The feeds module reads
// Microsoft's release information pages on the box and hands the releases it finds to Learn; ByBuild, ByProduct and Releases answer
// from this table first, then from those. The table's hand facts (Ended, LTSC, LastFreeRev, the NVD names Microsoft's pages do not
// spell out) always win: a learned release never replaces or changes one of the table.
package winrel

import (
	"regexp"
	"slices"
	"sync/atomic"
	"time"
)

// Release is one Windows release.
type Release struct {
	Build   int    // 22631
	Product string // NVD product name, "windows_11_23h2"
	Display string // "Windows 11 23H2"
	Server  bool
	// Line is the first build of the client releases that are one code base with one monthly update, the same update
	// revision every month (10.0.26100.7092 and 10.0.26200.7092 are KB5068861 of November 2025): 19041..19045,
	// 22621/22631, 26100/26200, 18362/18363. Every other release is a line of its own (Line == Build). A server release
	// never shares a line with a client one, even on the same build (Server 2025 and Windows 11 24H2 are both 26100).
	Line int
	GA   time.Time // general availability of the release
	// GARev is the update revision of the first public build at general availability (26100.1742 for 24H2); 0 when the table does
	// not know it. A machine below it runs a preview or OEM build of the code base, older than the date says (findings' "shipped
	// after CISA listed it" proof needs revision >= GARev).
	GARev int
	// LastFreeRev is the last update revision Windows Update gives without Extended Security Updates (19045.6456, October 2025, for
	// Windows 10 22H2); 0 when the release is still serviced or the table does not know it. A fix above it needs ESU.
	LastFreeRev int
	// Ended: Microsoft no longer services the release (as of the table's last update, 2026-11-14).
	// LTSC: an LTSC/LTSB edition on the same build is still serviced (Windows 10 1809 LTSC 2019, 21H2
	// LTSC 2021), so an Ended release is ended only for a machine whose OS name does not say LTSC/LTSB.
	Ended, LTSC bool
}

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic("winrel: " + s) // a literal of this file; a test reads every one
	}
	return t
}

// releases, client then server. The 10.0 releases only: NVD names older ones (6.x) without build ranges. Columns: build, NVD product,
// display, server, line, general availability, GA revision (0: not known, so no proof from "only older releases listed"), last
// revision without ESU, ended, LTSC edition still serviced.
// GA revisions are the first build of each release's table on Microsoft's release information pages; only those confirmed are set.
var releases = []Release{
	{10240, "windows_10_1507", "Windows 10 1507", false, 10240, day("2015-07-29"), 16405, 0, true, false},
	{10586, "windows_10_1511", "Windows 10 1511", false, 10586, day("2015-11-10"), 0, 0, true, false},
	{14393, "windows_10_1607", "Windows 10 1607", false, 14393, day("2016-08-02"), 321, 0, true, false},
	{15063, "windows_10_1703", "Windows 10 1703", false, 15063, day("2017-04-11"), 0, 0, true, false},
	{16299, "windows_10_1709", "Windows 10 1709", false, 16299, day("2017-10-17"), 0, 0, true, false},
	{17134, "windows_10_1803", "Windows 10 1803", false, 17134, day("2018-04-30"), 0, 0, true, false},
	{17763, "windows_10_1809", "Windows 10 1809", false, 17763, day("2018-11-13"), 134, 0, true, true},
	{18362, "windows_10_1903", "Windows 10 1903", false, 18362, day("2019-05-21"), 116, 0, true, false},
	{18363, "windows_10_1909", "Windows 10 1909", false, 18362, day("2019-11-12"), 476, 0, true, false},
	{19041, "windows_10_2004", "Windows 10 2004", false, 19041, day("2020-05-27"), 264, 0, true, false},
	{19042, "windows_10_20h2", "Windows 10 20H2", false, 19041, day("2020-10-20"), 572, 0, true, false},
	{19043, "windows_10_21h1", "Windows 10 21H1", false, 19041, day("2021-05-18"), 985, 0, true, false},
	{19044, "windows_10_21h2", "Windows 10 21H2", false, 19041, day("2021-11-16"), 1288, 0, true, true},
	{19045, "windows_10_22h2", "Windows 10 22H2", false, 19041, day("2022-10-18"), 2130, 6456, true, false},
	{22000, "windows_11_21h2", "Windows 11 21H2", false, 22000, day("2021-10-04"), 194, 0, true, false},
	{22621, "windows_11_22h2", "Windows 11 22H2", false, 22621, day("2022-09-20"), 521, 0, true, false},
	{22631, "windows_11_23h2", "Windows 11 23H2", false, 22621, day("2023-10-31"), 2428, 0, true, false},
	{26100, "windows_11_24h2", "Windows 11 24H2", false, 26100, day("2024-10-01"), 1742, 0, false, false},
	{26200, "windows_11_25h2", "Windows 11 25H2", false, 26100, day("2025-09-30"), 6584, 0, false, false},

	{14393, "windows_server_2016", "Windows Server 2016", true, 14393, day("2016-10-12"), 321, 0, false, false},
	{16299, "windows_server_1709", "Windows Server 1709", true, 16299, day("2017-10-17"), 0, 0, true, false},
	{17134, "windows_server_1803", "Windows Server 1803", true, 17134, day("2018-04-30"), 0, 0, true, false},
	{17763, "windows_server_2019", "Windows Server 2019", true, 17763, day("2018-11-13"), 134, 0, false, false},
	{18362, "windows_server_1903", "Windows Server 1903", true, 18362, day("2019-05-21"), 0, 0, true, false},
	{18363, "windows_server_1909", "Windows Server 1909", true, 18363, day("2019-11-12"), 0, 0, true, false},
	{19041, "windows_server_2004", "Windows Server 2004", true, 19041, day("2020-05-27"), 0, 0, true, false},
	{19042, "windows_server_20h2", "Windows Server 20H2", true, 19042, day("2020-10-20"), 0, 0, true, false},
	{20348, "windows_server_2022", "Windows Server 2022", true, 20348, day("2021-08-18"), 169, 0, false, false},
	{25398, "windows_server_2022_23h2", "Windows Server 2022 23H2", true, 25398, day("2023-10-24"), 0, 0, true, false},
	{26100, "windows_server_2025", "Windows Server 2025", true, 26100, day("2024-11-01"), 1742, 0, false, false}, // GA media 26100.1742 (Microsoft's table, "2024-10 A")
}

// learned are the releases Learn was last given that the table does not have; nil before the first call.
var learned atomic.Pointer[[]Release]

// generation counts the calls of Learn and LearnUpdates.
var generation atomic.Uint64

// Generation changes whenever what Learn or LearnUpdates set may have changed (it counts their calls): a reader that keeps an answer
// built from the releases or the updates builds it again when it moves.
func Generation() uint64 { return generation.Load() }

// learnedProduct is the NVD name a learned release may have: Windows 11 by its version ("windows_11_26h2") or a Windows Server by
// its year ("windows_server_2028"), the two shapes NVD gives every release of the table since 2021.
var learnedProduct = regexp.MustCompile(`^windows_(11_[0-9]{2}h[12]|server_20[2-9][0-9])$`)

// Learn sets the releases Microsoft's release information lists and returns how many it kept. It keeps a release only when
// it is valid and the table has neither its build (of its kind) nor its NVD name: the table's hand facts win. A kept release is one
// Microsoft still services (Ended, LTSC and LastFreeRev are the table's facts, never learned) and is on its own line unless that line
// is the line of a client release of the table (24H2's 26100 for 26H2) or its own build; a server release is always its own line.
// Each call replaces what the last one set; nil or empty forgets every learned release.
func Learn(rs []Release) int {
	var keep []Release
	for _, r := range rs {
		r.Ended, r.LTSC, r.LastFreeRev = false, false, 0
		if !learnable(r) || slices.ContainsFunc(keep, func(k Release) bool { return k.Product == r.Product || k.Build == r.Build && k.Server == r.Server }) {
			continue
		}
		keep = append(keep, r)
	}
	learned.Store(&keep)
	generation.Add(1)
	return len(keep)
}

func learnable(r Release) bool {
	if r.Build < 10240 || r.Build > 99999 || !learnedProduct.MatchString(r.Product) || r.Server != (r.Product[8:14] == "server") ||
		len(r.Display) == 0 || len(r.Display) > 60 || r.GA.IsZero() || r.GARev < 0 || r.GARev > 999999 {
		return false
	}
	if _, ok := tableByBuild(r.Build, r.Server); ok {
		return false
	}
	if _, ok := tableByProduct(r.Product); ok {
		return false
	}
	if r.Line == r.Build {
		return true
	}
	first, ok := tableByBuild(r.Line, false)
	return !r.Server && ok && first.Line == r.Line && r.Line < r.Build
}

// Learned says whether r is a release Learn kept, not one of the table (review r1 M1 of #951): its end of servicing is never known, so
// findings never takes a proof from "only older releases are listed" for it, and a build below its first public revision is not checked.
func Learned(r Release) bool {
	if _, ok := tableByProduct(r.Product); ok {
		return false
	}
	return slices.ContainsFunc(learnedReleases(), func(l Release) bool { return l == r })
}

func learnedReleases() []Release {
	if p := learned.Load(); p != nil {
		return *p
	}
	return nil
}

// ByBuild is the client (server false) or server release of a build; false when neither the table nor the learned releases have it.
func ByBuild(build int, server bool) (Release, bool) {
	if r, ok := tableByBuild(build, server); ok {
		return r, true
	}
	for _, r := range learnedReleases() {
		if r.Build == build && r.Server == server {
			return r, true
		}
	}
	return Release{}, false
}

func tableByBuild(build int, server bool) (Release, bool) {
	for _, r := range releases {
		if r.Build == build && r.Server == server {
			return r, true
		}
	}
	return Release{}, false
}

// Releases is every release of the table, in its order, then the learned ones (a copy).
func Releases() []Release { return append(slices.Clone(releases), learnedReleases()...) }

// ByProduct is the release NVD names product ("windows_11_23h2", lower case as NVD writes it); false when neither the table nor the
// learned releases have it.
func ByProduct(product string) (Release, bool) {
	if r, ok := tableByProduct(product); ok {
		return r, true
	}
	for _, r := range learnedReleases() {
		if r.Product == product {
			return r, true
		}
	}
	return Release{}, false
}

func tableByProduct(product string) (Release, bool) {
	for _, r := range releases {
		if r.Product == product {
			return r, true
		}
	}
	return Release{}, false
}

// Update is one monthly security update ("2026-11 B", Patch Tuesday) Microsoft's release information pages list for a release: the
// cumulative update Windows Update offers that month, at the release's build ("26100.33822", KB5131080 of 2026-11-10 for Windows
// Server 2025). The feeds module reads them on the box once a day and hands them to LearnUpdates. NVD analyses a month's CVEs days
// to weeks after Microsoft publishes them, so the newest update named here may be newer than every fixed build NVD lists.
//
// Hotpatch marks a hotpatch of the month instead (the pages' hotpatch calendars: Windows Server 2022/2025 Azure Edition and Arc,
// Windows 11 Enterprise): a device enrolled in hotpatching gets it without a restart, at a revision below the month's B build
// ("26100.33730", KB5131077), with the month's security fixes. It is never a target; a device on it is current to its month (Baseline).
type Update struct {
	Build    int // 26100
	Server   bool
	Rev      int    // 33822
	KB       string // "KB5131080"; "" when the page names none
	Day      time.Time
	Hotpatch bool
}

type updateKey struct {
	build  int
	server bool
}

// learnedUpdates are the updates LearnUpdates was last given, by release, oldest first (monthly and hotpatch apart).
type learnedUpdates struct{ monthly, hotpatch map[updateKey][]Update }

// updates is what LearnUpdates was last given; nil before the first call.
var updates atomic.Pointer[learnedUpdates]

var kbShape = regexp.MustCompile(`^KB[0-9]{6,8}$`)

// LearnUpdates sets the monthly updates and hotpatches Microsoft's release information lists and returns how many it kept: a valid one
// (build of a Windows 10 or later release, revision 1..999999, a KB of the right shape or none, a day), once per release and revision.
// Each call replaces what the last one set; nil or empty forgets them all. The monthly updates are read first, whatever the order
// given: a hotpatch at the revision of a monthly update is not a hotpatch (a regular build is never one) and is dropped.
func LearnUpdates(us []Update) int {
	l := learnedUpdates{monthly: map[updateKey][]Update{}, hotpatch: map[updateKey][]Update{}}
	seen := map[[3]int]bool{}
	n := 0
	for _, hot := range []bool{false, true} {
		for _, u := range us {
			k := updateKey{u.Build, u.Server}
			r := [3]int{u.Build, boolInt(u.Server), u.Rev}
			if u.Hotpatch != hot || u.Build < 10240 || u.Build > 99999 || u.Rev < 1 || u.Rev > 999999 || u.KB != "" && !kbShape.MatchString(u.KB) ||
				u.Day.IsZero() || seen[r] {
				continue
			}
			seen[r] = true
			if hot {
				l.hotpatch[k] = append(l.hotpatch[k], u)
			} else {
				l.monthly[k] = append(l.monthly[k], u)
			}
			n++
		}
	}
	for _, m := range []map[updateKey][]Update{l.monthly, l.hotpatch} {
		for _, us := range m {
			slices.SortFunc(us, func(a, b Update) int {
				if c := a.Day.Compare(b.Day); c != 0 {
					return c
				}
				return a.Rev - b.Rev
			})
		}
	}
	updates.Store(&l)
	generation.Add(1)
	return n
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Updates are the monthly updates (never a hotpatch) of the client (server false) or server release on build, oldest first (by day,
// then revision); nil when none was learned. The caller must not change the slice.
func Updates(build int, server bool) []Update {
	if p := updates.Load(); p != nil {
		return p.monthly[updateKey{build, server}]
	}
	return nil
}

// Baseline is, for a device of the release on build at revision rev, the monthly update it is current to: when rev is a hotpatch
// Microsoft lists for the release (hot), the monthly update of the same month (base: its B build, with the same security fixes). A
// hotpatch sits between the previous month's update and its own month's (every real row, November 2024 to November 2026); a row
// outside that (a mistyped build, last month's out-of-band build pasted in) would close an exploited finding of a device that does not
// have the fix, so it maps nothing, nor does one whose month's update or previous update is not known. false then, and when rev is no
// hotpatch: the device is compared at its own revision.
func Baseline(build int, server bool, rev int) (base, hot Update, ok bool) {
	p := updates.Load()
	if p == nil {
		return Update{}, Update{}, false
	}
	k := updateKey{build, server}
	i := slices.IndexFunc(p.hotpatch[k], func(u Update) bool { return u.Rev == rev })
	if i < 0 {
		return Update{}, Update{}, false
	}
	h := p.hotpatch[k][i]
	month := func(u Update) int { return u.Day.Year()*12 + int(u.Day.Month()) }
	prev, cur := 0, -1 // the revision of the newest update before the hotpatch's month; its own month's update
	for j, u := range p.monthly[k] {
		switch {
		case month(u) < month(h):
			prev = max(prev, u.Rev)
		case month(u) == month(h) && cur < 0:
			cur = j
		}
	}
	if prev == 0 || cur < 0 || h.Rev <= prev || h.Rev >= p.monthly[k][cur].Rev {
		return Update{}, Update{}, false
	}
	return p.monthly[k][cur], h, true
}
