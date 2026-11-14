// Package winrel is the table of Windows 10, 11 and Server (2016 and later) releases: the build a machine reports
// ("10.0.22631"), the name NVD's configurations give the release ("windows_11_23h2", with ranges that end at the patched build,
// "< 10.0.22631.5189"), its general availability and the releases that take the same monthly update (D-546). agent-intake reads
// it to give a Windows PC its operating-system row, findings to read NVD's Windows entries against that row.
//
// Sources: Microsoft's release information pages (https://learn.microsoft.com/en-us/windows/release-health/release-information,
// .../windows11-release-information, https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info)
// for builds and dates; NVD's CPE dictionary for the names (checked 2026-11-14, docs/decisions/D-546.md lists which).
package winrel

import "time"

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
	// after CISA listed it" proof needs revision >= GARev, D-546 review r1 M1).
	GARev int
	// LastFreeRev is the last update revision Windows Update gives without Extended Security Updates (19045.6456, October 2025, for
	// Windows 10 22H2); 0 when the release is still serviced or the table does not know it. A fix above it needs ESU.
	LastFreeRev int
	// Ended: Microsoft no longer services the release (as of the table's last update, 2026-11-14; winrel upkeep in
	// .ai/deferred/tune-5b.md). LTSC: an LTSC/LTSB edition on the same build is still serviced (Windows 10 1809 LTSC 2019, 21H2
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
	{26100, "windows_server_2025", "Windows Server 2025", true, 26100, day("2024-11-01"), 2314, 0, false, false},
}

// ByBuild is the client (server false) or server release of a build; false when the table has none.
func ByBuild(build int, server bool) (Release, bool) {
	for _, r := range releases {
		if r.Build == build && r.Server == server {
			return r, true
		}
	}
	return Release{}, false
}

// ByProduct is the release NVD names product ("windows_11_23h2", lower case as NVD writes it); false when the table has none.
func ByProduct(product string) (Release, bool) {
	for _, r := range releases {
		if r.Product == product {
			return r, true
		}
	}
	return Release{}, false
}
