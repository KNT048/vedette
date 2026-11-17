package findings

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/winrel"
)

// monthly is a release's monthly security updates as Microsoft's release information lists them: day "YYYY-MM-DD" and revision.
type monthly struct {
	day string
	rev int
}

// learnUpdates gives core/winrel the monthly updates of releases (build, server) for one test. Not parallel: LearnUpdates is global.
func learnUpdates(t *testing.T, rels map[[2]int][]monthly) {
	t.Helper()
	t.Cleanup(func() { winrel.LearnUpdates(nil) })
	var us []winrel.Update
	for k, ms := range rels {
		for _, m := range ms {
			us = append(us, winrel.Update{Build: k[0], Server: k[1] == 1, Rev: m.rev, KB: kbOf(m.rev), Day: winDay(m.day)})
		}
	}
	winrel.LearnUpdates(us)
}

// kbOf is the sample KB number the tests give the update of revision rev.
func kbOf(rev int) string { return fmt.Sprintf("KB5%06d", rev) }

// winHost is a device whose agent reports a Windows release row at build.rev, with the OS name given ("" = the release's name).
func winHost(build int, server bool, rev int, os string) Asset {
	r, ok := winrel.ByBuild(build, server)
	if !ok {
		panic("no release")
	}
	v := "10.0." + strconv.Itoa(build) + "." + strconv.Itoa(rev)
	if os == "" {
		os = "Microsoft " + r.Display
	}
	return Asset{ID: "a-win", Name: "Windows host", OS: os + " " + v, AgentOS: os, Software: []Software{{
		ID: "s-win", Display: r.Display, Vendor: "Microsoft", Product: "Windows", Version: v, Source: "agent",
		CPE: "cpe:2.3:o:microsoft:" + r.Product + ":" + v + ":*:*:*:*:*:*:*", KevKeys: []string{"microsoft|windows"}}}}
}

// The target of a Windows release's cumulative update is the newest monthly update Microsoft lists for the device's own release
// line when that is newer than every fixed build NVD names: NVD analyses a month's CVEs after Patch Tuesday, so without it a host a
// month behind is told to install last month's update. Never a build below NVD's; NVD's when Microsoft's list has nothing for the
// release. The count is then a floor (nvd_lag): the newest update's CVEs are not analysed by NVD yet, or the newest update is younger
// than winNVDLagWindow (now is t0, 2026-11-09: an October update is young, an August one is not). The sentence names the target's KB
// when Microsoft lists the build. Measured by class: every release line Microsoft services (server, client, LTSC, ESU), each with the
// list newer, older, equal and missing.
func TestPlan_WindowsTargetIsMicrosoftsNewestUpdate(t *testing.T) {
	type line struct {
		name    string
		build   int
		server  bool
		os      string // "" = the release's own name
		product string // NVD's name of the release
		rev     int    // the device's revision
		nvd     []int  // the fixed revisions NVD names, one CVE each, oldest first
		kind    string // the plan item's kind
		months  []monthly
	}
	lines := []line{
		{"Windows Server 2025", 26100, true, "", "windows_server_2025", 1742, []int{33438, 33650}, "windows",
			[]monthly{{"2026-09-08", 33438}, {"2026-10-13", 33650}, {"2026-11-10", 33822}}},
		{"Windows Server 2022", 20348, true, "", "windows_server_2022", 2700, []int{5600, 5761}, "windows",
			[]monthly{{"2026-09-08", 5600}, {"2026-10-13", 5761}, {"2026-11-10", 5870}}},
		{"Windows Server 2019", 17763, true, "", "windows_server_2019", 6000, []int{9376}, "windows",
			[]monthly{{"2026-10-13", 9376}, {"2026-11-10", 9487}}},
		{"Windows Server 2016", 14393, true, "", "windows_server_2016", 8000, []int{9612}, "windows",
			[]monthly{{"2026-10-13", 9612}, {"2026-11-10", 9688}}},
		{"Windows 11 25H2", 26200, false, "", "windows_11_25h2", 6584, []int{9711}, "windows",
			[]monthly{{"2026-10-13", 9711}, {"2026-11-10", 9974}}},
		{"Windows 11 24H2", 26100, false, "", "windows_11_24h2", 1742, []int{9711}, "windows",
			[]monthly{{"2026-10-13", 9711}, {"2026-11-10", 9974}}},
		{"Windows 10 Enterprise LTSC 2019", 17763, false, "Microsoft Windows 10 Enterprise LTSC 2019", "windows_10_1809", 6000, []int{9376}, "windows",
			[]monthly{{"2026-10-13", 9376}, {"2026-11-10", 9487}}},
		{"Windows 10 22H2 with ESU", 19045, false, "", "windows_10_22h2", 6456, []int{7807}, "esu",
			[]monthly{{"2026-10-13", 7807}, {"2026-11-10", 7846}}},
	}
	cve := 60000
	for _, l := range lines {
		var tv []TierVuln
		for _, r := range l.nvd {
			cve++
			tv = append(tv, tierV(fmt.Sprintf("CVE-2026-%d", cve), "recent", 40, 0.01, Affected{
				CPE: "cpe:2.3:o:microsoft:" + l.product + ":*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: fmt.Sprintf("10.0.%d.%d", l.build, r)}}))
		}
		build := func(rev int) string { return fmt.Sprintf("10.0.%d.%d", l.build, rev) }
		nvdMax := build(l.nvd[len(l.nvd)-1])
		newest := l.months[len(l.months)-1]
		key := [2]int{l.build, boolInt(l.server)}
		for _, c := range []struct {
			feed   string
			months []monthly
			fixed  string
			lag    bool
			kb     string
		}{
			{"newer than NVD", l.months, build(newest.rev), true, kbOf(newest.rev)},
			{"older than NVD", []monthly{{"2026-08-11", l.nvd[len(l.nvd)-1] - 50}}, nvdMax, false, ""},
			{"equal to NVD and young", l.months[:len(l.months)-1], nvdMax, true, kbOf(l.nvd[len(l.nvd)-1])},
			{"missing", nil, nvdMax, false, ""},
		} {
			t.Run(l.name+"/"+c.feed, func(t *testing.T) {
				learnUpdates(t, map[[2]int][]monthly{key: c.months})
				items, _ := planOf(winHost(l.build, l.server, l.rev, l.os), tv, nil)
				if len(items) != 1 || items[0].Kind != l.kind || items[0].Fixed != c.fixed || items[0].NVDLag != c.lag || items[0].KB != c.kb || len(items[0].CVEs) != len(l.nvd) {
					t.Fatalf("want one %s item to %s %s (lag %v) of %d CVEs, got %+v", l.kind, c.fixed, c.kb, c.lag, len(l.nvd), items)
				}
				u := planAction(items[0])
				want := strings.TrimPrefix(c.fixed, "10.0.") + " or later"
				if c.kb != "" {
					want += "; " + c.kb
				}
				if u.NVDLag != c.lag || !strings.Contains(updateSentence(u), want) {
					t.Errorf("action %+v: %q, want %q", u, updateSentence(u), want)
				}
			})
		}
	}
}

// The cases around the class: a server never takes the client list of the same build (Server 2025 and 24H2 are both 26100); a
// fixed build NVD names on the newest month itself (a hotpatch build below that month's B build) is no lag; the free updates of a
// release whose free servicing ended stay the target when the newest update needs Extended Security Updates; a feature update is
// never a build; exploited findings name the same target (one update per device).
func TestPlan_WindowsTargetAroundTheClass(t *testing.T) {
	srv := func(rev int) TierVuln {
		return tierV(fmt.Sprintf("CVE-2026-7%04d", rev%10000), "recent", 40, 0.01, Affected{
			CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: fmt.Sprintf("10.0.26100.%d", rev)}})
	}
	host := winHost(26100, true, 1742, "")

	// the client list of build 26100 only
	learnUpdates(t, map[[2]int][]monthly{{26100, 0}: {{"2026-11-10", 99974}}})
	if items, _ := planOf(host, []TierVuln{srv(33650)}, nil); len(items) != 1 || items[0].Fixed != "10.0.26100.33650" || items[0].NVDLag {
		t.Fatalf("server read the client list: %+v", items)
	}

	// NVD's newest fix is the August hotpatch build (33222), below August's B build (33296): the month is analysed, the target the
	// B build, no lag
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-07-14", 33158}, {"2026-08-11", 33296}}})
	if items, _ := planOf(host, []TierVuln{srv(33158), srv(33222)}, nil); len(items) != 1 || items[0].Fixed != "10.0.26100.33296" || items[0].NVDLag {
		t.Fatalf("hotpatch build of the newest month: %+v", items)
	}

	// Windows 10 22H2 below its last free revision (6456) with every fix NVD names free: the target is the newest free update, not
	// the newest one (ESU), and the free updates are long analysed (no lag)
	learnUpdates(t, map[[2]int][]monthly{{19045, 0}: {{"2025-07-08", 6093}, {"2025-10-14", 6456}, {"2026-11-10", 7846}}})
	w10 := tierV("CVE-2026-71001", "recent", 300, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.0.19045.6093"}})
	if items, _ := planOf(winHost(19045, false, 6000, ""), []TierVuln{w10}, nil); len(items) != 1 || items[0].Kind != "windows" || items[0].Fixed != "10.0.19045.6456" || items[0].KB != kbOf(6456) || items[0].NVDLag {
		t.Fatalf("free fixes: %+v", items)
	}

	// exploited findings of the device name the same target as its plan item
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-10-13", 33650}, {"2026-11-10", 33822}}})
	kev := nvdWindows("CVE-2026-71002", "2026-10-20", nvdRow{"windows_server_2025", "*", "*", "10.0.26100.33650"})
	fixes := RowFixes(host, []Vuln{kev})
	if f := fixes[kev.CVE]; f == nil || f.Fixed != "10.0.26100.33822" || f.KB != kbOf(33822) {
		t.Fatalf("exploited target: %+v", f)
	}
}

// NVD analyses a Patch Tuesday's CVEs over weeks: once one CVE of the newest month is analysed, NVD's highest fix is the newest update
// itself, and most of that month's CVEs are still missing. The count keeps saying "at least" while the newest update is younger than
// winNVDLagWindow, also when NVD's highest fix is an out-of-band build between two monthly updates; after it, the count is exact.
func TestPlan_WindowsLagWhileTheNewestUpdateIsYoung(t *testing.T) {
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-10-13", 33650}, {"2026-11-10", 33822}}})
	host := winHost(26100, true, 1742, "")
	srv := func(cve string, rev int) TierVuln {
		v := tierV(cve, "recent", 0, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: fmt.Sprintf("10.0.26100.%d", rev)}})
		v.Published = winDay("2026-10-13")
		return v
	}
	for _, c := range []struct {
		name string
		rev  int    // NVD's highest fix
		now  string // when the plan compares
		lag  bool
	}{
		{"one CVE of the newest month analysed, update 5 days old", 33822, "2026-11-15", true},
		{"one CVE of the newest month analysed, update 41 days old", 33822, "2026-12-21", true},
		{"newest month analysed, update 7 weeks old", 33822, "2026-12-29", false},
		{"highest fix an out-of-band build of last month, newest update 7 days old", 33674, "2026-11-17", true},
	} {
		items, _ := matchTiers(host, newTierIndex([]TierVuln{srv("CVE-2026-72001", 33650), srv("CVE-2026-72002", c.rev)}), nil, winDay(c.now))
		if len(items) != 1 || items[0].Fixed != "10.0.26100.33822" || items[0].KB != kbOf(33822) || items[0].NVDLag != c.lag {
			t.Errorf("%s: want 26100.33822 with lag %v, got %+v", c.name, c.lag, items)
		}
	}
}
