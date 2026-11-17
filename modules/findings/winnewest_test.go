package findings

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// srv25 is a tier CVE of Windows Server 2025 fixed in build 26100.rev, published on day.
func srv25(cve string, rev int, day string) TierVuln {
	v := tierV(cve, "recent", 0, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: fmt.Sprintf("10.0.26100.%d", rev)}})
	v.Published = winDay(day)
	return v
}

// On Patch Tuesday every Windows device is one update behind, and NVD analyses that update's CVEs over the next weeks. A Windows
// release row below the newest monthly update Microsoft lists for its release gets an item at once, naming the update (build and KB)
// with no CVE yet; once NVD analyses a CVE of it the row has the usual item, with the same target and a count, never a second one.
// Every release line Microsoft services, client and server, one month behind with no CVE analysed.
func TestPlan_WindowsNewestUpdateBeforeNVD(t *testing.T) {
	now := winDay("2026-11-17")
	lines := []struct {
		name   string
		build  int
		server bool
		os     string
		prev   int // last month's update: the device's revision
		newest int
		kind   string
	}{
		{"Windows Server 2025", 26100, true, "", 33650, 33822, "windows"},
		{"Windows Server 2022", 20348, true, "", 5761, 5870, "windows"},
		{"Windows Server 2019", 17763, true, "", 9376, 9487, "windows"},
		{"Windows Server 2016", 14393, true, "", 9612, 9688, "windows"},
		{"Windows 11 25H2", 26200, false, "", 9711, 9974, "windows"},
		{"Windows 11 24H2", 26100, false, "", 9711, 9974, "windows"},
		{"Windows 10 Enterprise LTSC 2019", 17763, false, "Microsoft Windows 10 Enterprise LTSC 2019", 9376, 9487, "windows"},
		{"Windows 10 22H2 with ESU", 19045, false, "", 7807, 7846, "esu"},
	}
	for _, l := range lines {
		t.Run(l.name, func(t *testing.T) {
			learnUpdates(t, map[[2]int][]monthly{{l.build, boolInt(l.server)}: {{"2026-10-13", l.prev}, {"2026-11-10", l.newest}}})
			items, compared := matchTiers(winHost(l.build, l.server, l.prev, l.os), newTierIndex(nil), nil, now)
			want := fmt.Sprintf("10.0.%d.%d", l.build, l.newest)
			if !compared || len(items) != 1 || items[0].Kind != l.kind || items[0].Fixed != want || items[0].KB != kbOf(l.newest) || !items[0].NVDLag ||
				len(items[0].CVEs) != 0 || !awaitsNVD(items[0]) || items[0].Basis != planAgent || items[0].Group != "a-win/s-win" {
				t.Fatalf("one month behind: want one %s item to %s %s with no CVE, got %+v", l.kind, want, kbOf(l.newest), items)
			}
			// on the newest update: nothing
			if items, _ := matchTiers(winHost(l.build, l.server, l.newest, l.os), newTierIndex(nil), nil, now); len(items) != 0 {
				t.Fatalf("current: %+v", items)
			}
		})
	}
}

// The cases around the class.
func TestPlan_WindowsNewestUpdateAroundTheClass(t *testing.T) {
	now := winDay("2026-11-17")
	learnUpdates(t, map[[2]int][]monthly{
		{26100, 1}: {{"2026-09-08", 33438}, {"2026-10-13", 33650}, {"2026-11-10", 33822}},
		{19045, 0}: {{"2025-10-14", 6456}, {"2026-10-13", 7807}, {"2026-11-10", 7846}},
		{22631, 0}: {{"2026-10-13", 7652}, {"2026-11-10", 7711}},
	})
	sentence := func(it PlanItem) string { return updateSentence(planAction(it)) }

	// two months behind with some CVEs analysed (October's): the usual item, Microsoft's newest update its target, never a second row
	oct := srv25("CVE-2026-73001", 33650, "2026-10-13")
	items, _ := matchTiers(winHost(26100, true, 33438, ""), newTierIndex([]TierVuln{oct}), nil, now)
	if len(items) != 1 || len(items[0].CVEs) != 1 || items[0].Fixed != "10.0.26100.33822" || !items[0].NVDLag || items[0].KB != kbOf(33822) {
		t.Fatalf("two months behind: %+v", items)
	}
	// one month behind, 0 analysed: named with its build and KB
	items, _ = matchTiers(winHost(26100, true, 33650, ""), newTierIndex([]TierVuln{oct}), nil, now)
	if len(items) != 1 || len(items[0].CVEs) != 0 || sentence(items[0]) != "Install the latest cumulative update for Windows Server 2025 (from build 26100.33650 to 26100.33822 or later; "+kbOf(33822)+")" {
		t.Fatalf("one month behind: %+v %q", items, sentence(items[0]))
	}
	// the device's build is not known: no item (a release row without a revision is not read as one)
	noRev := winHost(26100, true, 33650, "")
	noRev.Software[0].Version, noRev.Software[0].CPE = "10.0.26100", "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100:*:*:*:*:*:*:*"
	if items, _ := matchTiers(noRev, newTierIndex(nil), nil, now); len(items) != 0 {
		t.Fatalf("unknown build: %+v", items)
	}
	// a version read from the network is no basis for the plan
	scanned := winHost(26100, true, 33650, "")
	scanned.Software[0].Source = "nmap"
	if items, _ := matchTiers(scanned, newTierIndex(nil), nil, now); len(items) != 0 {
		t.Fatalf("a scanned version: %+v", items)
	}
	// ESU: Windows 10 22H2 on its last free update; the newest update needs Extended Security Updates
	items, _ = matchTiers(winHost(19045, false, 6456, ""), newTierIndex(nil), nil, now)
	if len(items) != 1 || items[0].Kind != "esu" || items[0].Fixed != "10.0.19045.7846" ||
		sentence(items[0]) != "Install the Extended Security Update for Windows 10 22H2 (from build 19045.6456 to 19045.7846 or later; "+kbOf(7846)+"; it needs an ESU subscription)" {
		t.Fatalf("ESU: %+v", items)
	}
	// a release that ended for the device (Windows 11 23H2, no LTSC, no ESU): Microsoft's list is the Enterprise editions', no item
	if items, _ := matchTiers(winHost(22631, false, 7652, ""), newTierIndex(nil), nil, now); len(items) != 0 {
		t.Fatalf("ended release: %+v", items)
	}
	// no list for the release (the client list of build 26100 is empty here): no item
	if items, _ := matchTiers(winHost(26100, false, 9711, ""), newTierIndex(nil), nil, now); len(items) != 0 {
		t.Fatalf("no list: %+v", items)
	}
	// the agent's row and a typed row of the same install: one item
	two := winHost(26100, true, 33650, "")
	typed := two.Software[0]
	typed.ID, typed.Source = "s-typed", "manual"
	two.Software = append(two.Software, typed)
	items, _ = matchTiers(two, newTierIndex(nil), nil, now)
	if len(items) != 1 || items[0].SoftwareID != "s-win" {
		t.Fatalf("two rows of one install: %+v", items)
	}
	// it ranks after every item with a CVE
	ranked := []PlanItem{items[0], {Group: "a/b", Kind: "fixed", CVEs: []PlanCVE{{CVE: "CVE-2026-1", Tier: "recent"}}}}
	sortPlanItems(ranked)
	if ranked[0].Group != "a/b" {
		t.Fatalf("order: %+v", ranked)
	}
	// it is kept as the 12-month line moves (it never had a CVE), and planned as an action with no CVE
	if kept := listedPlanItems(items, now.AddDate(1, 0, 0)); len(kept) != 1 {
		t.Fatalf("listed: %+v", kept)
	}
	if u := planAction(items[0]); !u.NVDLag || len(u.CVEs) != 0 || u.KB != kbOf(33822) || riskyUpdate(u) {
		t.Fatalf("action: %+v", u)
	}
}

// Through the endpoints: GET /findings/plan lists the item under All and Recent (not Likely) with no CVE and says when no agent reports
// the device any more; GET /findings/to-fix plans it on the device.
func TestPlan_WindowsNewestUpdateThroughTheEndpoints(t *testing.T) {
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-10-13", 33650}, {"2026-11-10", 33822}}})
	e := newHTTPEnv(t)
	host := winHost(26100, true, 33650, "")
	host.ID, host.Software[0].SeenAt = "a-srv", time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	e.inv.assets["a-srv"] = AssetView{ID: "a-srv", Hostname: ptr("srv25"), IP: "192.168.10.40", Kind: "server", Name: "Windows Server 2025 host"}
	e.inv.match["a-srv"] = host
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.fh.SetAgents(func(context.Context, string) bool { return false })
	_, b := e.call("GET", "/findings/plan", "viewer", "")
	items := b["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("plan: %v", b)
	}
	it := items[0].(map[string]any)
	if it["fixed"] != "10.0.26100.33822" || it["kb"] != kbOf(33822) || it["nvd_lag"] != true || len(it["cves"].([]any)) != 0 || it["kind"] != "windows" ||
		it["agent_gone"] != true || it["agent_reported"] != "2026-11-02" {
		t.Fatalf("item: %v", it)
	}
	if c := b["counts"].(map[string]any); c["all"] != float64(1) || c["recent"] != float64(1) || c["likely"] != float64(0) {
		t.Fatalf("counts: %v", c)
	}
	if _, l := e.call("GET", "/findings/plan?tier=likely", "viewer", ""); len(l["items"].([]any)) != 0 {
		t.Fatalf("likely: %v", l)
	}
	if _, r := e.call("GET", "/findings/plan?tier=recent", "viewer", ""); len(r["items"].([]any)) != 1 {
		t.Fatalf("recent: %v", r)
	}
	_, tf := e.call("GET", "/findings/to-fix", "viewer", "")
	devs := tf["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("to fix: %v", tf)
	}
	planned := devs[0].(map[string]any)["planned"].([]any)
	if len(planned) != 1 || planned[0].(map[string]any)["action"] != "Install the latest cumulative update for Windows Server 2025 (from build 26100.33650 to 26100.33822 or later; "+kbOf(33822)+")" ||
		planned[0].(map[string]any)["nvd_lag"] != true || len(planned[0].(map[string]any)["cves"].([]any)) != 0 {
		t.Fatalf("planned: %v", planned)
	}
}

// When an exploited-list entry of the newest month already has the row (NVD analyses those first), To fix names the same update with
// the same target: the plan names no second row saying its CVEs are not analysed.
func TestPlan_WindowsNewestUpdateNotWhenExploited(t *testing.T) {
	now := winDay("2026-11-17")
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-10-13", 33650}, {"2026-11-10", 33822}}})
	host := winHost(26100, true, 33650, "")
	zeroDay := nvdWindows("CVE-2026-74001", "2026-11-10", nvdRow{"windows_server_2025", "*", "*", "10.0.26100.33822"})
	if f := RowFixes(host, []Vuln{zeroDay})[zeroDay.CVE]; f == nil || f.Fixed != "10.0.26100.33822" || f.KB != kbOf(33822) {
		t.Fatalf("the exploited row: %+v", f)
	}
	x := newTierIndex(nil).withKEV([]Vuln{zeroDay})
	if items, _ := matchTiers(host, x, map[string]bool{zeroDay.CVE: true}, now); len(items) != 0 {
		t.Fatalf("a second row for the exploited update: %+v", items)
	}
	// an exploited entry the device is not inside (fixed in October) does not stand for the newest update
	old := nvdWindows("CVE-2026-74002", "2026-10-13", nvdRow{"windows_server_2025", "*", "*", "10.0.26100.33650"})
	if items, _ := matchTiers(host, newTierIndex(nil).withKEV([]Vuln{old}), map[string]bool{old.CVE: true}, now); len(items) != 1 || len(items[0].CVEs) != 0 {
		t.Fatalf("no exploited row: want the newest update, got %+v", items)
	}
}

// A device enrolled in hotpatching runs the month's hotpatch, below that month's B build but with its security fixes: it is current to
// the month, for the newest-update row and for the rows with counts (an NVD range that ends at the month's B build does not hold it),
// and for exploited findings; the month after, it is one update behind like any other device, named from its own build.
func TestPlan_WindowsHotpatchIsCurrentForItsMonth(t *testing.T) {
	now := winDay("2026-11-17")
	t.Cleanup(func() { winrel.LearnUpdates(nil) })
	learn := func(extra ...winrel.Update) {
		winrel.LearnUpdates(append([]winrel.Update{
			{Build: 26100, Server: true, Rev: 33650, KB: kbOf(33650), Day: winDay("2026-10-13")},
			{Build: 26100, Server: true, Rev: 33822, KB: kbOf(33822), Day: winDay("2026-11-10")},
			{Build: 26100, Server: true, Rev: 33730, KB: kbOf(33730), Day: winDay("2026-11-10"), Hotpatch: true},
		}, extra...))
	}
	learn()
	hot := winHost(26100, true, 33730, "")
	nov := srv25("CVE-2026-75001", 33822, "2026-11-12")
	if items, _ := matchTiers(hot, newTierIndex([]TierVuln{nov}), nil, now); len(items) != 0 {
		t.Fatalf("hotpatch of the newest month: %+v", items)
	}
	zeroDay := nvdWindows("CVE-2026-75002", "2026-11-10", nvdRow{"windows_server_2025", "*", "*", "10.0.26100.33822"})
	if fixes := RowFixes(hot, []Vuln{zeroDay}); len(fixes) != 0 {
		t.Fatalf("exploited: %+v", fixes)
	}
	if w, m := oneMatch(t, hot, zeroDay, true); w != "notaffected" {
		t.Fatalf("exploited match: %s %+v", w, m)
	}
	// the same build on a device not on hotpatch would be below November's update: only a revision Microsoft lists as a hotpatch counts
	if items, _ := matchTiers(winHost(26100, true, 33731, ""), newTierIndex([]TierVuln{nov}), nil, now); len(items) != 1 || len(items[0].CVEs) != 1 {
		t.Fatalf("not a hotpatch: %+v", items)
	}
	// December's update is out: the hotpatch device is one update behind, named from the build it runs
	learn(winrel.Update{Build: 26100, Server: true, Rev: 33950, KB: kbOf(33950), Day: winDay("2026-12-08")})
	items, _ := matchTiers(hot, newTierIndex([]TierVuln{nov}), nil, winDay("2026-12-10"))
	if len(items) != 1 || len(items[0].CVEs) != 0 || items[0].Fixed != "10.0.26100.33950" || items[0].Version != "10.0.26100.33730" {
		t.Fatalf("a month later: %+v", items)
	}
}

// "Its CVEs are not yet analysed by NVD" holds while the update is young (winNVDLagWindow); after it the row stays, the device is still
// behind, but nvd_lag is false: the pages say NVD lists no CVE of it for the release yet. Past AgeLimit (the feed has not been read for a
// year) no update is named.
func TestPlan_WindowsNewestUpdateAge(t *testing.T) {
	learnUpdates(t, map[[2]int][]monthly{{26100, 1}: {{"2026-10-13", 33650}, {"2026-11-10", 33822}}})
	host := winHost(26100, true, 33650, "")
	for _, c := range []struct {
		now   string
		items int
		lag   bool
	}{{"2026-11-17", 1, true}, {"2026-12-21", 1, true}, {"2026-12-23", 1, false}, {"2027-11-12", 0, false}} {
		items, _ := matchTiers(host, newTierIndex(nil), nil, winDay(c.now))
		if len(items) != c.items || c.items == 1 && items[0].NVDLag != c.lag {
			t.Errorf("%s: want %d item (lag %v), got %+v", c.now, c.items, c.lag, items)
		}
	}
}
