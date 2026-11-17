package findings

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// A Windows release row's plan item counts NVD's own list for that release and nothing else, cause by cause. NVD's list for
// Windows Server 2025 over the last 12 months is long (Microsoft's monthly updates list hundreds of CVEs each, and a host on its
// first build misses every one of them), so the count must come only from entries of the release itself whose fixed build is above
// the device's. Every other shape the tier data holds for a Windows host is counted here by cause and must add nothing: the item
// is the release's own entries, at the device's build, fixed by the newest build of the list.
func TestPlan_WindowsCountIsTheReleasesOwnList(t *testing.T) {
	t.Parallel()
	own := func(end string) Affected {
		return Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*", Range: VersionRange{EndExcl: end}}
	}
	// Monthly updates as NVD numbers them for Server 2025: the shared 24H2 numbering until early 2026, its own line after.
	months := []struct {
		days int
		fix  string
		n    int
	}{{340, "10.0.26100.7392", 3}, {300, "10.0.26100.32230", 4}, {150, "10.0.26100.32995", 5}, {60, "10.0.26100.33438", 7}, {30, "10.0.26100.33650", 9}}
	var tv []TierVuln
	seq := 50000
	cve := func() string { seq++; return fmt.Sprintf("CVE-2026-%d", seq) }
	byMonth := map[string][]string{}
	for _, m := range months {
		for range m.n {
			id := cve()
			tv = append(tv, tierV(id, "recent", m.days, 0.01, own(m.fix)))
			byMonth[m.fix] = append(byMonth[m.fix], id)
		}
	}
	// An application NVD lists "running on" Server 2025, with a range: the Windows release row reads only Windows release entries
	// (candidates), so it never counts there, whatever its platform condition says.
	dotnet := tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "4.8", EndExcl: "4.8.2"}})
	dotnet.Platforms = [][]string{{"microsoft:windows_server_2025"}}
	// One CVE as NVD writes a monthly update: the server's own row beside every client release and older servers (both
	// architectures), each with its own fixed build. It counts once, fixed at the server's own build.
	rel := func(product, hw, end string) Affected {
		return Affected{CPE: "cpe:2.3:o:microsoft:" + product + ":*:*:*:*:*:*:" + hw + ":*", Range: VersionRange{EndExcl: end}}
	}
	nvdShape := tierV(cve(), "recent", 30, 0.01, rel("windows_server_2025", "x64", "10.0.26100.33650"),
		rel("windows_11_24h2", "x64", "10.0.26100.9711"), rel("windows_11_24h2", "arm64", "10.0.26100.9711"),
		rel("windows_11_25h2", "x64", "10.0.26200.9711"), rel("windows_11_25h2", "arm64", "10.0.26200.9711"),
		rel("windows_11_26h1", "arm64", "10.0.28000.3231"), rel("windows_11_23h2", "x64", "10.0.22631.7121"),
		rel("windows_10_22h2", "x64", "10.0.19045.6575"), rel("windows_10_22h2", "x86", "10.0.19045.6575"),
		rel("windows_10_1809", "x64", "10.0.17763.8027"), rel("windows_server_2019", "x64", "10.0.17763.8027"),
		rel("windows_server_2022", "x64", "10.0.20348.4405"), rel("windows_server_2016", "x64", "10.0.14393.8594"))
	byMonth["10.0.26100.33650"] = append(byMonth["10.0.26100.33650"], nvdShape.CVE)
	// The same CVE's own row twice (x64 and any architecture, two ends): one CVE, counted once below both ends. Between the two ends
	// it is not counted on a host whose architecture is not known (INV-15: in range of every row, or not at all); NVD wrote no such
	// record for Server 2025 in the 12 months to November 2026 (each CVE has one end), so this only guards the shape.
	twoRows := tierV(cve(), "recent", 60, 0.01, rel("windows_server_2025", "x64", "10.0.26100.33438"), rel("windows_server_2025", "*", "10.0.26100.33222"))
	byMonth["10.0.26100.33438"] = append(byMonth["10.0.26100.33438"], twoRows.CVE)
	tv = append(tv, nvdShape, twoRows)
	kev := tierV(cve(), "recent", 30, 0.01, own("10.0.26100.33650"))
	noise := map[string]TierVuln{
		"fixed before the device's build":        tierV(cve(), "recent", 30, 0.01, own("10.0.26100.1700")),
		"client release on the same build":       tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*", Range: VersionRange{EndExcl: "10.0.26100.9711"}}),
		"application running on Windows":         dotnet,
		"application named windows_*":            tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:microsoft:windows_admin_center:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.4.2"}}),
		"release entry with no fixed build":      tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:*:*"}),
		"family entry for every Windows":         tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}),
		"on an exploited list":                   kev,
		"published more than 12 months ago":      tierV("CVE-2025-49999", "recent", 400, 0.01, own("10.0.26100.4061")),
		"another server release of the same era": tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:x64:*", Range: VersionRange{EndExcl: "10.0.20348.4405"}}),
	}
	for _, v := range noise {
		tv = append(tv, v)
	}
	host := func(build string) Asset {
		return Asset{ID: "a-srv25", Name: "Windows Server 2025 host", OS: "Microsoft Windows Server 2025 Standard", AgentOS: "Microsoft Windows Server 2025 Standard",
			Software: []Software{{ID: "s-win", Display: "Windows Server 2025", Vendor: "Microsoft", Product: "Windows", Version: build,
				CPE: "cpe:2.3:o:microsoft:windows_server_2025:" + build + ":*:*:*:*:*:*:*", Source: "agent", KevKeys: []string{"microsoft|windows"}}}}
	}
	exploited := map[string]bool{kev.CVE: true}

	// Cause by cause: no noise entry gives a plan CVE on its own.
	for cause, v := range noise {
		if items, _ := planOf(host("10.0.26100.1742"), []TierVuln{v}, exploited); len(items) != 0 {
			t.Errorf("%s: counted %+v", cause, items)
		}
	}

	// The host on its first build: every entry of its own release, one item, from its build to the newest fixed build.
	total := 2 // nvdShape and twoRows
	for _, m := range months {
		total += m.n
	}
	items, compared := planOf(host("10.0.26100.1742"), tv, exploited)
	if !compared || len(items) != 1 || items[0].Kind != "windows" || items[0].Version != "10.0.26100.1742" || items[0].Fixed != "10.0.26100.33650" || len(items[0].CVEs) != total {
		t.Fatalf("first build: want one item of %d CVEs from 10.0.26100.1742 to 10.0.26100.33650, got %+v", total, items)
	}
	// A host updated in the middle of the year: only the months after its build.
	items, _ = planOf(host("10.0.26100.32995"), tv, exploited)
	if want := len(byMonth["10.0.26100.33438"]) + len(byMonth["10.0.26100.33650"]); len(items) != 1 || len(items[0].CVEs) != want || items[0].Version != "10.0.26100.32995" {
		t.Fatalf("mid-year build: want %d CVEs, got %+v", want, items)
	}
	// A host exactly on a month's fixed build has that month's fix: only the later month counts.
	items, _ = planOf(host("10.0.26100.33438"), tv, exploited)
	if want := len(byMonth["10.0.26100.33650"]); len(items) != 1 || len(items[0].CVEs) != want {
		t.Fatalf("on the September build: want %d CVEs, got %+v", want, items)
	}
	if items, _ = planOf(host("10.0.26100.33222"), []TierVuln{twoRows}, exploited); len(items) != 0 {
		t.Fatalf("between the two ends of one CVE: %+v", items)
	}
	// A host on the newest build: nothing to plan.
	if items, _ = planOf(host("10.0.26100.33650"), tv, exploited); len(items) != 0 {
		t.Fatalf("newest build: %+v", items)
	}
}

// Every Windows update sentence names the device's build and the fixed one, as an upgrade of any other software names its version.
func TestUpdateSentence_WindowsNamesTheDevicesBuild(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		u    UpdateAction
		want string
	}{
		{UpdateAction{Software: "Windows Server 2025", Version: "10.0.26100.1742", Fixed: "10.0.26100.33650", Kind: "windows", Windows: true},
			"Install the latest cumulative update for Windows Server 2025 (from build 26100.1742 to 26100.33650 or later)"},
		{UpdateAction{Software: "Windows Server 2025", Version: "10.0.26100.1742", Fixed: "10.0.26100.33650", Kind: "fixed", Windows: true},
			"Install the latest cumulative update for Windows Server 2025 (from build 26100.1742 to 26100.33650 or later)"},
		{UpdateAction{Software: "Windows 10 22H2", Version: "10.0.19045.6456", Fixed: "10.0.19045.6575", Kind: "esu", Windows: true},
			"Install the Extended Security Update for Windows 10 22H2 (from build 19045.6456 to 19045.6575 or later; it needs an ESU subscription)"},
		{UpdateAction{Software: "Windows Server 2025", Fixed: "10.0.26100.33650", Kind: "windows", Windows: true},
			"Install the latest cumulative update for Windows Server 2025 (build 26100.33650 or later)"},
		{UpdateAction{Software: "Windows 10 21H2", Version: "10.0.19044.5000", Fixed: "Windows 10 22H2", Kind: "feature_update", Windows: true},
			"Upgrade Windows 10 21H2 to Windows 10 22H2: some of these get no update for this release"},
		{UpdateAction{Software: "FortiOS", Version: "7.2.13", Fixed: "7.6.7", Kind: "fixed"}, "Upgrade FortiOS from 7.2.13 to 7.6.7 or later"},
	} {
		if got := updateSentence(c.u); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.u, got, c.want)
		}
	}
}

// GET /findings/plan says when the version of an agent's row is only the last list an agent sent: no agent of this box reports the
// device now (the binary's AgentReports, agent-intake's report state). The item then carries agent_gone and the day the row was
// last reported; a device an agent reports, a row a person typed, and a box with no agent check (nil) say nothing.
func TestPlan_AgentGoneSaysTheLastReport(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	seen := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	agentRow := nginxRow("1.18.0", "agent")
	agentRow.SeenAt = seen
	e.inv.assets["a-gone"] = AssetView{ID: "a-gone", Hostname: ptr("old-web"), IP: "192.168.10.31", Kind: "server", Name: "old-web"}
	e.inv.match["a-gone"] = Asset{ID: "a-gone", Name: "old-web", Software: []Software{agentRow}}
	e.inv.assets["a-live"] = AssetView{ID: "a-live", Hostname: ptr("web01"), IP: "192.168.10.30", Kind: "server", Name: "web01"}
	e.inv.match["a-live"] = Asset{ID: "a-live", Name: "web01", Software: []Software{agentRow}}
	e.inv.assets["a-typed"] = AssetView{ID: "a-typed", Hostname: ptr("typed"), IP: "192.168.10.32", Kind: "server", Name: "typed"}
	e.inv.match["a-typed"] = Asset{ID: "a-typed", Name: "typed", Software: []Software{nginxRow("1.18.0", "manual")}}
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126())}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	byDevice := func() map[string]map[string]any {
		_, b := e.call("GET", "/findings/plan", "viewer", "")
		out := map[string]map[string]any{}
		for _, it := range b["items"].([]any) {
			m := it.(map[string]any)
			out[m["asset"].(map[string]any)["id"].(string)] = m
		}
		return out
	}
	if got := byDevice(); len(got) != 3 || got["a-gone"]["agent_gone"] != false || got["a-gone"]["agent_reported"] != nil {
		t.Fatalf("no agent check: nothing is said: %v", got)
	}
	asked := map[string]int{}
	e.fh.SetAgents(func(_ context.Context, id string) bool { asked[id]++; return id != "a-gone" })
	got := byDevice()
	if g := got["a-gone"]; g["agent_gone"] != true || g["agent_reported"] != "2026-10-02" {
		t.Fatalf("no agent reports old-web: %v", g)
	}
	if l := got["a-live"]; l["agent_gone"] != false || l["agent_reported"] != nil {
		t.Fatalf("an agent reports web01: %v", l)
	}
	if ty := got["a-typed"]; ty["agent_gone"] != false || asked["a-typed"] != 0 {
		t.Fatalf("a typed row asks no agent: %v (asked %d)", ty, asked["a-typed"])
	}
}
