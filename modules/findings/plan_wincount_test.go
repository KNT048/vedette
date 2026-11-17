package findings

import (
	"fmt"
	"testing"
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
	dotnet := tierV(cve(), "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*"})
	dotnet.Platforms = [][]string{{"microsoft:windows_server_2025"}}
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
	total := 0
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
