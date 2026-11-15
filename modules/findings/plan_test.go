package findings

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// Tier data of the plan tests: t0 is 2026-11-09.
func tierV(cve, tier string, daysAgo int, epss float64, aff ...Affected) TierVuln {
	v := TierVuln{CVE: cve, Tier: tier, Published: t0.AddDate(0, 0, -daysAgo), Severity: "high", Score: ptr(7.5), Affected: aff}
	if epss >= 0 {
		v.EPSS, v.Percentile = ptr(epss), ptr(0.9)
	}
	return v
}

// nginxBelow126 is NVD's entry "nginx before 1.26.0".
func nginxBelow126() Affected {
	return Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "1.26.0"}}
}

// nginxRow is the device's nginx row s-ng.
func nginxRow(version, source string) Software {
	return Software{ID: "s-ng", Display: "nginx", Vendor: "F5", Product: "nginx", Version: version, CPE: "cpe:2.3:a:f5:nginx:" + version + ":*:*:*:*:*:*:*", Source: source}
}

func planOf(a Asset, tv []TierVuln, kev map[string]bool) ([]PlanItem, bool) {
	return matchTiers(a, newTierIndex(tv), kev, t0)
}

func cvesOf(it PlanItem) []string {
	var out []string
	for _, c := range it.CVEs {
		out = append(out, c.CVE+"/"+c.Tier+"/"+c.Basis)
	}
	return out
}

// S-TIER-1/2 guards (D-613 (2), D-615, D-617): only a version proved inside a range that ends gives a plan CVE; an exploited CVE, one
// older than 12 months, a product-only entry (no range), a version outside, a banner version and a distribution's package give none.
// One item per update (D-545): "Upgrade nginx from 1.18.0 to 1.26.0", likely first.
func TestPlan_VersionConfirmedOnly(t *testing.T) {
	t.Parallel()
	tv := []TierVuln{
		tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126()),
		tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126()),
		tierV("CVE-2026-41003", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}),                                                            // every version, no range: product-only
		tierV("CVE-2026-41004", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "2.0.0", EndExcl: "2.1.0"}}), // outside
		tierV("CVE-2026-41005", "likely", 30, 0.5, nginxBelow126()),                                                                                                 // on an exploited list: a finding, never here
		tierV("CVE-2025-41006", "likely", 400, 0.5, nginxBelow126()),                                                                                                // older than 12 months, no scan
		tierV("CVE-2026-41007", "recent", 30, -1, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.0.0"}}),                     // no end: no fix to plan
	}
	kev := map[string]bool{"CVE-2026-41005": true}
	a := Asset{ID: "a-web", Name: "web01", OS: "Ubuntu 24.04 LTS", Software: []Software{nginxRow("1.18.0", "agent")}}
	items, compared := planOf(a, tv, kev)
	if !compared || len(items) != 1 {
		t.Fatalf("compared %v, items %+v", compared, items)
	}
	it := items[0]
	if it.Group != "a-web/s-ng" || it.Kind != "fixed" || it.Fixed != "1.26.0" || it.Version != "1.18.0" || it.Software != "nginx" {
		t.Fatalf("item %+v", it)
	}
	if got := cvesOf(it); !slices.Equal(got, []string{"CVE-2026-41002/likely/agent", "CVE-2026-41001/recent/agent"}) {
		t.Fatalf("cves %v", got)
	}
	if c := it.CVEs[0]; c.Published != "2026-09-10" || c.Severity == nil || *c.Severity != "high" || c.EPSS == nil || *c.EPSS != 0.34 {
		t.Fatalf("cve %+v", c)
	}
	// A version a person typed is exact too (basis version); a banner (nmap), the scan's guess and a row of unknown origin are not.
	a.Software = []Software{nginxRow("1.18.0", "manual")}
	if items, _ = planOf(a, tv, kev); len(items) != 1 || items[0].CVEs[0].Basis != "version" {
		t.Fatalf("manual: %+v", items)
	}
	for _, src := range []string{"nmap", "scan", "passive", ""} {
		a.Software = []Software{nginxRow("1.18.0", src)}
		if items, compared = planOf(a, tv, kev); len(items) != 0 || compared {
			t.Fatalf("source %q: compared %v, %+v", src, compared, items)
		}
	}
	// A distribution's package: its fixes are backported, NVD's upstream range would put a patched build inside (D-617).
	pkg := nginxRow("1.18.0", "agent")
	pkg.Packaged, pkg.PkgVersion, pkg.PkgSource = true, "1.18.0-6ubuntu14.6", "nginx"
	marked := nginxRow("1.18.0-6ubuntu14.6", "manual")
	for _, s := range []Software{pkg, marked} {
		a.Software = []Software{s}
		if items, _ = planOf(a, tv, kev); len(items) != 0 {
			t.Fatalf("package %+v: %+v", s, items)
		}
	}
}

// D-545 grouping when no one release fixes every CVE of a row: each CVE goes to the item of its own nearest fix, and a CVE NVD names no
// fixed release for (only an inclusive end) is left out: there is no update to plan for it.
func TestPlan_SplitsByFixWhenNoReleaseFixesAll(t *testing.T) {
	t.Parallel()
	tv := []TierVuln{
		tierV("CVE-2026-42001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.0.0", EndExcl: "1.20.0"}}),
		tierV("CVE-2026-42002", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.18.0", EndIncl: "1.30.0"}}),
	}
	items, _ := planOf(Asset{ID: "a-web", Software: []Software{nginxRow("1.18.0", "agent")}}, tv, nil)
	if len(items) != 1 || items[0].Fixed != "1.20.0" || items[0].Group != "a-web/s-ng/fixed/1.20.0" || !slices.Equal(cvesOf(items[0]), []string{"CVE-2026-42001/recent/agent"}) {
		t.Fatalf("items %+v", items)
	}
}

// D-546, D-610 on tier CVEs: a Windows release row reads NVD's entries by its monthly update; the item is the cumulative update with
// the build that fixes them all. An entry naming only older Windows releases (XP) is never a match.
func TestPlan_WindowsByMonthlyUpdate(t *testing.T) {
	t.Parallel()
	ws := func(end string) Affected {
		return Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.0.20348.0", EndExcl: end}}
	}
	tv := []TierVuln{
		tierV("CVE-2026-43001", "likely", 20, 0.27, ws("10.0.20348.4405")),
		tierV("CVE-2026-43002", "recent", 50, 0.03, ws("10.0.20348.3207")),
		tierV("CVE-2026-43003", "recent", 50, 0.03, ws("10.0.20348.2600")), // fixed before the device's build
		tierV("CVE-2026-43004", "recent", 50, 0.03, Affected{CPE: "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:*:*:*:*"}),
	}
	a := Asset{ID: "a-srv", Name: "srv-acc", OS: "Microsoft Windows Server 2022 Standard", Software: []Software{{ID: "s-win", Display: "Windows Server 2022",
		Vendor: "Microsoft", Product: "Windows", Version: "10.0.20348.2700", CPE: "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:x64:*", Source: "agent", KevKeys: []string{"microsoft|windows"}}}}
	items, _ := planOf(a, tv, nil)
	if len(items) != 1 || items[0].Kind != "windows" || items[0].Fixed != "10.0.20348.4405" ||
		!slices.Equal(cvesOf(items[0]), []string{"CVE-2026-43001/likely/agent", "CVE-2026-43002/recent/agent"}) {
		t.Fatalf("items %+v", items)
	}
}

// The scope asks feeds only for the products the devices run (D-617): a compared row's product, its aliases and Windows releases for a
// Windows row; never the product of a banner row.
func TestPlan_TierScopeKeepsOnlyTheDevicesProducts(t *testing.T) {
	t.Parallel()
	sc := NewTierScope([]Asset{{ID: "a", Software: []Software{nginxRow("1.18.0", "agent"),
		{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.0", Source: "nmap"}}}})
	for cpe, want := range map[string]bool{
		"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*":                      true,
		"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*":               false,
		"cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*": false,
		"not a cpe": false,
	} {
		if sc.Keep(cpe) != want {
			t.Errorf("Keep(%s) = %v", cpe, !want)
		}
	}
	if NewTierScope([]Asset{{ID: "b", Software: []Software{{ID: "s", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.0", Source: "nmap"}}}}).Empty() != true {
		t.Fatal("a device with banner rows only needs no tier data")
	}
}

// The plan job and GET /findings/plan (S-TIER-1, S-TIER-2, D-617): "Not compared yet" until the job's first run, then the items with
// the device's name, the tier filter, the counts of compared and unchecked devices; a device whose software changed is compared again
// at the next run without a full pass, and a deleted device's items go at once.
func TestPlan_JobAndEndpoint(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.inv.assets["a-web"] = AssetView{ID: "a-web", Hostname: ptr("web01"), IP: "192.168.10.30", Kind: "server", Name: "web01"}
	e.inv.match["a-web"] = Asset{ID: "a-web", Name: "web01", Software: []Software{nginxRow("1.18.0", "agent")}}
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126()), tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126())}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	e.feeds.stamp = "s1"
	if _, b := e.call("GET", "/findings/plan", "viewer", ""); b["compared"] != false {
		t.Fatalf("before the job: %v", b)
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, b := e.call("GET", "/findings/plan", "viewer", "")
	items, _ := b["items"].([]any)
	if c != 200 || b["compared"] != true || len(items) != 1 || b["compared_devices"] != float64(1) || b["unchecked_devices"] != float64(1) || b["old_evidence"] != float64(0) {
		t.Fatalf("%d %v", c, b)
	}
	it := items[0].(map[string]any)
	if it["asset"].(map[string]any)["name"] != "web01" || it["likely"] != float64(1) || it["recent"] != float64(1) || it["fixed"] != "1.26.0" || it["kind"] != "fixed" {
		t.Fatalf("item %v", it)
	}
	if _, b = e.call("GET", "/findings/plan?tier=likely", "viewer", ""); len(b["items"].([]any)) != 1 || len(b["items"].([]any)[0].(map[string]any)["cves"].([]any)) != 1 {
		t.Fatalf("likely: %v", b)
	}
	if _, b = e.call("GET", "/findings/plan?asset=a-1", "viewer", ""); len(b["items"].([]any)) != 0 {
		t.Fatalf("other device: %v", b)
	}
	// The device is upgraded: the next run compares it again (no stamp change, so not a full pass).
	e.inv.match["a-web"] = Asset{ID: "a-web", Name: "web01", Software: []Software{nginxRow("1.26.0", "agent")}}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 1 {
		t.Fatalf("no event, no stamp change: the plan stays until the next full pass: %+v", v)
	}
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-web"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 0 || v.Compared != 1 {
		t.Fatalf("after the upgrade: %+v", v)
	}
	// A new pull (stamp) compares everything again; the feeds module off shows no item.
	e.inv.match["a-web"] = Asset{ID: "a-web", Name: "web01", Software: []Software{nginxRow("1.18.0", "agent")}}
	e.feeds.stamp = "s2"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 1 {
		t.Fatalf("after a pull: %+v", v)
	}
	e.gate.Set("feeds", false)
	if _, b = e.call("GET", "/findings/plan", "viewer", ""); len(b["items"].([]any)) != 0 {
		t.Fatalf("feeds off: %v", b)
	}
	e.gate.Set("feeds", true)
	if _, err := e.svc.OnAssetDeleted(t.Context(), "a-web"); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 0 || v.Compared != 0 {
		t.Fatalf("after the delete: %+v", v)
	}
}

// Measured for the PR (D-617): a pass over tier data sized like the N100 (104,448 CVEs, about 2 NVD entries each, 21 devices with
// about 40 compared rows each) once feeds kept only the devices' products, and the index and match without that filter (the worst
// case: every CVE in memory), and a Windows device. Run: go test ./modules/findings -run '^$' -bench Plan -benchmem
func BenchmarkPlanPass(b *testing.B) {
	const cves = 104_448
	products := 5_000
	tv := make([]TierVuln, cves)
	for i := range tv {
		p := i % products
		tv[i] = tierV(fmt.Sprintf("CVE-2026-%05d", i+10000), "recent", i%360, 0.01,
			Affected{CPE: fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", p, p), Range: VersionRange{StartIncl: "1.0", EndExcl: fmt.Sprintf("2.%d", i%50)}},
			Affected{CPE: fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", p, p+1), Range: VersionRange{EndExcl: "3.0"}})
	}
	assets := make([]Asset, 21)
	for d := range assets {
		a := Asset{ID: fmt.Sprintf("a-%d", d), Name: fmt.Sprintf("dev%d", d)}
		for s := range 40 {
			p := (d*40 + s) % products
			a.Software = append(a.Software, Software{ID: fmt.Sprintf("s-%d-%d", d, s), Display: "Product", Vendor: fmt.Sprintf("vendor%d", p), Product: fmt.Sprintf("product%d", p),
				Version: "1.5", Source: "agent", CPE: fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:1.5:*:*:*:*:*:*:*", p, p)})
		}
		assets[d] = a
	}
	run := func(b *testing.B, tv []TierVuln) {
		b.ReportAllocs()
		for b.Loop() {
			sc := NewTierScope(assets)
			var kept []TierVuln
			for _, v := range tv {
				if slices.ContainsFunc(v.Affected, func(af Affected) bool { return sc.Keep(af.CPE) }) {
					kept = append(kept, v)
				}
			}
			x := newTierIndex(kept)
			n := 0
			for _, a := range assets {
				items, _ := matchTiers(a, x, nil, t0)
				n += len(items)
			}
			if n == 0 {
				b.Fatal("no item")
			}
		}
	}
	b.Run("scope_filter_and_match", func(b *testing.B) { run(b, tv) })
	// Review r1 #7 of #804: one Windows Server 2022 release row against 1,200 Windows CVEs of NVD's real shape (12 releases × 4 targets =
	// 48 entries each), the costliest device of a pass.
	b.Run("windows_device", func(b *testing.B) {
		rels := []struct {
			p     string
			build int
		}{{"windows_10_1809", 17763}, {"windows_10_21h2", 19044}, {"windows_10_22h2", 19045}, {"windows_11_22h2", 22621}, {"windows_11_23h2", 22631},
			{"windows_11_24h2", 26100}, {"windows_11_25h2", 26200}, {"windows_server_2016", 14393}, {"windows_server_2019", 17763},
			{"windows_server_2022", 20348}, {"windows_server_2022_23h2", 25398}, {"windows_server_2025", 26100}}
		win := make([]TierVuln, 1200)
		for i := range win {
			var aff []Affected
			for _, r := range rels {
				for _, tg := range []string{"x64", "x86", "arm64", "*"} {
					aff = append(aff, Affected{CPE: fmt.Sprintf("cpe:2.3:o:microsoft:%s:*:*:*:*:*:*:%s:*", r.p, tg),
						Range: VersionRange{StartIncl: fmt.Sprintf("10.0.%d.0", r.build), EndExcl: fmt.Sprintf("10.0.%d.%d", r.build, 2000+i)}})
				}
			}
			win[i] = tierV(fmt.Sprintf("CVE-2026-%05d", 60000+i), "recent", i%360, 0.01, aff...)
		}
		dev := Asset{ID: "a-srv", OS: "Microsoft Windows Server 2022 Standard", Software: []Software{{ID: "s-win", Display: "Windows Server 2022", Vendor: "Microsoft", Product: "Windows",
			Version: "10.0.20348.2700", CPE: "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:x64:*", Source: "agent", KevKeys: []string{"microsoft|windows"}}}}
		b.Run("index", func(b *testing.B) { // once per pass, whatever the number of devices
			b.ReportAllocs()
			for b.Loop() {
				newTierIndex(win)
			}
		})
		b.Run("match", func(b *testing.B) { // per Windows device
			x := newTierIndex(win)
			b.ReportAllocs()
			for b.Loop() {
				if items, _ := matchTiers(dev, x, nil, t0); len(items) != 1 {
					b.Fatal(len(items))
				}
			}
		})
	})
	b.Run("index_all_and_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			x := newTierIndex(tv)
			for _, a := range assets {
				matchTiers(a, x, nil, t0)
			}
		}
	})
}

// Review r1 #5 of #804: on a Windows release past its end of support (Windows 10 22H2: every fix after 19045.6456 is an Extended
// Security Update) the item says ESU, never a plain "install the latest cumulative update".
func TestPlan_WindowsESU(t *testing.T) {
	t.Parallel()
	w10 := Affected{CPE: "cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*", Range: VersionRange{StartIncl: "10.0.19045.0", EndExcl: "10.0.19045.6900"}}
	a := Asset{ID: "a-pc", Name: "pc1", OS: "Microsoft Windows 10 Pro", Software: []Software{{ID: "s-win", Display: "Windows 10 22H2", Vendor: "Microsoft", Product: "Windows",
		Version: "10.0.19045.6456", CPE: "cpe:2.3:o:microsoft:windows_10_22h2:10.0.19045.6456:*:*:*:*:*:x64:*", Source: "agent", KevKeys: []string{"microsoft|windows"}}}}
	items, _ := planOf(a, []TierVuln{tierV("CVE-2026-44001", "recent", 20, 0.02, w10)}, nil)
	if len(items) != 1 || items[0].Kind != "esu" || items[0].Fixed != "10.0.19045.6900" {
		t.Fatalf("items %+v", items)
	}
}

// Review r1 #6 of #804: an NVD entry "running on" operating systems counts only when the device's OS is known and is one of them;
// an entry stored before Vedette kept the condition ("?") never counts.
func TestPlan_PlatformConditionNeedsAKnownOS(t *testing.T) {
	t.Parallel()
	v := tierV("CVE-2026-45001", "recent", 20, 0.02, nginxBelow126())
	v.Platforms = [][]string{{"microsoft:windows"}}
	dev := func(agentOS, source string) Asset {
		return Asset{ID: "a-web", AgentOS: agentOS, Software: []Software{nginxRow("1.18.0", source)}}
	}
	for _, c := range []struct {
		name string
		a    Asset
		want int
	}{
		{"agent on Windows", dev("Microsoft Windows Server 2022 Standard", "agent"), 1},
		{"agent on Ubuntu", dev("Ubuntu 24.04.1 LTS", "agent"), 0},
		{"agent, OS not reported", dev("", "agent"), 0},
		{"typed version, OS not known", dev("Microsoft Windows Server 2022", "manual"), 0},
	} {
		if items, _ := planOf(c.a, []TierVuln{v}, nil); len(items) != c.want {
			t.Errorf("%s: %d items, want %d", c.name, len(items), c.want)
		}
	}
	unknown := v
	unknown.Platforms = [][]string{{"?"}}
	if items, _ := planOf(dev("Microsoft Windows Server 2022", "agent"), []TierVuln{unknown}, nil); len(items) != 0 {
		t.Fatalf("condition not known: %+v", items)
	}
	none := v
	none.Platforms = [][]string{{}}
	if items, _ := planOf(dev("", "agent"), []TierVuln{none}, nil); len(items) != 1 {
		t.Fatalf("no condition: %+v", items)
	}
}

// Review r1 #10 of #804: two rows of one product on a device (the agent's and a typed one) list each CVE once, under the agent's row.
func TestPlan_OneCVEOncePerDevice(t *testing.T) {
	t.Parallel()
	typed := nginxRow("1.18.0", "manual")
	typed.ID = "s-typed"
	a := Asset{ID: "a-web", Software: []Software{typed, nginxRow("1.18.0", "agent")}}
	items, _ := planOf(a, []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126())}, nil)
	if len(items) != 1 || items[0].Group != "a-web/s-ng" || items[0].CVEs[0].Basis != "agent" {
		t.Fatalf("items %+v", items)
	}
}

// Review r1 #2, #3, #4 of #804: a CVE that crossed the 12-month line after the pass is not listed and not counted as scan evidence; the
// tier stamp moving (the feeds module turned back on) or a long gap of the job forces a full pass; a device deleted while a pass reads
// it is not written back.
func TestPlan_AgeAtRequestStampGapAndDelete(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.inv.assets["a-web"] = AssetView{ID: "a-web", Name: "web01"}
	e.inv.match["a-web"] = Asset{ID: "a-web", Name: "web01", Software: []Software{nginxRow("1.18.0", "agent")}}
	e.feeds.tiers = []TierVuln{tierV("CVE-2025-46001", "recent", 364, 0.01, nginxBelow126())}
	e.feeds.stamp = "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 1 {
		t.Fatalf("pass: %+v", v)
	}
	e.advance(2 * 24 * time.Hour) // the CVE is now 366 days old; no pass ran since
	if _, b := e.call("GET", "/findings/plan", "viewer", ""); len(b["items"].([]any)) != 0 || b["old_evidence"] != float64(0) {
		t.Fatalf("after the 12 months: %v", b)
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil { // an hour since the last full pass: a full one
		t.Fatal(err)
	}
	// the job did not run for longer than two periods (the findings module was off), within the hour: the next run compares everything
	e.advance(11 * time.Minute)
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-46002", "recent", 10, 0.01, nginxBelow126())}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 1 || v.Items[0].CVEs[0].CVE != "CVE-2026-46002" {
		t.Fatalf("after a gap: %+v", v)
	}
	// the stamp moves (feeds module back on): a full pass at once, within the hour and the period
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-46003", "recent", 10, 0.01, nginxBelow126())}
	e.advance(time.Minute)
	e.feeds.stamp = "feeds-off"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 1 || v.Items[0].CVEs[0].CVE != "CVE-2026-46003" {
		t.Fatalf("after the stamp moved: %+v", v)
	}
	// deleted while the next full pass reads it
	e.feeds.stamp = "s2"
	e.inv.onMatch = func(id string) {
		if _, err := e.svc.OnAssetDeleted(t.Context(), id); err != nil {
			t.Error(err)
		}
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Plan(); len(v.Items) != 0 || v.Compared+v.Unchecked != 0 {
		t.Fatalf("a deleted device was written back: %+v", v)
	}
}

// Review r2 #2 of #804: two installs of one product at two versions (side-by-side runtimes) each get their item; only the same install
// seen twice folds.
func TestPlan_TwoInstallsKeepTheirItems(t *testing.T) {
	t.Parallel()
	newer := nginxRow("1.24.0", "agent")
	newer.ID = "s-ng-124"
	v := tierV("CVE-2026-47001", "recent", 30, 0.01, Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.18.0", EndExcl: "1.18.5"}},
		Affected{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "1.24.0", EndExcl: "1.24.3"}})
	items, _ := planOf(Asset{ID: "a-web", Software: []Software{nginxRow("1.18.0", "agent"), newer}}, []TierVuln{v}, nil)
	fixes := []string{}
	for _, it := range items {
		fixes = append(fixes, it.Version+">"+it.Fixed)
	}
	slices.Sort(fixes)
	if !slices.Equal(fixes, []string{"1.18.0>1.18.5", "1.24.0>1.24.3"}) {
		t.Fatalf("items %v", fixes)
	}
}
