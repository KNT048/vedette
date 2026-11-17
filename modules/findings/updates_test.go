package findings

import (
	"slices"
	"testing"
)

// G9 (J4, kien: "an osquery device needs confirming too? I want which apps to update"): many exploited CVEs of one product on a device
// whose agent reports the version are ONE action ("Upgrade Photo Station from 6.1.1 to 6.3.0 or later", 4 CVEs, worst critical), all
// detected, none "suspected"; a banner-read version on another device is suspected; the plan's items of the device come in the same
// answer with their software row.
func TestDeviceUpdates_G9_OneActionPerUpdateAgentIsDetected(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ranged := func(cve, end string, ransom bool) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Photo Station", Ransomware: ransom,
			Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: end}}}}
	}
	e.feeds.vulns = []Vuln{ranged("CVE-2099-0001", "6.1.2", false), ranged("CVE-2099-0002", "6.2.0", true), ranged("CVE-2099-0003", "6.3.0", false),
		ranged("CVE-2099-0004", "6.2.5", false)}
	pc := nas("6.1.1")
	pc.Software[0].Source = "agent"
	pc.Software = append(pc.Software, nginxRow("1.18.0", "agent"))
	guess := nas("6.1.1")
	guess.ID, guess.Software[0].Source = "a-2", "nmap"
	e.inv.mu.Lock()
	e.inv.match["a-1"], e.inv.match["a-2"] = pc, guess
	e.inv.mu.Unlock()
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126()), tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126())}
	e.feeds.stamp = "s1"
	for _, id := range []string{"a-1", "a-2"} {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}

	u, ok, err := e.svc.DeviceUpdates(t.Context(), "a-1")
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if u.Open != 4 || len(u.Exploited) != 1 || len(u.NoUpdate) != 0 {
		t.Fatalf("one action for the 4 findings of one product: %+v", u)
	}
	x := u.Exploited[0]
	if x.Action != "Upgrade Photo Station from 6.1.1 to 6.3.0 or later" || len(x.CVEs) != 4 || len(x.FindingIDs) != 4 || x.Worst != "critical" ||
		x.CVEs[0] != "CVE-2099-0002" || x.Ransomware != 1 || x.SoftwareID != "s-1" || x.Version != "6.1.1" {
		t.Fatalf("action %+v", x)
	}
	if x.Detected != 4 || x.Suspected != 0 || x.Confirmed != 0 {
		t.Fatalf("the agent reported the version: detected, never suspected: %+v", x)
	}
	if !u.PlanRan || len(u.Planned) != 1 || u.Planned[0].SoftwareID != "s-ng" || u.Planned[0].Fixed != "1.26.0" || len(u.Planned[0].CVEs) != 2 ||
		u.Planned[0].Likely != 1 || u.Planned[0].Worst != "high" || u.Planned[0].Action != "Upgrade nginx from 1.18.0 to 1.26.0 or later" {
		t.Fatalf("planned %+v", u.Planned)
	}

	g, _, err := e.svc.DeviceUpdates(t.Context(), "a-2")
	if err != nil || len(g.Exploited) != 1 || g.Exploited[0].Suspected != 4 || g.Exploited[0].Detected != 0 {
		t.Fatalf("a banner's version is a network guess: suspected: %+v %v", g, err)
	}
	if _, ok, err := e.svc.DeviceUpdates(t.Context(), "a-none"); ok || err != nil {
		t.Fatalf("unknown device: %v %v", ok, err)
	}
}

// A product-only finding names no update: it is listed apart, by its software row, and an agent's row is still detected (D-612).
func TestDeviceUpdates_G9_ProductOnlyIsNoNamedUpdate(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // qnapVuln has no ranges: a product match on Photo Station
	pc := nas("6.1.1")
	pc.Software[0].Source = "agent"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = pc
	e.inv.mu.Unlock()
	e.seed()
	u, _, err := e.svc.DeviceUpdates(t.Context(), "a-1")
	if err != nil || len(u.Exploited) != 0 || len(u.NoUpdate) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	n := u.NoUpdate[0]
	if n.Kind != "none" || n.SoftwareID != "s-1" || !slices.Equal(n.CVEs, []string{"CVE-2022-27593"}) || n.Detected != 1 || n.Suspected != 0 {
		t.Fatalf("no named update %+v", n)
	}
}
