package findings

import (
	"slices"
	"testing"
	"time"
)

// deviceUpdates is one device's answer of To fix (ToFix with that device): the grouping of its open findings by the update that fixes
// them and its recommended updates. ok is false for a device the inventory does not have.
func deviceUpdates(t *testing.T, e *env, assetID string, feedsOn bool) (DeviceUpdates, bool, error) {
	t.Helper()
	tf, err := e.svc.ToFix(t.Context(), feedsOn, assetID)
	if err != nil {
		return DeviceUpdates{}, false, err
	}
	if len(tf.Devices) > 0 {
		return tf.Devices[0], true, nil
	}
	_, ok, err := e.svc.cfg.Inventory.MatchInput(t.Context(), assetID)
	return DeviceUpdates{AssetID: assetID, PlanOff: !feedsOn}, ok, err
}

// Many exploited CVEs of one product on a device
// whose agent reports the version are ONE action ("Upgrade Photo Station from 6.1.1 to 6.3.0 or later", 4 CVEs, worst critical), all
// detected, none "suspected"; a banner-read version on another device is suspected; the plan's items of the device come in the same
// answer with their software row.
func TestDeviceUpdates_OneActionPerUpdateAgentIsConfirmed(t *testing.T) {
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

	u, ok, err := deviceUpdates(t, e, "a-1", true)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if u.Open != 4 || len(u.Exploited) != 1 || len(u.NoUpdate) != 0 {
		t.Fatalf("one action for the 4 findings of one product: %+v", u)
	}
	x := u.Exploited[0]
	if x.Action != "Upgrade Photo Station from 6.1.1 to 6.3.0 or later" || len(x.CVEs) != 4 || len(x.FindingIDs) != 4 || x.Worst != "medium" ||
		!slices.Contains(x.CVEs, "CVE-2099-0002") || x.Ransomware != 1 || x.SoftwareID != "s-1" || x.Version != "6.1.1" {
		t.Fatalf("action %+v", x)
	}
	if x.Confirmed != 4 || x.Suspected != 0 || x.Detected != 0 { // the finding page says confirmed: To fix counts it the same
		t.Fatalf("the agent reported the version inside the range: confirmed, never suspected: %+v", x)
	}
	if !u.PlanRan || !u.PlanCompared || u.PlanOff || len(u.Planned) != 1 || u.Planned[0].SoftwareID != "s-ng" || u.Planned[0].Fixed != "1.26.0" || len(u.Planned[0].CVEs) != 2 ||
		u.Planned[0].Likely != 1 || u.Planned[0].Worst != "high" || u.Planned[0].Action != "Upgrade nginx from 1.18.0 to 1.26.0 or later" {
		t.Fatalf("planned %+v", u.Planned)
	}

	g, _, err := deviceUpdates(t, e, "a-2", true)
	if err != nil || len(g.Exploited) != 1 || g.Exploited[0].Suspected != 4 || g.Exploited[0].Detected != 0 {
		t.Fatalf("a banner's version is a network guess: suspected: %+v %v", g, err)
	}
	if !g.PlanRan || g.PlanCompared || len(g.Planned) != 0 {
		t.Fatalf("review r1 M4 of #935: a device the plan could not compare says so, it is not 0 updates: %+v", g)
	}
	// review r1 L1: the feeds module off lists no recommended update, as GET /findings/plan
	if off, _, _ := deviceUpdates(t, e, "a-1", false); !off.PlanOff || off.Planned != nil || len(off.Exploited) != 1 {
		t.Fatalf("feeds off: %+v", off)
	}
	// review r1 L5: a recommended CVE that crossed the 12-month line since the pass is left out, as on the page
	e.advance(310 * 24 * time.Hour) // the 60-day-old CVE is now older than 12 months, the 30-day-old one is not
	if late, _, _ := deviceUpdates(t, e, "a-1", true); len(late.Planned) != 1 || !slices.Equal(late.Planned[0].CVEs, []string{"CVE-2026-41001"}) || late.Planned[0].Likely != 0 {
		t.Fatalf("12-month cut: %+v", late.Planned)
	}
	if _, ok, err := deviceUpdates(t, e, "a-none", true); ok || err != nil {
		t.Fatalf("unknown device: %v %v", ok, err)
	}
}

// A product-only finding names no update: it is listed apart, by its software row; on an agent's row it is "reported" (the agent gave
// the version, Vedette could not compare it: review r1 M1 of #935), never suspected nor "inside the range".
func TestDeviceUpdates_ProductOnlyIsNoNamedUpdate(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // qnapVuln has no ranges: a product match on Photo Station
	pc := nas("6.1.1")
	pc.Software[0].Source = "agent"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = pc
	e.inv.mu.Unlock()
	e.seed()
	u, _, err := deviceUpdates(t, e, "a-1", true)
	if err != nil || len(u.Exploited) != 0 || len(u.NoUpdate) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	n := u.NoUpdate[0]
	if n.Kind != "none" || n.SoftwareID != "s-1" || !slices.Equal(n.CVEs, []string{"CVE-2022-27593"}) || n.Reported != 1 || n.Detected != 0 || n.Suspected != 0 {
		t.Fatalf("no named update %+v", n)
	}
}

// Review r1 L2, L5 of #935: a version a person typed is one the plan trusts (tierSource): detected; a finding whose CVE left the
// exploited list has no row and no update: it is listed under no named update with an empty software row, and the counts still sum.
func TestDeviceUpdates_ManualRowIsDetectedAndALeftCVEStays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := Vuln{CVE: "CVE-2099-0001", Vendor: "QNAP", Product: "Photo Station", Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "6.2.0"}}}}
	e.feeds.vulns = []Vuln{v, qnapScanned()} // the scannable one stays a product finding
	typed := nas("6.1.1")
	typed.Software[0].Source = "manual"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = typed
	e.inv.mu.Unlock()
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	e.feeds.vulns = []Vuln{v} // CVE-2022-27593 left the list; its finding stays open
	u, _, err := deviceUpdates(t, e, "a-1", true)
	if err != nil || u.Open != 2 || len(u.Exploited) != 1 || u.Exploited[0].Detected != 1 || u.Exploited[0].Suspected != 0 {
		t.Fatalf("manual row: %+v %v", u, err)
	}
	if len(u.NoUpdate) != 1 || u.NoUpdate[0].Group != "a-1/" || u.NoUpdate[0].SoftwareID != "" || !slices.Equal(u.NoUpdate[0].CVEs, []string{"CVE-2022-27593"}) {
		t.Fatalf("left the list: %+v", u.NoUpdate)
	}
}
