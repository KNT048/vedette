package findings

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// G4 (kien): the risk marker of a device in every list uses To fix's tests (one rule, G8): red = its open exploited findings To fix
// counts as something to fix; amber = none of those, but a recommended update fixes a CVE likely to be exploited or of High or Critical
// severity; nothing when clean. RiskMap reads them in one batch, never per device.

// riskOfToFix is what To fix shows for device d, read the way RiskMap must agree with.
func riskOfToFix(d DeviceUpdates) AssetRisk {
	var r AssetRisk
	for _, a := range d.actionable() {
		r.Exploited += len(a.CVEs)
	}
	for _, u := range d.Planned {
		if riskyUpdate(u) {
			r.Updates++
		}
	}
	return r
}

func TestRiskMap_G4_AgreesWithToFix(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ranged := func(cve, end string) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Photo Station",
			Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: end}}}}
	}
	e.feeds.vulns = []Vuln{ranged("CVE-2099-0001", "6.1.2"), ranged("CVE-2099-0002", "6.2.0")}
	exploited := nas("6.1.1")
	exploited.Software[0].Source = "agent"
	withNginx := func(id string) Asset {
		a := nas("9.9.9") // not affected by the exploited CVEs; nginx below 1.26 gets the tier CVEs
		a.ID = id
		a.Software = append(a.Software, nginxRow("1.18.0", "agent"))
		return a
	}
	clean := nas("9.9.9")
	clean.ID = "a-4"
	e.inv.mu.Lock()
	e.inv.match["a-1"], e.inv.match["a-3"], e.inv.match["a-4"] = exploited, withNginx("a-3"), clean
	e.inv.mu.Unlock()
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126())} // High (CVSS 7.5), EPSS 1%
	e.feeds.stamp = "s1"
	for _, id := range []string{"a-1", "a-3", "a-4"} {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.RiskMap(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]AssetRisk{"a-1": {Exploited: 2}, "a-3": {Updates: 1}}) {
		t.Fatalf("risk = %+v: want a-1 two exploited findings to fix, a-3 one High update, a-4 clean", got)
	}
	// One rule: every device To fix lists has the marker of what it shows.
	tf, err := e.svc.ToFix(t.Context(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range tf.Devices {
		if got[d.AssetID] != riskOfToFix(d) {
			t.Errorf("%s: marker %+v, To fix %+v", d.AssetID, got[d.AssetID], riskOfToFix(d))
		}
	}
	if off, _ := e.svc.RiskMap(t.Context(), false); len(off) != 1 || off["a-1"].Exploited != 2 {
		t.Errorf("feeds off: %+v", off)
	}

	// A Medium recommended update nobody is likely to exploit is no marker; a likely one is.
	medium := tierV("CVE-2026-41003", "recent", 30, 0.01, nginxBelow126())
	medium.Severity, medium.Score = "medium", ptr(5.0)
	e.feeds.tiers, e.feeds.stamp = []TierVuln{medium}, "s2"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.svc.RiskMap(t.Context(), true); got["a-3"] != (AssetRisk{}) {
		t.Errorf("a Medium, unlikely update marks the device: %+v", got["a-3"])
	}
	likely := tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126())
	likely.Severity, likely.Score = "medium", ptr(5.0)
	e.feeds.tiers, e.feeds.stamp = []TierVuln{likely}, "s3"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.svc.RiskMap(t.Context(), true); got["a-3"] != (AssetRisk{Updates: 1}) {
		t.Errorf("a likely update (the plan changed: the cache is dropped): %+v", got["a-3"])
	}
}

// Closed, not relevant and risk-accepted findings are no risk; a product-only guess is in Needs your input, not To fix.
func TestRiskMap_G4_OnlyOpenFindingsToFix(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // qnapVuln: a product match, no range
	id := e.seed()
	if got, err := e.svc.RiskMap(t.Context(), true); err != nil || len(got) != 0 {
		t.Fatalf("an unproved product match: %+v, %v", got, err)
	}
	// make it a finding To fix counts (a scan confirmed it), then accept the risk, then close it
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.RiskMap(t.Context(), true); got["a-1"] != (AssetRisk{Exploited: 1}) {
		t.Fatalf("confirmed: %+v (a write must drop the cache)", got)
	}
	if _, _, err := e.svc.setStatusMany(t.Context(), []string{id}, ActionAcceptRisk, "until the vendor ships it", "it@acme.example", dayOf(t0).AddDate(0, 0, 30)); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.RiskMap(t.Context(), true); len(got) != 0 {
		t.Errorf("risk accepted: %+v", got)
	}
	if _, err := e.svc.SetStatus(t.Context(), id, ActionReopen, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.RiskMap(t.Context(), true); len(got) != 0 {
		t.Errorf("patched: %+v", got)
	}
}

// Review r1 of #949 (N+1): many devices with findings and recommended updates cost one batch, with no read per device, and a
// second read is the cached answer until something changes.
func TestRiskMap_G4_OneBatchForManyDevices(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const n = 300
	e.inv.mu.Lock()
	for i := range n {
		a := nas("9.9.9")
		a.ID = fmt.Sprintf("a-%03d", i)
		a.Software = append(a.Software, nginxRow("1.18.0", "agent"))
		e.inv.match[a.ID] = a
	}
	e.inv.mu.Unlock()
	e.feeds.tiers, e.feeds.stamp = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126())}, "s1"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	e.inv.mu.Lock()
	e.inv.onMatch = func(string) { reads.Add(1) }
	e.inv.mu.Unlock()
	start := time.Now()
	got, err := e.svc.RiskMap(t.Context(), true)
	if err != nil || len(got) != n {
		t.Fatalf("%d devices marked, %v", len(got), err)
	}
	if reads.Load() != 0 {
		t.Errorf("RiskMap read %d devices one by one", reads.Load())
	}
	again, _ := e.svc.RiskMap(t.Context(), true)
	if reflect.ValueOf(again).Pointer() != reflect.ValueOf(got).Pointer() {
		t.Error("the second read was not the cached answer")
	}
	t.Logf("%d devices: %v", n, time.Since(start))
}

// The pages read the marker from their own answer (no device list): GET /findings/to-fix and GET /findings/plan carry each device's
// risk; the Vedette box itself is never marked, while To fix still lists its updates (review r1 of #949).
func TestRiskMap_G4_ToFixAndPlanCarryTheMarkerNotForTheBox(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	for _, id := range []string{"a-web", "a-box"} {
		a := nas("9.9.9")
		a.ID = id
		a.Software = append(a.Software, nginxRow("1.18.0", "agent"))
		e.inv.assets[id] = AssetView{ID: id, Name: id, IP: "192.168.10.30", Kind: "server", Box: id == "a-box"}
		e.inv.match[id] = a
	}
	e.feeds.tiers, e.feeds.stamp = []TierVuln{tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126())}, "s1"
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "ready", EPSSDate: t0, RecentSince: t0.AddDate(0, 0, -365)}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	risks := func(path, list string) map[string]any {
		t.Helper()
		_, b := e.call("GET", path, "viewer", "")
		out := map[string]any{}
		for _, x := range b[list].([]any) {
			m := x.(map[string]any)
			out[m["asset"].(map[string]any)["id"].(string)] = m["risk"]
		}
		return out
	}
	want := map[string]any{"level": "update", "exploited": float64(0), "updates": float64(1)}
	for _, path := range []string{"/findings/to-fix", "/findings/plan?tier=all"} {
		list := "devices"
		if path != "/findings/to-fix" {
			list = "items"
		}
		got := risks(path, list)
		if !reflect.DeepEqual(got["a-web"], want) {
			t.Errorf("%s a-web: %v", path, got["a-web"])
		}
		if r, listed := got["a-box"]; !listed || r != nil {
			t.Errorf("%s: the box is listed with no marker, got listed=%v risk=%v", path, listed, r)
		}
	}
}
