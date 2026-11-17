package findings

import "testing"

// G4 (kien): the risk marker of a device in every list reads what "To fix" shows for it (one rule, G8): red = its open exploited
// findings To fix lists (an update is named, or the box proved them), with their count; amber = none of those, but a recommended update
// fixes a CVE likely to be exploited or of High or Critical severity; nothing when clean.
func TestRiskByAsset_G4_AgreesWithToFix(t *testing.T) {
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
	high := tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126()) // High (CVSS 7.5), EPSS 1%
	e.feeds.tiers = []TierVuln{high}
	e.feeds.stamp = "s1"
	for _, id := range []string{"a-1", "a-3", "a-4"} {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.RiskByAsset(t.Context(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	if got["a-1"] != (AssetRisk{Exploited: 2}) || got["a-3"] != (AssetRisk{Updates: 1}) || len(got) != 2 {
		t.Fatalf("risk = %+v: want a-1 two exploited findings to fix, a-3 one High update, a-4 clean", got)
	}
	// One rule: every device To fix lists has exactly RiskOf of what it shows.
	tf, err := e.svc.ToFix(t.Context(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range tf.Devices {
		if got[d.AssetID] != RiskOf(d) {
			t.Errorf("%s: marker %+v, To fix %+v", d.AssetID, got[d.AssetID], RiskOf(d))
		}
	}
	// One device (the device page); the feeds module off: no recommended update counts.
	if one, err := e.svc.RiskByAsset(t.Context(), true, "a-3"); err != nil || len(one) != 1 || one["a-3"].Updates != 1 {
		t.Errorf("one device: %+v %v", one, err)
	}
	if off, _ := e.svc.RiskByAsset(t.Context(), false, ""); len(off) != 1 || off["a-1"].Exploited != 2 {
		t.Errorf("feeds off: %+v", off)
	}

	// A Medium recommended update nobody is likely to exploit is no marker; a likely one is.
	medium := tierV("CVE-2026-41003", "recent", 30, 0.01, nginxBelow126())
	medium.Severity, medium.Score = "medium", ptr(5.0)
	e.feeds.tiers, e.feeds.stamp = []TierVuln{medium}, "s2"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.svc.RiskByAsset(t.Context(), true, ""); got["a-3"] != (AssetRisk{}) {
		t.Errorf("a Medium, unlikely update marks the device: %+v", got["a-3"])
	}
	likely := tierV("CVE-2026-41002", "likely", 60, 0.34, nginxBelow126())
	likely.Severity, likely.Score = "medium", ptr(5.0)
	e.feeds.tiers, e.feeds.stamp = []TierVuln{likely}, "s3"
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.svc.RiskByAsset(t.Context(), true, ""); got["a-3"] != (AssetRisk{Updates: 1}) {
		t.Errorf("a likely update: %+v", got["a-3"])
	}
}

// A product-only guess (no update named, nothing proved) is in "Needs your input", not To fix: no red marker.
func TestRiskByAsset_G4_AnUnprovedGuessIsNoMarker(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // qnapVuln: a product match, no range
	e.seed()
	got, err := e.svc.RiskByAsset(t.Context(), true, "")
	if err != nil || len(got) != 0 {
		t.Fatalf("risk = %+v, %v", got, err)
	}
	// the same for the one device (the device page)
	if got, _ = e.svc.RiskByAsset(t.Context(), false, "a-1"); len(got) != 0 {
		t.Fatalf("one device = %+v", got)
	}
}
