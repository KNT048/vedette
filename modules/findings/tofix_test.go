package findings

import "testing"

// kien G8: "To fix" lists every device with something to fix or plan, the most urgent first: a device with an exploited update to
// install (critical, ransomware) before one whose only findings are unproved product matches, before one with only a recommended
// update; a device with nothing is not listed.
func TestToFix_G8_MostUrgentDeviceFirst(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ranged := func(cve, end string, ransom bool) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Photo Station", Ransomware: ransom,
			Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: end}}}}
	}
	e.feeds.vulns = []Vuln{ranged("CVE-2099-0001", "6.1.2", false), ranged("CVE-2099-0002", "6.2.0", true)}
	urgentDev := nas("6.1.1")
	urgentDev.Software[0].Source = "agent"
	planOnly := nas("9.9.9") // not affected by the exploited CVEs; nginx below 1.26 gives it a recommended update
	planOnly.ID = "a-3"
	planOnly.Software = append(planOnly.Software, nginxRow("1.18.0", "agent"))
	clean := nas("9.9.9")
	clean.ID = "a-4"
	e.inv.mu.Lock()
	e.inv.match["a-1"], e.inv.match["a-3"], e.inv.match["a-4"] = urgentDev, planOnly, clean
	e.inv.mu.Unlock()
	e.feeds.tiers = []TierVuln{tierV("CVE-2026-41001", "recent", 30, 0.01, nginxBelow126())}
	e.feeds.stamp = "s1"
	for _, id := range []string{"a-1", "a-3", "a-4"} {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RefreshPlan(t.Context()); err != nil {
		t.Fatal(err)
	}
	tf, err := e.svc.ToFix(t.Context(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !tf.PlanRan || tf.PlanOff || tf.Truncated || len(tf.Devices) != 2 {
		t.Fatalf("devices %+v", tf)
	}
	if d := tf.Devices[0]; d.AssetID != "a-1" || len(d.Exploited) != 1 || d.Exploited[0].Action != "Upgrade Photo Station from 6.1.1 to 6.2.0 or later" || d.Exploited[0].Ransomware != 1 {
		t.Fatalf("the exploited, ransomware device first, one action: %+v", d)
	}
	if d := tf.Devices[1]; d.AssetID != "a-3" || len(d.Exploited) != 0 || len(d.Planned) != 1 || d.Planned[0].Fixed != "1.26.0" {
		t.Fatalf("then the device with only a recommended update: %+v", d)
	}
	// one device only (its Software tab)
	if one, err := e.svc.ToFix(t.Context(), true, "a-3"); err != nil || len(one.Devices) != 1 || one.Devices[0].AssetID != "a-3" {
		t.Fatalf("one device: %+v %v", one, err)
	}
	// feeds off: no recommended update, so the plan-only device is not listed
	off, err := e.svc.ToFix(t.Context(), false, "")
	if err != nil || !off.PlanOff || len(off.Devices) != 1 || off.Devices[0].AssetID != "a-1" {
		t.Fatalf("feeds off: %+v %v", off, err)
	}
}

// An unproved product match (no named update, nothing confirmed or detected) is the person's to check, not "to fix": its device
// comes after one with a proved action.
func TestToFix_G8_UnprovedIsNotUrgent(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // qnapVuln: a product match, no range
	pc := nas("6.1.1")
	pc.Software[0].Source = "agent"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = pc
	e.inv.mu.Unlock()
	e.seed()
	tf, err := e.svc.ToFix(t.Context(), true, "")
	if err != nil || len(tf.Devices) != 1 || len(tf.Devices[0].NoUpdate) != 1 || tf.Devices[0].NoUpdate[0].Proved() || len(tf.Devices[0].actionable()) != 0 {
		t.Fatalf("%+v %v", tf, err)
	}
}
