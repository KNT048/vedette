package findings

import (
	"database/sql"
	"slices"
	"testing"
)

// kien G8: "To fix" lists every device with something to fix or plan, the most urgent first: a device with an exploited update to
// install before one with only a recommended update; a device with nothing is not listed.
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
	// review r2 of #943: every action carries the product's identity, so "By fix" merges the same product across device names
	if p := tf.Devices[0].Exploited[0].Product; p != "qnap|photo station" {
		t.Errorf("exploited product %q", p)
	}
	// kien G12: the row's source too, so the page's "I updated it" follows who reports the version
	if src := tf.Devices[0].Exploited[0].Source; src != "agent" {
		t.Errorf("exploited source %q", src)
	}
	if src := tf.Devices[1].Planned[0].Source; src != "agent" {
		t.Errorf("planned source %q", src)
	}
	if p := tf.Devices[1].Planned[0].Product; p != "f5|nginx" {
		t.Errorf("planned product %q", p)
	}
	if u, _, _ := e.svc.DeviceUpdates(t.Context(), "a-3", true); len(u.Planned) != 1 || u.Planned[0].Product != "f5|nginx" {
		t.Errorf("DeviceUpdates planned product: %+v", u.Planned)
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

// Review r1 of #943: the order field by field, each step deciding where the ones before it tie: something to fix, the worst
// severity, ransomware, proved findings, CVEs, then the plan; a full tie by id.
func TestToFix_G8_UrgencyFieldByField(t *testing.T) {
	t.Parallel()
	ex := func(worst string, ransom, proved, cves int) UpdateAction {
		u := UpdateAction{Kind: "fixed", Worst: worst, Ransomware: ransom, Detected: proved, Suspected: cves - proved}
		for range cves {
			u.CVEs = append(u.CVEs, "CVE")
		}
		return u
	}
	dev := func(id string, acts []UpdateAction, planned ...UpdateAction) DeviceUpdates {
		return DeviceUpdates{AssetID: id, Exploited: acts, Planned: planned}
	}
	unproved := DeviceUpdates{AssetID: "a-unproved", NoUpdate: []UpdateAction{{Kind: "none", Worst: "critical", Ransomware: 5, Reported: 9, CVEs: []string{"x"}}}}
	ds := []DeviceUpdates{
		unproved, // nothing to fix, nothing to plan: last
		dev("a-plan", nil, UpdateAction{Kind: "fixed", Worst: "critical", Likely: 3, CVEs: []string{"x"}}), // only a plan
		dev("a-z-tie", []UpdateAction{ex("high", 0, 1, 1)}),
		dev("a-a-tie", []UpdateAction{ex("high", 0, 1, 1)}),
		dev("a-more-cves", []UpdateAction{ex("high", 0, 1, 5)}),
		dev("a-proved", []UpdateAction{ex("high", 0, 3, 3)}),
		dev("a-ransom-high", []UpdateAction{ex("high", 2, 1, 1)}),
		dev("a-critical", []UpdateAction{ex("critical", 0, 0, 1)}), // critical beats ransomware on a high
	}
	sortByUrgency(ds)
	var got []string
	for _, d := range ds {
		got = append(got, d.AssetID)
	}
	want := []string{"a-critical", "a-ransom-high", "a-proved", "a-more-cves", "a-a-tie", "a-z-tie", "a-plan", "a-unproved"}
	if !slices.Equal(got, want) {
		t.Fatalf("order\n got %v\nwant %v", got, want)
	}
}

// Review r2 of #943: the cap keeps the devices To fix lists. Versionless product-only guesses (Critical, ransomware) on many devices
// never push out a PC with a proved exploited CVE and a named update.
func TestToFix_G8_CapKeepsTheProvedDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// two ransomware product-only guesses on Surveillance Station (no range) on four devices; the PC has one ranged CVE, no ransomware
	guess := func(cve string) Vuln {
		return Vuln{CVE: cve, Vendor: "QNAP", Product: "Surveillance Station", Ransomware: true, HasTemplate: true} // a scan checks it: a product finding stays (D-602)
	}
	ranged := Vuln{CVE: "CVE-2099-0001", Vendor: "QNAP", Product: "Photo Station",
		Affected: []Affected{{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "6.1.2"}}}}
	e.feeds.vulns = []Vuln{guess("CVE-2098-0001"), guess("CVE-2098-0002"), ranged}
	ids := []string{"a-g1", "a-g2", "a-g3", "a-g4", "a-pc"}
	e.inv.mu.Lock()
	for _, id := range ids {
		a := Asset{ID: id, Name: id, Software: []Software{{ID: "s-ss", Display: "Surveillance Station", Vendor: "QNAP", Product: "Surveillance Station", Version: "5.0", KevKeys: []string{"qnap|surveillance station"}}}}
		if id == "a-pc" {
			a = nas("6.1.1") // inside the range: a version finding the agent reports, with a named update
			a.ID = id
			a.Software[0].Source = "agent"
		}
		e.inv.match[id] = a
	}
	e.inv.mu.Unlock()
	for _, id := range ids {
		if _, err := e.svc.OnMatchChanged(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	// the guesses as the reviewer's case has them: Critical (a row stored before the product regrade, or a distro's Critical)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET severity = 'critical' WHERE basis = 'product'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE basis = 'product' AND severity = 'critical'`); n != 8 {
		t.Fatalf("guesses: %d", n)
	}
	tf, err := e.svc.toFix(t.Context(), true, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !tf.Truncated || len(tf.Devices) == 0 || tf.Devices[0].AssetID != "a-pc" || len(tf.Devices[0].Exploited) != 1 {
		t.Fatalf("the proved PC is kept and first under a cap of 2: %+v", tf)
	}
}
