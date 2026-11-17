package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// BN340 (n82): nmap's fingerprint guesses "Android 9 - 10 (Linux 4.9 - 4.14)"; the device's SNMP answer (net-snmp's uname layout) says
// Alpine Linux and wins over the guess (INV-1); a person's correction wins over both, drives matching, survives later reads, says when
// the sources disagree, and can be cleared (INV-39).
func TestINV39_CorrectedOSWinsDrivesMatchingAndClears(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.18.1")
	rec := func(v string, src observe.Source) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: v, Source: src, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Alpine Linux", observe.SNMP)
	id := e.count(`SELECT count(*) FROM inv_asset`) // one device
	if id != 1 {
		t.Fatalf("%d devices", id)
	}
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	dev := addrs[ip.String()]
	detail := func() inventory.Detail {
		t.Helper()
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := detail(); d.Asset.OS == nil || d.Asset.OS.Value != "Alpine Linux" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("SNMP's OS must beat nmap's guess: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}

	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine <b>")}), 400, "bad_os")
	e.ev.reset()
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("  Alpine Linux 3.23 ")}); err != nil {
		t.Fatal(err)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).Match {
		t.Fatalf("a corrected OS must match the device again: %+v", ev)
	}
	d := detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" || d.Asset.OS.Source != "manual" {
		t.Fatalf("the correction must win: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || c.Value != "Alpine Linux 3.23" || c.Detected == nil || c.Detected.Value != "Alpine Linux" || c.Detected.Source != "snmp" || c.Disagrees {
		t.Fatalf("correction %+v (SNMP's Alpine Linux does not contradict Alpine Linux 3.23)", c)
	}
	m, ok, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil || !ok || m.OS != "Alpine Linux 3.23" || m.SNMPOS != "Alpine Linux 3.23" || m.StatedOS != "Alpine Linux 3.23" || m.AgentOS != "" {
		t.Fatalf("matching must read the person's OS: %+v %v %v", m, ok, err)
	}

	// The next reads change nothing shown; one that reads another OS makes the device say so.
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Ubuntu", observe.SNMP)
	d = detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" {
		t.Fatalf("the correction must survive the next scan: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || !c.Disagrees || c.Detected.Value != "Ubuntu" {
		t.Fatalf("the device must say the last read disagrees: %+v", c)
	}

	// The same value again writes nothing; clearing brings back what the sources read.
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine Linux 3.23")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if d := detail(); d.Asset.OS.Value != "Ubuntu" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("cleared: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); m.SNMPOS != "Ubuntu" {
		t.Fatalf("cleared: matching reads the sources again: %+v", m)
	}
	a := e.auditActions()
	if n := countOf(a, "inventory.correct_os"); n != 1 || countOf(a, "inventory.clear_os") != 1 {
		t.Fatalf("audit %v", a)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_os' AND user = 'op@example.com' AND detail = 'Alpine Linux → Alpine Linux 3.23'`) != 1 {
		t.Fatal("the audit row must say who changed what to what")
	}
}

// INV-39: a person corrects the OpenSSH row a scan reported (BN340: package release 10.2_p1-r1). The correction replaces the scanned row
// for matching, survives the next scan, says when the scan disagrees, can change the product (the wrong row's CVEs stop matching), and
// clearing it brings the scanned row back.
func TestINV39_CorrectedSoftwareReplacesTheScannedRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"openbsd|openssh": {"CVE-2026-123158"}, "matt johnston|dropbear ssh": {"CVE-2026-0002"}}}))
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.18.1")}
	scan := func(version string) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, []observe.Software{
			{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	scan("10.2")
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	dev := addrs[hint.IP.String()]
	views := func() (scanned, mine inventory.SoftwareView) {
		t.Helper()
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range d.Asset.Software {
			if s.Source == "manual" {
				mine = s
			} else {
				scanned = s
			}
		}
		return scanned, mine
	}
	match := func() []inventory.MatchSoftware {
		t.Helper()
		m, ok, err := e.svc.MatchInput(e.ctx(), dev)
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		return m.Software
	}
	scanned, _ := views()

	wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{}), 400, "bad_edit")
	wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{PkgVersion: ptr("10.2 <x>")}), 400, "bad_pkg_version")
	e.ev.reset()
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{Version: ptr("10.2p1"), PkgVersion: ptr("10.2_p1-r1")}); err != nil {
		t.Fatal(err)
	}
	if len(e.ev.named(inventory.EventSoftwareChanged)) != 1 {
		t.Fatal("a correction must match the device again (inventory.software.changed)")
	}
	sw := match()
	if len(sw) != 1 || sw[0].Source != "manual" || sw[0].Version != "10.2p1" || sw[0].PkgVersion != "10.2_p1-r1" || !slices.Equal(sw[0].KevKeys, []string{"openbsd|openssh"}) {
		t.Fatalf("matching must read only the correction: %+v", sw)
	}
	scanned, mine := views()
	if mine.Correction == nil || mine.Correction.Detected == nil || mine.Correction.Detected.ID != scanned.ID || !mine.Correction.Disagrees ||
		mine.PkgVersion == nil || *mine.PkgVersion != "10.2_p1-r1" || scanned.CorrectedBy == nil || *scanned.CorrectedBy != mine.ID {
		t.Fatalf("detail: scanned %+v, correction %+v", scanned, mine)
	}

	// The next scan writes its own row (a new one); the correction still replaces it, and says what it reads now.
	scan("10.3")
	if sw := match(); len(sw) != 1 || sw[0].Source != "manual" {
		t.Fatalf("the correction must survive the next scan: %+v", sw)
	}
	if _, mine := views(); mine.Correction == nil || mine.Correction.Detected == nil || *mine.Correction.Detected.Version != "10.3" || !mine.Correction.Disagrees {
		t.Fatalf("the last scan reads 10.3: %+v", mine.Correction)
	}
	// Editing the correction from the scanned row changes the one correction; a version-only edit of it is the D-471 edit.
	scanned, mine = views()
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{Version: ptr("10.3")}); err != nil {
		t.Fatal(err)
	}
	if _, again := views(); again.ID != mine.ID || *again.Version != "10.3" || *again.PkgVersion != "10.2_p1-r1" || again.Correction.Disagrees {
		t.Fatalf("one correction per product: %+v", again)
	}

	// Another product: the wrong row's CVEs stop matching.
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, mine.ID, inventory.SoftwareEdit{Vendor: "Matt Johnston", Product: "Dropbear SSH", Version: ptr("2024.86")}); err != nil {
		t.Fatal(err)
	}
	if sw := match(); len(sw) != 1 || !slices.Equal(sw[0].KevKeys, []string{"matt johnston|dropbear ssh"}) {
		t.Fatalf("matching must read the corrected product: %+v", sw)
	}
	run, err := e.svc.DevicesRunning(e.ctx(), []inventory.ProductQuery{{Vendor: "OpenBSD", Product: "OpenSSH"}})
	if err != nil || len(run["openbsd|openssh"]) != 0 {
		t.Fatalf("the corrected row must not run OpenSSH any more: %+v %v", run, err)
	}

	// Clearing: the scanned row matches again.
	_, mine = views()
	if err := e.svc.RemoveSoftware(e.ctx(), "op@example.com", dev, mine.ID); err != nil {
		t.Fatal(err)
	}
	if sw := match(); len(sw) != 1 || sw[0].Source != "nmap" || sw[0].Version != "10.3" {
		t.Fatalf("cleared: the scanned row is back: %+v", sw)
	}
	if scanned, _ := views(); scanned.CorrectedBy != nil {
		t.Fatalf("cleared: %+v", scanned)
	}
	a := e.auditActions()
	if countOf(a, "inventory.correct_software") != 3 || countOf(a, "inventory.clear_software_correction") != 1 {
		t.Fatalf("audit %v", a)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_software' AND user = 'op@example.com' AND detail = 'OpenSSH 10.2 (nmap) → OpenSSH 10.2p1 (package 10.2_p1-r1)'`) != 1 {
		t.Fatal("the first audit row must say what the scan read and what the person set")
	}
}

func countOf(list []string, v string) int {
	n := 0
	for _, x := range list {
		if x == v {
			n++
		}
	}
	return n
}
