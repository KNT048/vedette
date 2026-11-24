package main

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The Juniper EX4200-48T of a test network is known only from LLDP (no IP, no software row). Its stated OS
// "JUNOS 15.1R7.9" reaches the matcher through the real wiring: the device's discovery runs findings, the EX flaw becomes a
// version finding, and the SRX-only one (same NVD range) does not, because CISA names SRX Series and the model is EX.
func TestWiringLLDPJunosSwitchGetsItsFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	now := time.Now().UTC()
	for _, v := range []struct{ cve, name string }{ // the box's rows (n23), NVD's "junos:*" before 20.4 for both
		{"CVE-2023-36845", "Juniper Junos OS EX Series and SRX Series PHP External Variable Modification Vulnerability"},
		{"CVE-2023-36846", "Juniper Junos OS SRX Series Missing Authentication for Critical Function Vulnerability"},
	} {
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			if err := seedKEVRow(ctx, tx, v.cve, "Juniper", "Junos OS", v.name, time.Date(2023, 11, 13, 0, 0, 0, 0, time.UTC), false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, v.cve, now.AddDate(-3, 0, 0), 0); err != nil {
				return err
			}
			return seedRange(ctx, tx, v.cve, "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", "", "", "", "20.4")
		}); err != nil {
			t.Fatal(err)
		}
	}
	var updates []inventory.AssetEvent // asset.updated as findings receives it
	s.d.Bus.Subscribe(inventory.EventAssetUpdated, func(_ context.Context, e events.Event) error {
		ev, _ := e.Data.(inventory.AssetEvent)
		updates = append(updates, ev)
		return nil
	})
	mac := "3c:8a:b0:9c:85:80"
	record := func(src observe.Source, conf float64, fields map[observe.Field]string) {
		t.Helper()
		var batch []observe.Observation
		for f, v := range fields {
			batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: f, Value: v, Source: src, Confidence: conf, SeenAt: time.Now().UTC()})
		}
		if err := s.d.Inventory.Record(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	cves := func() []string {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range recs {
			out = append(out, r.CVE)
			if r.Basis != "version" {
				t.Errorf("%s: basis %s", r.CVE, r.Basis)
			}
		}
		return out
	}
	// The usual LLDP order (review L5 of #703): the MAC and vendor first, the system description (model, OS) later.
	record(observe.Passive, 0.6, map[observe.Field]string{observe.MAC: mac, observe.Vendor: "Juniper Networks", observe.Kind: "switch"})
	if got := cves(); len(got) != 0 {
		t.Fatalf("before the OS: %v", got)
	}
	record(observe.Passive, 0.5, map[observe.Field]string{observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9"})
	if got := cves(); !slices.Equal(got, []string{"CVE-2023-36845"}) {
		t.Fatalf("findings of the LLDP switch: %v", got)
	}
	if n := len(updates); n == 0 || !updates[n-1].Match {
		t.Fatalf("the OS change is announced for matching: %+v", updates)
	}
	// nmap's guess wins the OS field (review M2): the switch's own statement still decides, nothing "no longer matches".
	record(observe.Nmap, 0.9, map[observe.Field]string{observe.OS: "Juniper JUNOS 10.4R1.9 (EX4200 switch)"})
	if got, n := cves(), s.count(`SELECT count(*) FROM fnd_finding_event WHERE kind = 'no_longer_detected'`); !slices.Equal(got, []string{"CVE-2023-36845"}) || n != 0 {
		t.Fatalf("after nmap: %v, %d no-longer-matches rows", got, n)
	}
	// A hostname is not what the matcher reads: no rematch (review L3).
	updates = nil
	record(observe.Passive, 0.5, map[observe.Field]string{observe.Hostname: "sw-core-01"})
	if len(updates) != 1 || updates[0].Match {
		t.Fatalf("hostname change: %+v", updates)
	}
}

// Review L5 of #703: with findings off, an LLDP Junos switch gets no finding (the subscription honours the module switch).
func TestWiringLLDPJunosSwitchFindingsOff(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.setModule("findings", false)
	mac := "3c:8a:b0:9c:85:81"
	var batch []observe.Observation
	for f, v := range map[observe.Field]string{observe.MAC: mac, observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9"} {
		batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.5})
	}
	s.kev("CVE-2023-36845", "Juniper", "Junos OS")
	if err := s.d.Inventory.Record(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding`); n != 0 {
		t.Fatalf("findings off: %d findings", n)
	}
}

// junosSwitch is a stack whose feeds list five Junos EX entries, and the frame the test switch's LLDP sends.
func junosSwitch(t *testing.T) (s *stack, cves []string, lldp func()) {
	t.Helper()
	s = newStack(t)
	ctx := t.Context()
	now := time.Now().UTC()
	cves = []string{"CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2023-36851", "CVE-2024-21591"}
	for _, cve := range cves {
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			if err := seedKEVRow(ctx, tx, cve, "Juniper", "Junos OS", "Juniper Junos OS EX Series Vulnerability", time.Date(2023, 11, 13, 0, 0, 0, 0, time.UTC), false, false); err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, cve, now.AddDate(-3, 0, 0), 0); err != nil {
				return err
			}
			return seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", "", "", "", "20.4")
		}); err != nil {
			t.Fatal(err)
		}
	}
	const base, mgmt, ip = "3c:8a:b0:9c:85:80", "3c:8a:b0:9c:85:ff", "10.142.0.47"
	lldp = func() {
		t.Helper()
		var batch []observe.Observation
		for f, v := range map[observe.Field]string{observe.MAC: base, observe.Vendor: "Juniper Networks", observe.Kind: "switch", observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9"} {
			batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: base}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.5, SeenAt: time.Now().UTC()})
		}
		if err := s.d.Inventory.Record(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	return s, cves, lldp
}

// The test switch. Its LLDP row holds the Junos findings (one marked a false positive by a person);
// when it joins the .47 device, the findings move with their status and nothing is created or announced again.
func TestWiringJoinedSwitchKeepsItsFindings(t *testing.T) {
	t.Parallel()
	s, cves, lldp := junosSwitch(t)
	ctx := t.Context()
	const mgmt, ip = "3c:8a:b0:9c:85:ff", "10.142.0.47"
	lldp()
	recs, err := s.d.Findings.List(ctx, "")
	if err != nil || len(recs) != len(cves) {
		t.Fatalf("findings of the LLDP row: %d (%v)", len(recs), err)
	}
	fp := recs[0]
	if _, _, err := s.d.Findings.Handle(ctx, []string{fp.ID}, findings.ResolutionFalsePositive, "J-Web is off on this switch", time.Time{}, "anna"); err != nil {
		t.Fatal(err)
	}
	h := observe.AssetHint{MAC: mgmt, IP: netip.MustParseAddr(ip)}
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: mgmt, Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	created := 0
	s.d.Bus.Subscribe(findings.EventCreated, func(context.Context, events.Event) error { created++; return nil })
	lldp()
	list, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ipID string
	n := 0
	for _, d := range list.Items {
		if !d.IsBox {
			n++
		}
		if d.IP == ip {
			ipID = d.ID
		}
	}
	if n != 1 || ipID == "" {
		t.Fatalf("%d devices (.47 is %q), want one switch", n, ipID)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = '` + ipID + `'`); n != len(cves) {
		t.Errorf("%d findings on the kept device, want %d", n, len(cves))
	}
	if r, err := s.d.Findings.Get(ctx, fp.ID); err != nil || r.Status != findings.StatusFalsePositive || r.AssetID != ipID {
		t.Errorf("the person's false positive: %+v %v", r, err)
	}
	if created != 0 {
		t.Errorf("%d findings created again", created)
	}
}

// Review L5 (round 2) of #722: when findings cannot move a merged device's findings, nothing of the join happens: the participants
// run inside the inventory's write, so the failure rolls the whole join back and the LLDP row keeps its findings. Here both rows hold
// the Junos CVEs and mitigation's table is gone, so the move fails.
func TestWiringAFailedMoveKeepsTheFindings(t *testing.T) {
	t.Parallel()
	s, cves, lldp := junosSwitch(t)
	ctx := t.Context()
	lldp()
	recs, err := s.d.Findings.List(ctx, "")
	if err != nil || len(recs) != len(cves) {
		t.Fatalf("findings of the LLDP row: %d (%v)", len(recs), err)
	}
	lldpID := recs[0].AssetID
	h := observe.AssetHint{MAC: "3c:8a:b0:9c:85:ff", IP: netip.MustParseAddr("10.142.0.47")}
	var batch []observe.Observation
	for f, v := range map[observe.Field]string{observe.MAC: h.MAC, observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9"} {
		batch = append(batch, observe.Observation{AssetHint: h, Field: f, Value: v, Source: observe.SNMP, Confidence: 0.9})
	}
	if err := s.d.Inventory.Record(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding`); n != 2*len(cves) {
		t.Fatalf("%d findings, want both rows' %d", n, 2*len(cves))
	}
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, `DROP TABLE mit_applied`); return err }); err != nil {
		t.Fatal(err)
	}
	var again []observe.Observation
	for f, v := range map[observe.Field]string{observe.MAC: "3c:8a:b0:9c:85:80", observe.Vendor: "Juniper Networks", observe.Kind: "switch"} {
		again = append(again, observe.Observation{AssetHint: observe.AssetHint{MAC: "3c:8a:b0:9c:85:80"}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.5, SeenAt: time.Now().UTC()})
	}
	if err := s.d.Inventory.Record(ctx, again); err == nil {
		t.Fatal("the join succeeded although findings could not move its findings")
	}
	if _, err := s.d.Inventory.Device(ctx, lldpID); err != nil {
		t.Fatalf("the LLDP row is gone after a join that failed: %v", err)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = ?`, lldpID); n != len(cves) {
		t.Errorf("%d findings left on the LLDP row, want its %d", n, len(cves))
	}
}

// Review r2 #4 of #803: the findings adapter hands the feeds' template flag and NVD's published day to the matcher; the age
// rule never drops a pair whose CVE a safe template checks, and dates the CVE from them.
func TestWiringVulnsCarryTemplateAndPublished(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedKEVRow(ctx, tx, "CVE-2017-0144", "Microsoft", "SMBv1", "EternalBlue", time.Date(2022, 2, 10, 0, 0, 0, 0, time.UTC), true, true); err != nil {
			return err
		}
		if err := seedKEVRow(ctx, tx, "CVE-2018-13379", "Fortinet", "FortiOS", "SSL VPN", time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC), false, false); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET published = '2017-03-17T00:00:00.000Z' WHERE cve = 'CVE-2017-0144'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := findingsFeeds{st: fs.Store()}.Vulns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Vuln{}
	for _, v := range vulns {
		got[v.CVE] = v
	}
	if v := got["CVE-2017-0144"]; !v.HasTemplate || v.Published.Format(time.DateOnly) != "2017-03-17" || v.DateAdded.Format(time.DateOnly) != "2022-02-10" {
		t.Fatalf("EternalBlue: %+v", v)
	}
	if v := got["CVE-2018-13379"]; v.HasTemplate || !v.Published.IsZero() {
		t.Fatalf("no template, no published day: %+v", v)
	}
}

// "A safe check exists" (KevInfo.HasTemplate, To fix's Checkable) is the scan's own pack, never the feed flag: the feed says
// EternalBlue has a nuclei template the pack does not ship, and nothing for a FortiOS CVE the pack does check (an offline box).
func TestWiringSafeCheckIsTheScansPack(t *testing.T) {
	t.Parallel()
	if safeCheckFor("CVE-2017-0144") || !safeCheckFor("CVE-2018-13379") {
		t.Fatal("the pack index: CVE-2017-0144 has no template in it, CVE-2018-13379 has")
	}
	s := newStack(t)
	ctx := t.Context()
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedKEVRow(ctx, tx, "CVE-2017-0144", "Microsoft", "SMBv1", "EternalBlue", time.Date(2022, 2, 10, 0, 0, 0, 0, time.UTC), true, true); err != nil {
			return err
		}
		return seedKEVRow(ctx, tx, "CVE-2018-13379", "Fortinet", "FortiOS", "SSL VPN", time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC), false, false)
	}); err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	kev, err := findingsFeeds{st: fs.Store()}.KevInfo(ctx, []string{"CVE-2017-0144", "CVE-2018-13379"})
	if err != nil {
		t.Fatal(err)
	}
	if kev["CVE-2017-0144"].HasTemplate || !kev["CVE-2018-13379"].HasTemplate {
		t.Fatalf("has_template follows the feed, not the pack: %+v", kev)
	}
}
