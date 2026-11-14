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
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// W1-32, D-510: the Juniper EX4200-48T of customer walk 1 is known only from LLDP (no IP, no software row). Its stated OS
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
			ts := store.FormatTS(now)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, date_added, ransomware, source_id, updated_at)
				VALUES (?, 'Juniper', 'Junos OS', 'juniper|junos os', ?, '2023-11-13', 0, 'cisa-kev', ?)`, v.cve, v.name, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?)`, v.cve, ts); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl)
				VALUES (?, 'cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*', '', '', '', '20.4')`, v.cve)
			return err
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
	if got, n := cves(), s.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'no_longer_matches'`); !slices.Equal(got, []string{"CVE-2023-36845"}) || n != 0 {
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

// W1-37, D-515, review H2 of #722: the N100 switch. Its LLDP row holds the Junos findings (one marked a false positive by a person);
// when it joins the .47 device, the findings move with their status and nothing is created or announced again.
func TestWiringJoinedSwitchKeepsItsFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	now := time.Now().UTC()
	cves := []string{"CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2023-36851", "CVE-2024-21591"}
	for _, cve := range cves {
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			ts := store.FormatTS(now)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, date_added, ransomware, source_id, updated_at)
				VALUES (?, 'Juniper', 'Junos OS', 'juniper|junos os', 'Juniper Junos OS EX Series Vulnerability', '2023-11-13', 0, 'cisa-kev', ?)`, cve, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected_cve (cve, updated_at) VALUES (?, ?)`, cve, ts); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl)
				VALUES (?, 'cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*', '', '', '', '20.4')`, cve)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	const base, mgmt, ip = "3c:8a:b0:9c:85:80", "3c:8a:b0:9c:85:ff", "192.168.18.47"
	lldp := func() {
		t.Helper()
		var batch []observe.Observation
		for f, v := range map[observe.Field]string{observe.MAC: base, observe.Vendor: "Juniper Networks", observe.Kind: "switch", observe.Model: "EX4200-48T", observe.OS: "JUNOS 15.1R7.9"} {
			batch = append(batch, observe.Observation{AssetHint: observe.AssetHint{MAC: base}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.5, SeenAt: time.Now().UTC()})
		}
		if err := s.d.Inventory.Record(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	lldp()
	recs, err := s.d.Findings.List(ctx, "")
	if err != nil || len(recs) != len(cves) {
		t.Fatalf("findings of the LLDP row: %d (%v)", len(recs), err)
	}
	fp := recs[0]
	if _, err := s.d.Findings.SetStatus(ctx, fp.ID, findings.ActionFalsePositive, "J-Web is off on this switch", "kien"); err != nil {
		t.Fatal(err)
	}
	h := observe.AssetHint{MAC: mgmt, IP: netip.MustParseAddr(ip)}
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: mgmt, Source: observe.Passive, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	created := 0
	s.d.Bus.Subscribe(findings.EventCreated, func(context.Context, events.Event) error { created++; return nil })
	lldp()
	if n := s.count(`SELECT count(*) FROM inv_asset WHERE is_box = 0`); n != 1 {
		t.Fatalf("%d devices, want one switch", n)
	}
	var ipID string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE ip = ?`, ip).Scan(&ipID); err != nil {
		t.Fatal(err)
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
