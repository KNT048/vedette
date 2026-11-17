package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// G4 (kien): the Devices list's risk marker comes from findings through the wiring (findingCounts.RiskByAsset, the same rule as
// Findings › To fix): a device with a finding the box proved is "exploited"; a clean one has none; findings off marks nothing.
func TestDeviceRiskThroughTheWiring(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("inventory", true)
	s.setModule("findings", true)
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	fw, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	clean, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{Vendor: "Acme", Product: "Widget", Name: "widget", IP: "192.168.30.2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.ConfirmFromScan(ctx, fw.ID, "CVE-2024-21762", findings.Evidence{Summary: "x", Template: "CVE-2024-21762", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	risks := func(f inventory.DeviceFilter) map[string]*inventory.Risk {
		t.Helper()
		l, err := s.d.Inventory.DevicesPage(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]*inventory.Risk{}
		for _, d := range l.Items {
			out[d.ID] = d.Risk
		}
		return out
	}
	got := risks(inventory.DeviceFilter{})
	if r := got[fw.ID]; r == nil || r.Level != inventory.RiskExploited || r.Exploited != 1 {
		t.Fatalf("fw-hq risk = %+v", r)
	}
	if got[clean.ID] != nil {
		t.Fatalf("clean device risk = %+v", got[clean.ID])
	}
	// the same value as To fix shows for the device
	tf, err := s.d.Findings.ToFix(ctx, true, fw.ID)
	if err != nil || len(tf.Devices) != 1 || len(tf.Devices[0].Exploited)+len(tf.Devices[0].NoUpdate) != 1 {
		t.Fatalf("To fix = %+v, %v", tf, err)
	}
	if d, err := s.d.Inventory.DetailPage(ctx, fw.ID); err != nil || d.Risk == nil || d.Risk.Exploited != 1 {
		t.Fatalf("detail risk = %+v, %v", d.Risk, err)
	}
	f, err := inventory.ParseDeviceSearch("", "", "", "", "", "", "exploited", "")
	if err != nil {
		t.Fatal(err)
	}
	if only := risks(f); len(only) != 1 || only[fw.ID] == nil {
		t.Fatalf("risk=exploited = %v", only)
	}
	s.setModule("findings", false)
	if r := risks(inventory.DeviceFilter{})[fw.ID]; r != nil {
		t.Fatalf("findings off: %+v", r)
	}
}

// The amber path through the wiring: a recommended update for a High CVE marks the device "update" while the feeds module is on, and
// nothing when it is off (findingCounts passes the switch, as GET /findings/plan lists nothing then). The box is never marked.
func TestDeviceRiskAmberThroughTheWiring(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kevAdded("CVE-2024-1111", "Acme", "Gizmo", time.Now().AddDate(0, -2, 0)) // the exploited list is loaded, with nothing of this device
	now := time.Now().UTC()
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score) VALUES ('CVE-2026-50001', ?, ?, 'Analyzed', 'HIGH', 8.1)`,
				[]any{store.FormatTS(now.AddDate(0, 0, -30)), store.FormatTS(now.AddDate(0, 0, -20))}},
			{`INSERT INTO feeds_recent_affected (cve, cpe, start_incl, start_excl, end_incl, end_excl, platforms) VALUES ('CVE-2026-50001', 'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', '7.2.0', '', '', '7.2.9', '[]')`, nil},
			{`INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'done', ?, ?, ?, 0, 0)`,
				[]any{store.FormatTS(now), store.FormatTS(now), store.FormatTS(now)}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id := s.addFortiGate() // FortiOS 7.2.5, typed by a person
	box, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "boxkien", IP: "192.168.18.2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := findingsJobs(*s.d)[1].Run(ctx); err != nil {
		t.Fatal(err)
	}
	risk := func() map[string]*inventory.Risk {
		t.Helper()
		l, err := s.d.Inventory.DevicesPage(ctx, inventory.DeviceFilter{})
		if err != nil || l.RiskUnavailable {
			t.Fatalf("list: %v, unavailable %v", err, l.RiskUnavailable)
		}
		out := map[string]*inventory.Risk{}
		for _, d := range l.Items {
			out[d.ID] = d.Risk
		}
		return out
	}
	if r := risk()[id]; r == nil || *r != (inventory.Risk{Level: inventory.RiskUpdate, Updates: 1}) {
		t.Fatalf("FortiGate with a High recommended update: %+v", r)
	}
	if r := risk()[box]; r != nil {
		t.Fatalf("the box is marked: %+v", r)
	}
	s.setModule("feeds", false)
	if r := risk()[id]; r != nil {
		t.Fatalf("feeds off: %+v", r)
	}
}
