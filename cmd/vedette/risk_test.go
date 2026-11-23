package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The Devices list's badge comes from findings through the wiring (findingCounts.DeviceStatuses, the device status of the findings
// lists): a device with an exploited finding is "1 exploited"; a clean one has none; findings off marks nothing.
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
	if r := got[fw.ID]; r == nil || r.Code != inventory.RiskExploited || r.Count != 1 {
		t.Fatalf("fw-hq risk = %+v", r)
	}
	if got[clean.ID] != nil {
		t.Fatalf("clean device risk = %+v", got[clean.ID])
	}
	// the same value as the findings lists give the device
	cards, err := s.d.Findings.ByDevice(ctx, findings.ListFilter{Device: fw.ID}, findings.Page{Limit: 1})
	if err != nil || len(cards.Items) != 1 || cards.Items[0].Status == nil || cards.Items[0].Status.Code != got[fw.ID].Code {
		t.Fatalf("By device = %+v, %v", cards, err)
	}
	if d, err := s.d.Inventory.DetailPage(ctx, fw.ID); err != nil || d.Risk == nil || d.Risk.Count != 1 {
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

// A catalogue CVE on no list that matches a device is a finding at "update recommended": the badge says so. The box is never marked.
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
			{`INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2026-50001', ?1, ?2, 'Analyzed', ?2, ?2)`,
				[]any{store.FormatTS(now.AddDate(0, 0, -30)), store.FormatTS(now.AddDate(0, 0, -20))}},
			{`INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES ('CVE-2026-50001', 'nvd', '3.1', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')`, nil},
			{`INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms) VALUES ('CVE-2026-50001', 'nvd', 'o', 'fortinet', 'fortios', 'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*', '7.2.0', '', '', '7.2.9', '[]')`, nil},
			{`INSERT INTO feeds_nvd_cursor (selector, url, mode, win_from, win_to, until, next_index, total) VALUES ('recent', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'done', ?1, ?1, ?1, 0, 0)`,
				[]any{store.FormatTS(now)}},
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
	box, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "boxanna", IP: "192.168.18.2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
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
	if r := risk()[id]; r == nil || *r != (inventory.Risk{Code: inventory.RiskUpdate, Count: 1}) {
		t.Fatalf("FortiGate with a catalogue CVE: %+v", r)
	}
	if r := risk()[box]; r != nil {
		t.Fatalf("the box is marked: %+v", r)
	}
}
