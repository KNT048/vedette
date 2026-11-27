package main

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/findings"
)

// Inventory INV-41 (6), findings INV-6c: through the real API, inventory and bus, an operator says the FortiOS row a scan
// reported is not installed. Its finding closes with the person named; a viewer may not; the next scan at the same version keeps it
// closed; Clear (DELETE on the correction) reopens it.
func TestWiringNotInstalledClosesAReportedRowsFinding(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.30.7")}
	scan := func() {
		t.Helper()
		// the scan's host first, as a device check records it: a list by address only attaches to a device, never makes one
		if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: hint, Field: observe.Hostname, Value: "fw-01", Source: observe.Nmap, Confidence: 0.6}}); err != nil {
			t.Fatal(err)
		}
		if err := s.d.Inventory.ReplaceSoftware(ctx, hint, observe.Nmap, nil, []observe.Software{
			{Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.5", KevKeys: []string{"fortinet|fortios"}, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs["192.168.30.7"]
	finding := func() findings.Record {
		t.Helper()
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil || len(recs) != 1 {
			t.Fatalf("findings %+v %v", recs, err)
		}
		return recs[0]
	}
	if r := finding(); r.Status != findings.StatusSuspected {
		t.Fatalf("seed: %+v", r.Row)
	}
	m, _, err := s.d.Inventory.MatchInput(ctx, id)
	if err != nil || len(m.Software) != 1 {
		t.Fatalf("match input %+v %v", m, err)
	}
	path := "/inventory/devices/" + id + "/software/" + m.Software[0].ID
	if c, b := s.do("PATCH", path, "viewer", `{"not_installed":true}`); c != 403 {
		t.Fatalf("a viewer must not: %d %v", c, b)
	}
	if c, b := s.do("PATCH", path, "operator", `{"not_installed":true,"version":"7.2.6"}`); c != 400 || at(b, "error", "code") != "bad_edit" {
		t.Fatalf("not_installed goes alone: %d %v", c, b)
	}
	if c, b := s.do("PATCH", path, "operator", `{"not_installed":true}`); c != 200 {
		t.Fatalf("PATCH not_installed: %d %v", c, b)
	}
	r := finding()
	if r.Status != findings.StatusNotRelevant || r.Row.Via != findings.ViaNotInstalled || r.ResolvedBy != "it@acme.example" {
		t.Fatalf("closed with the person named: %+v", r.Row)
	}
	_, detail := s.do("GET", "/inventory/devices/"+id, "viewer", "")
	var corr map[string]any
	for _, sw := range at(detail, "asset", "software").([]any) {
		if c, ok := at(sw, "correction").(map[string]any); ok {
			corr = c
		}
	}
	if corr == nil || corr["not_installed"] != true || corr["active"] != true || corr["disagrees"] != false {
		t.Fatalf("the device shows the row not installed: %v", corr)
	}
	// what the device runs, for the Ask context and the MCP asset data, leaves out the software a person said is not installed
	dev, err := s.d.Inventory.Device(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := mcpAsset(dev).Software; len(got) != 0 {
		t.Fatalf("the MCP asset must not list it: %+v", got)
	}
	rows, err := aiAsk{inv: s.d.Inventory}.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id && len(row.Software) != 0 {
			t.Fatalf("the Ask context must not list it: %+v", row.Software)
		}
	}
	scan() // the same version again: it stays closed
	if r := finding(); r.Status != findings.StatusNotRelevant {
		t.Fatalf("the next scan must keep it closed: %+v", r.Row)
	}
	var cid string
	for _, sw := range at(detail, "asset", "software").([]any) {
		if at(sw, "correction") != nil {
			cid, _ = at(sw, "id").(string)
		}
	}
	if c, b := s.do("DELETE", "/inventory/devices/"+id+"/software/"+cid, "operator", ""); c != 204 {
		t.Fatalf("Clear: %d %v", c, b)
	}
	if r := finding(); r.Status != findings.StatusSuspected {
		t.Fatalf("Clear must reopen it: %+v", r.Row)
	}
	if dev, err := s.d.Inventory.Device(ctx, id); err != nil || len(mcpAsset(dev).Software) != 1 {
		t.Fatalf("cleared: the software is listed again: %+v %v", dev.Software, err)
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action IN ('inventory.mark_not_installed', 'inventory.clear_software_correction')`); n != 2 {
		t.Fatalf("audit rows %d", n)
	}
}
