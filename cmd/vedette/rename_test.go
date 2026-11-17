package main

import (
	"testing"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// G2 (kien, J2): the name a person gives a device in Vedette reaches every module that names devices (findings, notify, the audit
// log, reports, honeypot, sensor-active, the CVE page, response, MCP, the AI), and an empty name gives the default back.
func TestTheNameInVedetteReachesEveryReader(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("inventory", true)
	add, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	inv := s.d.Inventory
	rename := func(n string) {
		t.Helper()
		if err := inv.PatchDevice(ctx, "it@acme.example", add.ID, inventory.Patch{Name: &n}); err != nil {
			t.Fatal(err)
		}
	}
	names := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		fa, err := findingsInventory{inv: inv}.Assets(ctx, []string{add.ID})
		if err != nil {
			t.Fatal(err)
		}
		out["findings"] = fa[add.ID].Name
		ns, err := notifyDevices{inv: inv}.DeviceStates(ctx, []string{add.ID})
		if err != nil {
			t.Fatal(err)
		}
		out["notify"] = ns[add.ID].Name
		an, err := auditNamer{d: s.d}.AuditNames(ctx, []string{add.ID})
		if err != nil {
			t.Fatal(err)
		}
		out["audit"] = an[add.ID]
		rd, err := reportsInventory{inv: inv}.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range rd {
			if d.ID == add.ID {
				out["reports"] = d.Name
			}
		}
		hd, err := honeypotInventory{inv: inv}.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range hd {
			if d.ID == add.ID {
				out["honeypot"] = d.Name
			}
		}
		sa, err := sensorInventory{inv: inv}.Asset(ctx, add.ID)
		if err != nil {
			t.Fatal(err)
		}
		out["sensor-active"] = sa.Name
		m, err := feedsInventory{inv: inv}.MatchProducts(ctx, []feeds.Product{{Vendor: "Fortinet", Product: "FortiOS"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range m {
			for _, x := range list {
				if x.ID == add.ID && x.Hostname != nil {
					out["cve page"] = *x.Hostname
				}
			}
		}
		dev, err := inv.Device(ctx, add.ID)
		if err != nil {
			t.Fatal(err)
		}
		out["response"] = deviceInfo(dev).Name
		out["mcp"] = mcpAsset(dev).Name
		out["ai"] = aiName(dev)
		if len(out) != 10 {
			t.Fatalf("a reader did not list the device: %v", out)
		}
		return out
	}
	for reader, n := range names() {
		if n != "fw-hq" {
			t.Errorf("before: %s names it %q", reader, n)
		}
	}
	rename("Branch firewall")
	for reader, n := range names() {
		if n != "Branch firewall" {
			t.Errorf("renamed: %s names it %q", reader, n)
		}
	}
	rename("")
	for reader, n := range names() {
		if n != "fw-hq" {
			t.Errorf("cleared: %s names it %q, want the default name", reader, n)
		}
	}
}
