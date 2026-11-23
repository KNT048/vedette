package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The name a person gives a device in Vedette reaches every module that names devices (findings, notify, the audit
// log, reports, honeypot, sensor-active, the CVE page, response (devices, plan targets, gateways), MCP, the AI (facts, ask, affected
// devices)), and an empty name gives the default back.
func TestTheNameInVedetteReachesEveryReader(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("inventory", true)
	s.setModule("findings", true)
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	add, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "fw-hq", IP: "192.168.30.1"})
	if err != nil {
		t.Fatal(err)
	}
	inv := s.d.Inventory
	f, err := s.d.Findings.ConfirmFromScan(ctx, add.ID, "CVE-2024-21762", findings.Evidence{Summary: "x", Template: "CVE-2024-21762", CheckedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { // the response plan reads critical findings only: the CVE's CVSS band
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO feeds_cve (cve) VALUES (?)`, f.CVE); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_metric (cve, source, version, score, vector) VALUES (?, 'nvd', '3.1', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')`, f.CVE)
		return err
	}); err != nil {
		t.Fatal(err)
	}
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
		rows, err := aiAsk{inv: inv}.Assets(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.ID == add.ID {
				out["ai ask"] = r.Name
			}
		}
		facts, err := aiFacts{cases: caseSource{findings: s.d.Findings}, inv: findingsInventory{inv}}.AffectedAssets(ctx, "CVE-2024-21762")
		if err != nil || len(facts) != 1 {
			t.Fatalf("AffectedAssets = %+v, %v", facts, err)
		}
		out["ai affected"] = facts[0].Name
		targets, err := responseCritical{fnd: s.d.Findings, inv: findingsInventory{inv}}.list(ctx)
		if err != nil || len(targets) != 1 {
			t.Fatalf("response plan targets = %+v, %v", targets, err)
		}
		out["response plan"] = targets[0].AssetName
		kinds, err := responseDirectory{inv: inv}.DevicesOfKind(ctx, "firewall")
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range kinds {
			if k.ID == add.ID {
				out["response gateways"] = k.Name
			}
		}
		if len(out) != 14 {
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
