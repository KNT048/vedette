package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Each active source of the box is on or off per device. A device added by hand stays silent until a person turns a source on;
// turning one on lifts the hand-added default for that source only; turning one off stops it for any device.
func TestContract_SourcesPerDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.30.0/24")
	const who = "admin@acme.example"
	on, off := inventory.SourceOn, inventory.SourceOff
	hand := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.1"})
	e.record(obs(netip.MustParseAddr("192.168.30.20"), macA, observe.Kind, "pc", observe.Agent, 0.9))
	seen := e.idByMAC(macA)
	policy := func(id string) (scan, snmp inventory.ScanDecision) {
		t.Helper()
		var err error
		if scan, err = e.svc.ScanPolicy(e.ctx(), id); err != nil {
			t.Fatal(err)
		}
		if snmp, err = e.svc.SNMPPolicy(e.ctx(), id); err != nil {
			t.Fatal(err)
		}
		return scan, snmp
	}
	protected := func(ip string) bool {
		t.Helper()
		list, err := e.svc.ProtectedIPs(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range list {
			if a.String() == ip {
				return true
			}
		}
		return false
	}

	// Silent by default: no scan, no SNMP, the sweep leaves it out, the device says off for both.
	scan, snmp := policy(hand)
	if scan.Allowed || scan.Reason != inventory.ReasonDeclaredByHand || snmp.Allowed || snmp.Reason != inventory.ReasonDeclaredByHand {
		t.Fatalf("hand-added by default: scan %+v, snmp %+v", scan, snmp)
	}
	if !protected("192.168.30.1") {
		t.Fatal("the sweep must leave a hand-added device out by default")
	}
	if vd, _ := e.svc.VulnScanPolicy(e.ctx(), hand, true); vd.Allowed || vd.Reason != inventory.ReasonDeclaredByHand {
		t.Fatalf("a pick in Scan now of a hand-added device whose scan is off (review r1 M1): %+v", vd)
	}
	if d := e.detail(hand); d.Asset.ScanSource != off || d.Asset.SNMPSource != off {
		t.Fatalf("hand-added sources = %s/%s, want off/off", d.Asset.ScanSource, d.Asset.SNMPSource)
	}
	if d := e.detail(seen); d.Asset.ScanSource != on || d.Asset.SNMPSource != on {
		t.Fatalf("discovered sources = %s/%s, want on/on", d.Asset.ScanSource, d.Asset.SNMPSource)
	}

	// SNMP on: read, the network scan stays off (that source only).
	e.ev.reset()
	got, err := e.svc.SetSources(e.ctx(), who, hand, nil, &on)
	if err != nil || got != (inventory.Sources{Scan: off, SNMP: on, Agent: on}) {
		t.Fatalf("SNMP on: %+v, %v", got, err)
	}
	if scan, snmp = policy(hand); scan.Allowed || !snmp.Allowed {
		t.Fatalf("SNMP on: scan %+v, snmp %+v", scan, snmp)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || ev[0].Data.(inventory.AssetEvent).ScanOn {
		t.Fatalf("SNMP on publishes one update without scan_on: %+v", ev)
	}

	// Scan on: scanned within the scope (the first gentle scan of a fragile kind), no longer protected, queued (scan_on).
	e.ev.reset()
	if _, err := e.svc.SetSources(e.ctx(), who, hand, &on, nil); err != nil {
		t.Fatal(err)
	}
	if scan, _ = policy(hand); !scan.Allowed {
		t.Fatalf("scan on: %+v", scan)
	}
	if protected("192.168.30.1") {
		t.Fatal("scan on: the sweep may reach it")
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).ScanOn {
		t.Fatalf("scan on publishes scan_on: %+v", ev)
	}
	if vd, _ := e.svc.VulnScanPolicy(e.ctx(), hand, false); vd.Reason == inventory.ReasonDeclaredByHand {
		t.Fatalf("scan on lifts declared_by_hand for the scheduled vulnerability scans too: %+v", vd)
	}

	// Off, for a discovered device too: refused with a plain reason, protected from the sweep, absolute for the scan module.
	for _, id := range []string{hand, seen} {
		if _, err := e.svc.SetSources(e.ctx(), who, id, &off, &off); err != nil {
			t.Fatal(err)
		}
		scan, snmp = policy(id)
		if scan.Allowed || scan.Reason != inventory.ReasonRegularScanNever || !scan.Never || snmp.Allowed || snmp.Reason != inventory.ReasonSNMPOff {
			t.Fatalf("%s off: scan %+v, snmp %+v", id, scan, snmp)
		}
		if vd, _ := e.svc.VulnScanPolicy(e.ctx(), id, true); vd.Allowed {
			t.Fatalf("%s off: a pick in Scan now must be refused too: %+v", id, vd)
		}
	}
	if !protected("192.168.30.20") {
		t.Fatal("a discovered device with its scan off must be left out of the sweep")
	}

	// Audit: who, which device, which source, on or off; saying the same again writes nothing and publishes nothing (review r1 L3).
	n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'inventory.set_source'`)
	if n != 6 { // hand: snmp on, scan on, scan off, snmp off; seen: scan off, snmp off
		t.Fatalf("audit rows = %d, want 6", n)
	}
	e.ev.reset()
	if _, err := e.svc.SetSources(e.ctx(), who, seen, &off, nil); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'inventory.set_source'`) != n {
		t.Fatal("turning off what is off must not write an audit row")
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 0 {
		t.Fatalf("a PUT that changes nothing published %+v", ev)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'inventory.set_source' AND user = ? AND detail = 'SNMP: on'`, who) != 1 {
		t.Fatal("the audit row names the person, the source and the state")
	}

	// Review r2 M1: a discovered device outside lan_ranges shows SNMP off (its default does not reach it); turning it on is the stored
	// consent SNMPPolicy reads, so it is a change: audited and announced.
	e.record(obs(netip.MustParseAddr("10.9.0.20"), macB, observe.Kind, "switch", observe.Agent, 0.9))
	far := e.idByMAC(macB)
	if d := e.detail(far); d.Asset.SNMPSource != off {
		t.Fatalf("a discovered device outside lan_ranges shows SNMP %q, want off", d.Asset.SNMPSource)
	}
	if d, _ := e.svc.SNMPPolicy(e.ctx(), far); d.Allowed {
		t.Fatalf("outside lan_ranges, default: %+v", d)
	}
	audits := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'inventory.set_source'`)
	e.ev.reset()
	got, err = e.svc.SetSources(e.ctx(), who, far, nil, &on)
	if err != nil || got.SNMP != on {
		t.Fatalf("SNMP on outside lan_ranges: %+v, %v", got, err)
	}
	if d, _ := e.svc.SNMPPolicy(e.ctx(), far); !d.Allowed {
		t.Fatalf("outside lan_ranges, turned on: %+v", d)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'inventory.set_source'`) - audits; n != 1 {
		t.Fatalf("%d audit rows for the outside-LAN consent, want 1", n)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 {
		t.Fatalf("%d events for the outside-LAN consent, want 1", len(ev))
	}
	if d := e.detail(far); d.Asset.SNMPSource != on {
		t.Fatalf("after turning it on the device shows SNMP %q", d.Asset.SNMPSource)
	}

	// Refusals.
	_, err = e.svc.SetSources(e.ctx(), who, hand, nil, nil)
	wantAPIError(t, err, 400, "bad_source")
	bad := "maybe"
	_, err = e.svc.SetSources(e.ctx(), who, hand, &bad, nil)
	wantAPIError(t, err, 400, "bad_source")
	_, err = e.svc.SetSources(e.ctx(), who, "a-nope", &on, nil)
	wantAPIError(t, err, 404, "not_found")
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.30.2"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.SetSources(e.ctx(), who, box, &on, &on)
	wantAPIError(t, err, 409, "box_device")
}

// Inside lan_ranges a credential's scope decides as before; outside them SNMP reads only a device whose SNMP a
// person turned on (so no credential saved by an older version reaches past the LAN by itself); an excluded address never; the network scan
// keeps to lan_ranges.
func TestContract_SNMPOutsideLANRangesNeedsTheSwitch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	in := okSettings("192.168.30.0/24")
	in.Active.Enabled, in.ScopeConfirmed = true, true
	in.Active.Exclusions = []string{"100.66.255.9"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	on := inventory.SourceOn
	far := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "100.66.255.1"})
	excl := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "100.66.255.9"})
	e.record(obs(netip.MustParseAddr("100.66.255.20"), macA, observe.Kind, "switch", observe.Agent, 0.9))
	seenFar := e.idByMAC(macA) // discovered outside lan_ranges: SNMP "on" by default, which does not reach past the LAN
	if d, _ := e.svc.SNMPPolicy(e.ctx(), seenFar); d.Allowed || d.Reason != inventory.ReasonOutOfScope {
		t.Fatalf("outside lan_ranges with the default switch: %+v", d)
	}
	if d, _ := e.svc.SNMPPolicy(e.ctx(), far); d.Allowed || d.Reason != inventory.ReasonDeclaredByHand {
		t.Fatalf("hand-added outside lan_ranges, SNMP not turned on: %+v", d)
	}
	for _, id := range []string{far, excl, seenFar} {
		if _, err := e.svc.SetSources(e.ctx(), "admin@acme.example", id, &on, &on); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{far, seenFar} {
		if d, _ := e.svc.SNMPPolicy(e.ctx(), id); !d.Allowed {
			t.Fatalf("SNMP turned on, outside lan_ranges: %+v", d)
		}
		if d, _ := e.svc.ScanPolicy(e.ctx(), id); d.Allowed || d.Reason != inventory.ReasonOutOfScope {
			t.Fatalf("the network scan keeps to lan_ranges: %+v", d)
		}
	}
	if d, _ := e.svc.SNMPPolicy(e.ctx(), excl); d.Allowed || d.Reason != inventory.ReasonExcluded {
		t.Fatalf("SNMP to an excluded address, switch on: %+v", d)
	}
}
