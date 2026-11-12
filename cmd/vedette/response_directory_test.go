package main

import (
	"database/sql"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
)

// DevicesOfKind reads inventory without the 2000 row cap of the device list (newest first): with 2000 newer devices the oldest one, the
// gateway, must still be a never-touch device. A cap here dropped it silently, with no error to make the fail-closed path trigger.
// The 2000 newer devices are planted in one statement, as the discovered rows the observation path leaves (a MAC and an address);
// recording them through that path took 80 s under -race, the longest test of the package. The premise is checked below either way:
// the capped device list must no longer hold the gateway.
func TestResponseDirectoryKeepsTheOldestGatewayPastTheListCap(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	fg := s.addFortiGate()
	dir := responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}
	has := func() bool {
		l, err := dir.DevicesOfKind(ctx, "router", "firewall")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range l {
			if d.ID == fg {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Fatal("the FortiGate is not a router/firewall to begin with")
	}
	newer := store.FormatTS(time.Now().Add(time.Minute)) // every planted device is strictly newer than the gateway: the cap cuts the oldest first
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 1999)
			INSERT INTO inv_asset (id, ip, mac, origin, first_seen, last_seen)
			SELECT printf('a-planted-%04d', i), printf('10.20.%d.%d', i / 250, i % 250 + 1), printf('02:00:00:00:%02x:%02x', i / 256, i % 256),
				'discovered', ?, ? FROM n`, newer, newer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	capped, err := s.d.Inventory.Devices(ctx) // the premise: the capped list no longer holds the gateway
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(capped.Items, func(d inventory.Device) bool { return d.ID == fg }) {
		t.Fatal("the premise is gone: the capped device list still holds the gateway, so this test proves nothing")
	}
	if !has() {
		t.Errorf("with 2000 newer devices the firewall %s is no longer returned by DevicesOfKind, so it is not never-touch", fg)
	}
}

// D-177 (M5): one passive frame (an SSDP NOTIFY or an LLDP frame that says "router") must not put an intruder's device on the never-touch
// list; a router whose kind came from nmap does, and so does an approved one.
func TestResponseDirectoryIgnoresARouterOnlyAPassiveFrameClaimed(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	dir := responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}
	rec := func(ip, mac string, src observe.Source) {
		a := netip.MustParseAddr(ip)
		h := observe.AssetHint{IP: a, MAC: mac}
		if err := s.d.Inventory.Record(ctx, []observe.Observation{
			{AssetHint: h, Field: observe.MAC, Value: mac, Source: src, Confidence: 0.9},
			{AssetHint: h, Field: observe.Kind, Value: "router", Source: src, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	rec("10.7.0.66", "02:00:00:00:66:66", observe.Passive) // the intruder's InternetGatewayDevice announcement
	rec("10.7.0.1", "02:00:00:00:00:01", observe.Nmap)
	ips := func() []string {
		l, err := dir.DevicesOfKind(ctx, "router", "firewall")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range l {
			out = append(out, d.IP)
		}
		return out
	}
	if got := ips(); len(got) != 0 {
		t.Fatalf("gateways %v: a passive router and an unapproved nmap router must not be never-touch", got)
	}
	l, err := s.d.Inventory.DevicesOfKind(ctx, []string{"router"})
	if err != nil {
		t.Fatal(err)
	}
	var passive string
	for _, d := range l {
		if err := s.d.Inventory.Approve(ctx, "emily@acme.example", d.ID); err != nil {
			t.Fatal(err)
		}
		if d.IP == "10.7.0.66" {
			passive = d.ID
		}
	}
	if got := ips(); slices.Contains(got, "10.7.0.66") || !slices.Contains(got, "10.7.0.1") {
		t.Fatalf("gateways %v: want the approved nmap router and not the approved passive one", got)
	}
	r := "router" // the operator vouches for the passive-only router by picking its kind
	if err := s.d.Inventory.PatchDevice(ctx, "emily@acme.example", passive, inventory.Patch{Kind: &r}); err != nil {
		t.Fatal(err)
	}
	if got := ips(); !slices.Contains(got, "10.7.0.66") {
		t.Fatalf("gateways %v: the router the operator picked is missing", got)
	}
}
