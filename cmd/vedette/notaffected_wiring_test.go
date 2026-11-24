package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// The CVE page's check runs on the device as findings reads it. The Ubuntu box whose agent reads
// OpenSSH is not affected by the Alpine-only CVE; a CVE with no platform limit reads no device.
func TestWiringCVEPageNotAffected(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	ip := netip.MustParseAddr("192.168.40.10")
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: "Ubuntu 24.04.3 LTS", Source: observe.Agent, Confidence: 0.95, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs[ip.String()]
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1",
		KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95}}, "osquery"); err != nil {
		t.Fatal(err)
	}
	fi := feedsInventory{s.d.Inventory}
	got, err := fi.NotAffected(ctx, "CVE-2026-123158", "OpenBSD", "OpenSSH", nil, []string{id})
	if err != nil || !got[id] {
		t.Fatalf("Alpine-only CVE on the Ubuntu box: %v %v", got, err)
	}
	if got, err := fi.NotAffected(ctx, "CVE-2024-6387", "OpenBSD", "OpenSSH", nil, []string{id}); err != nil || len(got) != 0 {
		t.Fatalf("a CVE without a platform limit: %v %v", got, err)
	}
	// gw-alpine, a scanned OpenSSH 10.2 whose package release a person gave on a device a person says runs Alpine Linux 3.23: not affected
	// by Alpine's fixed release from the feed's rows, and only with them (no rows: NVD decides, the page keeps it)
	bn := netip.MustParseAddr("10.142.0.1")
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: bn}, Field: observe.Hostname, Value: "gw-alpine", Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if addrs, err = s.d.Inventory.AddressMap(ctx); err != nil {
		t.Fatal(err)
	}
	bid := addrs[bn.String()]
	if err := s.d.Inventory.UpsertSoftware(ctx, bid, []inventory.SoftwareItem{{Display: "OpenSSH 10.2", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2",
		KevKeys: []string{"openbsd|openssh"}, Confidence: 0.8}}, "scan"); err != nil {
		t.Fatal(err)
	}
	alpine, rel := "Alpine Linux 3.23", "10.2_p1-r1"
	if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", bid, inventory.Patch{OS: &alpine}); err != nil {
		t.Fatal(err)
	}
	dev, err := s.d.Inventory.Device(ctx, bid)
	if err != nil || len(dev.Software) != 1 {
		t.Fatalf("gw-alpine: %+v %v", dev, err)
	}
	if err := s.d.Inventory.EditSoftware(ctx, "it@acme.example", bid, dev.Software[0].ID, inventory.SoftwareEdit{PkgVersion: &rel}); err != nil {
		t.Fatal(err)
	}
	rows := []feeds.DistroFix{{Distro: "alpine", Release: "3.23", Package: "openssh", CVE: "CVE-2026-123158", Status: "fixed", Fixed: "10.2_p1-r1"},
		{Distro: "alpine", Release: "3.24", Package: "openssh", CVE: "CVE-2026-123158", Status: "fixed", Fixed: "10.3_p1-r2"}}
	if got, err := fi.NotAffected(ctx, "CVE-2026-123158", "OpenBSD", "OpenSSH", rows, []string{bid}); err != nil || !got[bid] {
		t.Fatalf("gw-alpine with Alpine's rows: %v %v", got, err)
	}
	if got, err := fi.NotAffected(ctx, "CVE-2026-123158", "OpenBSD", "OpenSSH", nil, []string{bid}); err != nil || got[bid] {
		t.Fatalf("gw-alpine without Alpine's rows: %v %v", got, err)
	}
}
