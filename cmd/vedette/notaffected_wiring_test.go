package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// D-549, KF-CVEPAGE (review r1 #13): the CVE page's check runs on the device as findings reads it. The Ubuntu box whose agent reads
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
		KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95}}, "agent"); err != nil {
		t.Fatal(err)
	}
	fi := feedsInventory{s.d.Inventory}
	got, err := fi.NotAffected(ctx, "CVE-2026-123158", "OpenBSD", "OpenSSH", []string{id})
	if err != nil || !got[id] {
		t.Fatalf("Alpine-only CVE on the Ubuntu box: %v %v", got, err)
	}
	if got, err := fi.NotAffected(ctx, "CVE-2024-6387", "OpenBSD", "OpenSSH", []string{id}); err != nil || len(got) != 0 {
		t.Fatalf("a CVE without a platform limit: %v %v", got, err)
	}
}
