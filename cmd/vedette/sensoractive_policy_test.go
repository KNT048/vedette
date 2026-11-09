package main

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The in-memory scope of sensor-active equals the inventory's Settings.InScope on random
// and odd inputs (overlapping ranges, ranges with host bits, single-host exclusions, /31, /32, network and
// broadcast addresses, IPv6 and v4-mapped strings, junk).
func TestScopeParityRandom(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(7, 9)) //nolint:gosec // deterministic test data
	odd := []string{"fd00::/64", "::ffff:192.168.10.0/120", "::ffff:192.168.10.7", "fd00::1", "junk", "", " 192.168.10.0/24",
		"192.168.10.5%eth0", "0.0.0.0/0", "192.168.010.0/24", "192.168.10.0/33", "192.168.10.0/-1"}
	addr := func() netip.Addr {
		b := [4]byte{192, 168, 10, byte(r.IntN(256))} //nolint:gosec // IntN(256) fits a byte
		switch r.IntN(4) {
		case 0:
			b = [4]byte{10, byte(r.IntN(2)), byte(r.IntN(4)), byte(r.IntN(256))} //nolint:gosec // all below 256
		case 1:
			b[2] = byte(9 + r.IntN(3)) //nolint:gosec // 9..11
		}
		return netip.AddrFrom4(b)
	}
	str := func(singleHost bool) string {
		if r.IntN(8) == 0 {
			return odd[r.IntN(len(odd))]
		}
		if singleHost {
			return addr().String()
		}
		return fmt.Sprintf("%s/%d", addr(), 8+r.IntN(25))
	}
	for iter := range 4000 {
		var ranges, excl []string
		for range 1 + r.IntN(4) {
			ranges = append(ranges, str(false))
		}
		for range r.IntN(5) {
			excl = append(excl, str(r.IntN(2) == 0))
		}
		inv := inventory.Settings{LANRanges: ranges, Active: inventory.ActiveWindow{Exclusions: excl}}
		sa := sensoractive.Settings{LANRanges: ranges, Exclusions: excl}
		for range 40 {
			a := addr()
			if r.IntN(10) == 0 {
				a = netip.AddrFrom16(a.As16()) // v4-mapped
			}
			if got, want := sa.InScope(a), inv.InScope(a); got != want {
				t.Fatalf("iter %d: %s ranges %q excl %q: sensor-active %v, inventory %v", iter, a, ranges, excl, got, want)
			}
		}
	}
}

// Every device the inventory's policy refuses for a device reason (declared by hand,
// fragile or unclassified passive-only) is in ProtectedIPs, so the sweep cannot probe it either; and an
// unclassified device's only active scan without a person is the gentle one. Matrix: kind unknown / server /
// printer (fragile, in regular_scan_kinds) / camera (fragile, not in it) x regular_scan follow / allow / never x
// gentle scan done or not, plus a hand-declared device.
func TestProtectedIPsCoverEveryPolicyRefusal(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	if _, err := s.d.Inventory.SaveSettings(ctx, "admin@acme.example", inventory.SettingsInput{
		Settings: inventory.Settings{
			LANRanges:        []string{"192.168.10.0/24"},
			Active:           inventory.ActiveWindow{Enabled: true, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100},
			FragileKinds:     []string{"printer", "camera"},
			RegularScanKinds: []string{"printer"},
		},
		ScopeConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	type dev struct {
		id, ip, kind, regular string
		first                 bool
	}
	var devs []dev
	n := 100
	for _, kind := range []string{"", "server", "printer", "camera"} {
		for _, regular := range []string{"follow", "allow", "never"} {
			for _, first := range []bool{false, true} {
				ip := fmt.Sprintf("192.168.10.%d", n)
				id := s.seen(t, ip, fmt.Sprintf("aa:bb:cc:00:01:%02x", n), kind)
				n++
				if regular != "follow" {
					rs := regular
					if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{RegularScan: &rs}); err != nil {
						t.Fatal(err)
					}
				}
				if first {
					if err := s.d.Inventory.MarkFirstScan(ctx, id); err != nil {
						t.Fatal(err)
					}
				}
				devs = append(devs, dev{id: id, ip: ip, kind: kind, regular: regular, first: first})
			}
		}
	}
	if _, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.40"}); err != nil {
		t.Fatal(err)
	}
	devs = append(devs, dev{id: s.idByIP(t, "192.168.10.40"), ip: "192.168.10.40", kind: "manual"})
	prot, err := s.d.Inventory.ProtectedIPs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		dec, err := s.d.Inventory.ScanPolicy(ctx, d.id)
		if err != nil {
			t.Fatal(err)
		}
		p := slices.Contains(prot, netip.MustParseAddr(d.ip))
		if !dec.Allowed && !p {
			t.Errorf("%+v: refused by the policy (%s) but not protected from the sweep", d, dec.Reason)
		}
		if d.kind == "" && dec.Allowed && dec.Reason != inventory.ReasonFirstGentleScan && d.regular != "allow" {
			t.Errorf("%+v: unclassified device allowed a %s scan without a person allowing it", d, dec.Reason)
		}
		if d.regular == "never" && dec.Allowed && dec.Reason != inventory.ReasonFirstGentleScan {
			t.Errorf("%+v: regular scan is never, yet the policy allows a %s scan", d, dec.Reason)
		}
		if dec.Allowed && p {
			t.Logf("note: %+v allowed by ScanPolicy (%s, rate %d) yet protected from the sweep", d, dec.Reason, dec.Rate)
		}
	}
}

// ProtectedIPs protects the box from the sweep, and ScanPolicy must refuse a device scan of it
// too (reason "box"), so a caller of ScanPolicy (a queued box, the future scan module) cannot probe the machine
// Vedette runs on.
func TestScanPolicyRefusesTheBox(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.saveScope(t)
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: "192.168.10.2"})
	if err != nil {
		t.Fatal(err)
	}
	prot, err := s.d.Inventory.ProtectedIPs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(prot, netip.MustParseAddr("192.168.10.2")) {
		t.Fatal("setup: the box is not in ProtectedIPs")
	}
	dec, err := s.d.Inventory.ScanPolicy(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allowed {
		t.Errorf("ScanPolicy(box) = %+v: the box is protected from the sweep but a device scan of it is allowed", dec)
	}
	if dec.Reason != inventory.ReasonBox {
		t.Errorf("reason = %q, want %q", dec.Reason, inventory.ReasonBox)
	}
}

// "Never" means never, for every kind: the one gentle scan when the device is first seen, then passive only. A
// plain server (not fragile, not unclassified) was the gap: the sweep skipped it but a device scan was allowed.
func TestScanPolicyNeverMeansNeverForEveryKind(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.saveScope(t)
	never := "never"
	for i, kind := range []string{"", "server", "printer", "camera", "router"} {
		id := s.seen(t, fmt.Sprintf("192.168.10.%d", 30+i), fmt.Sprintf("aa:bb:cc:00:03:%02x", i), kind)
		if err := s.d.Inventory.PatchDevice(ctx, "it@acme.example", id, inventory.Patch{RegularScan: &never}); err != nil {
			t.Fatal(err)
		}
		dec, err := s.d.Inventory.ScanPolicy(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !dec.Allowed || dec.Reason != inventory.ReasonFirstGentleScan || dec.Rate != 1 {
			t.Errorf("kind %q before its first scan: %+v, want the one gentle scan", kind, dec)
		}
		if err := s.d.Inventory.MarkFirstScan(ctx, id); err != nil {
			t.Fatal(err)
		}
		if dec, err = s.d.Inventory.ScanPolicy(ctx, id); err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			t.Errorf("kind %q after its first scan: %+v, want passive only", kind, dec)
		}
	}
}
