package main

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
)

// fakeNet is vedette-host's state/net as core sees it.
type fakeNet struct {
	st    api.NetState
	err   error
	calls int
}

func (f *fakeNet) StateNet(context.Context) (api.NetState, error) {
	f.calls++
	return f.st, f.err
}

func lanBox() *fakeNet {
	return &fakeNet{st: api.NetState{
		Interfaces: []api.NetInterface{
			{Name: "eth0", Role: api.NetRoleManagement, Addresses: []string{"192.168.10.250/24", "fe80::1/64", "fd00:1::5/64"}},
			{Name: "eth1", Role: api.NetRoleSPAN, Addresses: []string{}},
		},
		Decoys: []api.NetDecoy{{IP: "192.168.10.201", MAC: "02:00:00:00:00:01"}},
	}}
}

func TestHostNetSourceGivesSingleAddressPrefixes(t *testing.T) {
	t.Parallel()
	got, err := hostNetSource(lanBox())(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.10.250", "fe80::1", "fd00:1::5", "192.168.10.201"} {
		if !contains(got, a) {
			t.Errorf("%s is not reported as the box", a)
		}
	}
	for _, p := range got {
		if p.Bits() != p.Addr().BitLen() {
			t.Errorf("%s is a subnet: the whole LAN would be refused as the box", p)
		}
	}
	if contains(got, "192.168.10.7") {
		t.Error("a neighbour on the LAN counts as the box")
	}
}

func TestHostNetSourceIsNilSafeAndPassesErrors(t *testing.T) {
	t.Parallel()
	if hostNetSource(nil) != nil || hostSocketNet("") != nil {
		t.Fatal("a missing host must give a nil source")
	}
	// A socket path with no host behind it: a source that fails, never one that panics or hangs.
	src := hostSocketNet(filepath.Join(t.TempDir(), "absent.sock"))
	if src == nil {
		t.Fatal("a configured socket must give a source")
	}
	if _, err := src(t.Context()); !errors.Is(err, hostclient.ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
	bad := &fakeNet{err: errors.New("unreachable")}
	if _, err := hostNetSource(bad)(t.Context()); err == nil {
		t.Fatal("an unreachable host was reported as an empty box")
	}
	// A reply with odd text is skipped, not fatal.
	odd := &fakeNet{st: api.NetState{Interfaces: []api.NetInterface{{Addresses: []string{"nonsense", "10.0.0.9/24"}}}, Decoys: []api.NetDecoy{{IP: "x"}}}}
	if got, err := hostNetSource(odd)(t.Context()); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if hostIPv4s(t.Context(), nil) != nil {
		t.Fatal("no source, some addresses")
	}
	if hostIPv4s(t.Context(), hostNetSource(bad)) != nil {
		t.Fatal("a failing host gave addresses")
	}
	if got := hostIPv4s(t.Context(), hostNetSource(lanBox())); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.10.250"), netip.MustParseAddr("192.168.10.201")}) {
		t.Fatalf("%v", got)
	}
}

// INV-23: boxSources over a fake StateNet includes the host's addresses, is nil-safe with no host, and asks the socket once per 30 seconds.
func TestBoxSourcesUseTheHostsAddresses(t *testing.T) {
	t.Parallel()
	f := lanBox()
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	b := &boxSources{hostNet: hostNetSource(f), now: func() time.Time { return now }}
	got := b.BoxAddrs(t.Context())
	for _, a := range []string{"192.168.10.250", "fd00:1::5", "192.168.10.201"} {
		if !contains(got, a) {
			t.Errorf("%s is not refused as the box", a)
		}
	}
	b.BoxAddrs(t.Context())
	now = now.Add(29 * time.Second)
	b.BoxAddrs(t.Context())
	if f.calls != 1 {
		t.Fatalf("the host was asked %d times inside 30 seconds", f.calls)
	}
	now = now.Add(2 * time.Second)
	f.err = errors.New("down")
	if got := b.BoxAddrs(t.Context()); f.calls != 2 || !contains(got, "192.168.10.250") {
		t.Fatalf("after expiry with a dead host: %d calls, %v", f.calls, got)
	}
	// No host: nothing from it, no panic.
	if got := (&boxSources{hostNet: hostNetSource(nil)}).BoxAddrs(t.Context()); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// The sweep must not probe the LAN address of the appliance, which only vedette-host can report.
func TestSensorProtectedIPsIncludeTheHostsAddresses(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	prot, err := sensorInventory{inv: s.d.Inventory, hostNet: hostNetSource(lanBox())}.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.10.250", "192.168.10.201"} {
		if !slices.Contains(prot, netip.MustParseAddr(a)) {
			t.Errorf("%s is not protected from the sweep", a)
		}
	}
	if slices.Contains(prot, netip.MustParseAddr("fd00:1::5")) {
		t.Error("an IPv6 address in an IPv4 list")
	}
	// A dead host does not break the sweep's own list.
	if _, err := (sensorInventory{inv: s.d.Inventory, hostNet: hostNetSource(&fakeNet{err: errors.New("x")})}).ProtectedIPs(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The honeypot's box address falls back to the appliance's own LAN address.
func TestHoneypotBoxFallsBackToTheHostsAddress(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.saveScope(t)
	a := honeypotInventory{inv: s.d.Inventory, hostNet: hostNetSource(lanBox())}
	b, err := a.Box(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if b.IP != netip.MustParseAddr("192.168.10.250") {
		t.Fatalf("box IP %v, want the host's address inside the declared range", b.IP)
	}
}
