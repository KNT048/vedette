package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// D-446 review: on a container-only install (no host) the machine's addresses are the gateway, the -hosts literals, VEDETTE_BIND_IP
// and the host-alias names, so https://<LAN IP>:8443 cannot reach core through the published port.
func TestD446_MachineSourcesOfAContainerOnlyInstall(t *testing.T) {
	t.Parallel()
	m := machineSources{
		gateways: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("172.18.0.1")} },
		hosts:    []string{"vedette.lan", "192.168.18.141", "[fd00::141]", "0.0.0.0"},
		bindIP:   "192.168.18.142",
		aliases:  func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.65.254")} },
	}
	got, known := m.addrs()
	want := []string{"172.18.0.1", "192.168.18.141", "fd00::141", "192.168.18.142", "192.168.65.254"}
	if !known || len(got) != len(want) {
		t.Fatalf("addrs = %v, %v", got, known)
	}
	for _, w := range want {
		if !slices.Contains(got, netip.MustParseAddr(w)) {
			t.Errorf("%s is missing from %v", w, got)
		}
	}
	// the appliance: the host's flag carries through
	if _, known := (machineSources{host: func() ([]netip.Addr, bool) { return nil, false }}).addrs(); known {
		t.Error("an unknown host set reads as known")
	}
}

// The alias names resolve in place once, then a stale answer is served while one refresh runs; a name that fails adds nothing.
func TestD446_HostAliasCache(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	var clock atomic.Int64
	refreshed := make(chan struct{}, 4)
	c := &aliasCache{
		now: func() time.Time { return time.Unix(clock.Load(), 0) },
		resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			calls.Add(1)
			if host == "host.docker.internal" {
				return nil, errors.New("no such host")
			}
			defer func() { refreshed <- struct{}{} }()
			return []netip.Addr{netip.MustParseAddr("10.88.0.1")}, nil
		},
	}
	if got := c.get(); len(got) != 1 || got[0] != netip.MustParseAddr("10.88.0.1") {
		t.Fatalf("first get = %v", got)
	}
	<-refreshed
	if c.get(); calls.Load() != 2 {
		t.Errorf("a fresh answer was resolved again: %d calls", calls.Load())
	}
	clock.Store(int64(aliasTTL / time.Second))
	if got := c.get(); len(got) != 1 { // stale: the last answer, and a refresh in the background
		t.Errorf("stale get = %v", got)
	}
	<-refreshed // sent by the second name's lookup, after the first one's
	if calls.Load() != 4 {
		t.Errorf("%d resolutions, want 4 (two names, twice)", calls.Load())
	}
}
