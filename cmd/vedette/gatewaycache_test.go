package main

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// D-511: the inventory's gateway signal is the host's IPv4 default gateway, read again after a minute; a failed read is unknown and is
// not kept.
func TestGatewayCache(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	net := &fakeNet{st: api.NetState{DefaultRoute: &api.NetRoute{Gateway: "192.168.18.1"}}}
	g := &gatewayCache{state: net, now: func() time.Time { return now }}
	if ip := g.Get(t.Context()); ip.String() != "192.168.18.1" {
		t.Fatalf("gateway = %v", ip)
	}
	net.st.DefaultRoute.Gateway = "192.168.18.254"
	if ip := g.Get(t.Context()); ip.String() != "192.168.18.1" {
		t.Fatalf("within a minute the cached gateway is kept, got %v", ip)
	}
	now = now.Add(2 * time.Minute)
	if ip := g.Get(t.Context()); ip.String() != "192.168.18.254" {
		t.Fatalf("after a minute the gateway is read again, got %v", ip)
	}
	failing := &gatewayCache{state: &fakeNet{err: errors.New("host down")}, now: func() time.Time { return now }}
	if ip := failing.Get(t.Context()); ip.IsValid() {
		t.Fatalf("a failed read is unknown, got %v", ip)
	}
	none := &gatewayCache{state: &fakeNet{}, now: func() time.Time { return now }}
	if ip := none.Get(t.Context()); ip.IsValid() {
		t.Fatalf("no default route is unknown, got %v", ip)
	}
}
