package main

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// D-511: the inventory's gateway signal is the host's IPv4 default gateway, read again after a minute; a failed read is unknown, and
// kept for that minute too, so a host that does not answer costs one timeout a minute, not one per page (#714 M3).
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
	down := &fakeNet{err: errors.New("host down")}
	failing := &gatewayCache{state: down, now: func() time.Time { return now }}
	if ip := failing.Get(t.Context()); ip.IsValid() {
		t.Fatalf("a failed read is unknown, got %v", ip)
	}
	failing.Get(t.Context())
	if down.calls != 1 {
		t.Fatalf("a failed read was asked again %d times within the minute", down.calls-1)
	}
	now = now.Add(2 * time.Minute)
	failing.Get(t.Context())
	if down.calls != 2 {
		t.Fatalf("after a minute a failed read is asked again: %d calls", down.calls)
	}
	none := &gatewayCache{state: &fakeNet{}, now: func() time.Time { return now }}
	if ip := none.Get(t.Context()); ip.IsValid() {
		t.Fatalf("no default route is unknown, got %v", ip)
	}
}
