package main

import (
	"errors"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// D-492: the gateway is the host's LAN default route, matched by IP to an inventory device whose open findings are counted.
func TestExposureGateway(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	id := s.addFortiGate() // 192.168.30.1, two findings
	route := func(gw string) *fakeNet { return &fakeNet{st: api.NetState{DefaultRoute: &api.NetRoute{Gateway: gw}}} }
	g := func(st netStateReader) exposureGateway {
		return exposureGateway{state: st, inv: s.d.Inventory, fnd: s.d.Findings}
	}

	got, err := g(route("192.168.30.1")).Gateway(t.Context())
	if err != nil || got.IP.String() != "192.168.30.1" || got.DeviceID != id || got.OpenExploited != 2 || got.Name == "" {
		t.Fatalf("gateway in inventory: %+v %v", got, err)
	}
	if got, err = g(route("192.168.30.254")).Gateway(t.Context()); err != nil || got.IP.String() != "192.168.30.254" || got.DeviceID != "" || got.OpenExploited != 0 {
		t.Fatalf("gateway not in inventory: %+v %v", got, err)
	}
	if got, err = g(&fakeNet{}).Gateway(t.Context()); err != nil || got.IP.IsValid() {
		t.Fatalf("no default route: %+v %v", got, err)
	}
	if got, err = g(nil).Gateway(t.Context()); err != nil || got.IP.IsValid() {
		t.Fatalf("no host: %+v %v", got, err)
	}
	if _, err = g(&fakeNet{err: errors.New("host down")}).Gateway(t.Context()); err == nil {
		t.Fatal("a host that fails must fail the read (the page then says it cannot tell)")
	}
}
