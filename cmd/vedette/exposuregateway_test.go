package main

import (
	"errors"
	"regexp"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
)

// The gateway is the host's LAN default route, matched by IP to an inventory device whose open findings are counted.
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

// An appliance family a port on the Internet names is tied to the inventory devices of that family, each with its open findings:
// the FortiGate added from the catalog (its FortiOS software carries the KEV key), and nothing for a family with no device.
func TestExposureApplianceDevices(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	id := s.addFortiGate() // two findings
	g := exposureGateway{inv: s.d.Inventory, fnd: s.d.Findings}

	got, err := g.ApplianceDevices(t.Context(), exposure.ApplianceQuery{KevKeys: []string{"fortinet|fortios"}, Device: regexp.MustCompile(`(?i)\bforti(gate|os)\b`)})
	if err != nil || len(got) != 1 || got[0].DeviceID != id || got[0].OpenExploited != 2 || got[0].Name == "" {
		t.Fatalf("FortiGate: %+v %v", got, err)
	}
	// The device text alone is enough (a device whose software row has no KEV key, an SNMP-read model).
	if got, err = g.ApplianceDevices(t.Context(), exposure.ApplianceQuery{Device: regexp.MustCompile(`(?i)\bfortios\b`)}); err != nil || len(got) != 1 {
		t.Fatalf("by text: %+v %v", got, err)
	}
	got, err = g.ApplianceDevices(t.Context(), exposure.ApplianceQuery{KevKeys: []string{"palo alto networks|pan-os"}, Device: regexp.MustCompile(`(?i)\bpan-os\b`)})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no Palo Alto: %+v %v", got, err)
	}
}
