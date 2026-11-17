package main

import (
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/inventory"
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

// The appliance families a port on the Internet names are tied, in one read, to the inventory devices that are one: the FortiGate
// added from the catalog (its FortiOS software carries the family's KEV key), never a PC that runs the vendor's VPN client
// (FortiClient carries a FortiOS SSL-VPN key, AnyConnect expands to "anyconnect secure"), and nothing for a family with no device.
func TestExposureApplianceDevices(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-1001", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1002", "Fortinet", "FortiOS")
	s.kev("CVE-2026-1003", "Fortinet", "FortiOS and FortiProxy SSL-VPN")
	s.kev("CVE-2026-1004", "Cisco", "AnyConnect Secure")
	id := s.addFortiGate() // three findings: its FortiOS matches the SSL-VPN entry too
	for i, c := range []string{"fortinet-forticlient-ssl-vpn", "cisco-anyconnect-secure-client"} {
		if _, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: c, Version: "7.0.1", IP: fmt.Sprintf("192.168.30.%d", 50+i)}); err != nil {
			t.Fatal(err)
		}
	}
	g := exposureGateway{inv: s.d.Inventory, fnd: s.d.Findings}
	qs := []exposure.ApplianceQuery{
		{Family: "fortigate", KevKeys: []string{"fortinet|fortios"}, Device: regexp.MustCompile(`(?i)\bforti(gate|os|wifi)\b`)},
		{Family: "cisco-asa", KevKeys: []string{"cisco|adaptive security appliance (asa)"}, Device: regexp.MustCompile(`(?i)\bcisco asa\b`)},
		{Family: "paloalto", KevKeys: []string{"palo alto networks|pan-os"}, Device: regexp.MustCompile(`(?i)\bpan-os\b`)},
	}
	got, err := g.ApplianceDevices(t.Context(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if fg := got["fortigate"]; len(fg.Devices) != 1 || fg.Devices[0].DeviceID != id || fg.Devices[0].OpenExploited != 3 || fg.Devices[0].Name == "" || fg.More != 0 {
		t.Fatalf("FortiGate: %+v", fg)
	}
	for _, f := range []string{"cisco-asa", "paloalto"} {
		if m, ok := got[f]; !ok || m.Devices == nil || len(m.Devices) != 0 {
			t.Fatalf("%s: %+v (a VPN client PC is not the appliance)", f, m)
		}
	}
	// A large estate: the first exposure.MaxApplianceDevices are listed, the others counted.
	for i := range 5 {
		if _, err := s.d.Inventory.AddDevice(t.Context(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: fmt.Sprintf("192.168.31.%d", 1+i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err = g.ApplianceDevices(t.Context(), qs); err != nil || len(got["fortigate"].Devices) != exposure.MaxApplianceDevices || got["fortigate"].More != 1 {
		t.Fatalf("six FortiGates: %+v %v", got["fortigate"], err)
	}
}
