package capture

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// D-501: the vendor class (DHCP option 60) of a known DHCP client gives an OS hint; anything else gives nothing.
func TestDHCPVendorClassGivesAnOSHint(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"MSFT 5.0":        "Microsoft Windows",
		"android-dhcp-13": "Android 13",
		"android-dhcp-x1": "Android",
		"dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:BCM2835": "Linux",
		"dhcpcd-10.0.6:NetBSD-10.0:amd64:x86":           "NetBSD",
		"udhcp 1.36.1":                                  "Linux (BusyBox)",
		"Cisco Systems, Inc. IP Phone CP-7841":          "",
		"dhcpcd-9.4.1:Plan9-4":                          "",
		"":                                              "",
	} {
		if got := dhcpOS(in); got != want {
			t.Errorf("dhcpOS(%q) = %q, want %q", in, got, want)
		}
	}
	e, _ := newEngine(own)
	req := pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: "bobs-phone", VendorClass: "android-dhcp-14"})
	e.Handle(frameDHCP(pktgen.Phone, pktgen.Bcast, zeroIP, bcastIP, 68, 67, req))
	obs, _ := e.Drain(pktgen.T0, true)
	found := false
	for _, o := range obs {
		if o.Field == observe.OS {
			found = o.Value == "Android 14" && o.Confidence == ConfDHCPOS
		}
	}
	if !found {
		t.Errorf("no OS observation from option 60: %v", obs)
	}
}

// D-501: an LLDP Telephone capability (an IP desk phone, which also bridges its PC port) says iot, before Bridge says switch.
func TestLLDPTelephoneIsIot(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(own)
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "1", SysName: "phone-101", Caps: lldpCapBridge | lldpCapTelephone})})
	obs, _ := e.Drain(pktgen.T0, true)
	var kinds []string
	for _, o := range obs {
		if o.Field == observe.Kind {
			kinds = append(kinds, o.Value)
		}
	}
	if len(kinds) != 1 || kinds[0] != "iot" {
		t.Errorf("kinds = %v, want [iot]", kinds)
	}
}

// n69: a Mac answers mDNS for its services under a UUID host name ("6a3d1565-….local") and some TXT records carry "model=0,1,2". Neither
// names the machine: no observation, counted as value_meaningless. Its real name and model in the same answer still go out, and a DHCP
// host name that is a bare UUID is dropped too.
func TestIdentifiersAndNumberListsAreNoNameOrModel(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(own)
	mdns := netip.MustParseAddr("224.0.0.251")
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Mcast4, pktgen.Laptop, pktgen.LaptopIP, mdns, 5353, 5353, pktgen.DNSMessage(0, true, nil, []pktgen.DNSRecord{
		pktgen.RR("6a3d1565-2a3d-4d87-afe3-9e59546c8acc.local", dnsTypeA, pktgen.A(pktgen.LaptopIP)),
		pktgen.RR("0123456789abcdef0123456789ABCDEF.local", dnsTypeA, pktgen.A(pktgen.LaptopIP)),
		pktgen.RR("Kiens-MacBook-Air.local", dnsTypeA, pktgen.A(pktgen.LaptopIP)),
		pktgen.RR("Kiens-MacBook-Air._companion-link._tcp.local", dnsTypeTXT, pktgen.TXT("model=0,1,2")),
		pktgen.RR("Kiens-MacBook-Air._device-info._tcp.local", dnsTypeTXT, pktgen.TXT("model=Mac14,2")),
	}))})
	req := pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: "fbaf5191-cc17-4626-a85b-812bc3d7b83b"})
	e.Handle(frameDHCP(pktgen.Phone, pktgen.Bcast, zeroIP, bcastIP, 68, 67, req))
	obs, _ := e.Drain(pktgen.T0, true)
	var names, models []string
	for _, o := range obs {
		switch o.Field {
		case observe.Hostname:
			names = append(names, o.Value)
		case observe.Model:
			models = append(models, o.Value)
		}
	}
	if len(names) != 1 || names[0] != "kiens-macbook-air" || len(models) != 1 || models[0] != "Mac14,2" {
		t.Errorf("names %v models %v; want [kiens-macbook-air] [Mac14,2]", names, models)
	}
	if got := e.Counters()["value_meaningless"]; got != 4 {
		t.Errorf("value_meaningless = %d, want 4 (two UUID names, a number list, a DHCP UUID)", got)
	}
	for v, want := range map[string]bool{"Mac14,2": true, "0,1,2": false, "1234": false, "EX2300-24T": true} {
		if UsefulValue(observe.Model, v) != want {
			t.Errorf("model %q useful = %v", v, !want)
		}
	}
}
