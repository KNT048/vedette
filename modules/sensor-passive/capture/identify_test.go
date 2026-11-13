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
