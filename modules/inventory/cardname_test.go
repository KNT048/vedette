package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// The maker a network scan or the passive sensor reports is the one of the network card (the MAC's IEEE prefix): an ESXi host on an
// HPE card is not "Hewlett Packard", and two firewalls of one maker are not both "Fortinet". Such a device is named after the OS or
// firmware it states, else "<maker> device"; a maker SNMP, an agent or a person gives, or a model, still names it. Every reader of a
// name (the list, the page, Names, the audit name, DeviceRefs) gives the same one.
func TestDeviceName_CardMakerIsAWeakName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := func(last byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, last}) }
	const (
		esxi, fw, sw, snmp, guess = "aa:bb:cc:00:01:01", "aa:bb:cc:00:01:02", "aa:bb:cc:00:01:03", "aa:bb:cc:00:01:04", "aa:bb:cc:00:01:05"
	)
	e.record(
		obs(at(10), esxi, observe.MAC, esxi, observe.Nmap, 0.9), obs(at(10), esxi, observe.Vendor, "Hewlett Packard", observe.Nmap, 0.6),
		obs(at(10), esxi, observe.Vendor, "Hewlett Packard", observe.Passive, 0.4),
		obs(at(10), esxi, observe.OS, "VMware ESXi 8.0 Update 3 (build 24022510)", observe.Nmap, 0.95), // its own statement
		obs(at(11), fw, observe.MAC, fw, observe.Nmap, 0.9), obs(at(11), fw, observe.Vendor, "Fortinet", observe.Nmap, 0.6),
		obs(at(12), sw, observe.MAC, sw, observe.Passive, 0.9), obs(at(12), sw, observe.Vendor, "Juniper Networks", observe.Passive, 0.4),
		obs(at(12), sw, observe.Model, "EX4200-48T", observe.Passive, 0.5),
		obs(at(13), snmp, observe.MAC, snmp, observe.Nmap, 0.9), obs(at(13), snmp, observe.Vendor, "Fortinet", observe.SNMP, 0.9),
		obs(at(14), guess, observe.MAC, guess, observe.Nmap, 0.9), obs(at(14), guess, observe.Vendor, "Routerboard.com", observe.Nmap, 0.6),
		obs(at(14), guess, observe.OS, "MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)", observe.Nmap, 0.95), // nmap's fingerprint: a guess
	)
	want := map[string]string{esxi: "VMware ESXi", fw: "Fortinet device", sw: "Juniper Networks EX4200-48T", snmp: "Fortinet", guess: "Routerboard.com device"}
	names, err := e.svc.Names(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for mac := range want {
		ids[mac] = e.idByMAC(mac)
	}
	list := []string{}
	for _, id := range ids {
		list = append(list, id)
	}
	refs, err := e.svc.DeviceRefs(e.ctx(), list)
	if err != nil {
		t.Fatal(err)
	}
	for mac, w := range want {
		id := ids[mac]
		d, err := e.svc.Device(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Name(); got != w {
			t.Errorf("%s: Device.Name %q, want %q", mac, got, w)
		}
		if got := names[id]; got != w {
			t.Errorf("%s: Names %q, want %q", mac, got, w)
		}
		if got := inventory.DisplayName(refs[id].NameFacts("")); got != w {
			t.Errorf("%s: DeviceRefs %q, want %q", mac, got, w)
		}
	}
	// a name a person gives, and a host name, still win
	if err := e.svc.PatchDevice(e.ctx(), "it@example.com", ids[fw], inventory.Patch{Name: new("Branch firewall")}); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.svc.Device(e.ctx(), ids[fw]); d.Name() != "Branch firewall" {
		t.Errorf("renamed: %q", d.Name())
	}
}

func TestOSProduct(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"VMware ESXi 8.0 Update 3 (build 24022510)": "VMware ESXi",
		"MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)": "MikroTik RouterOS",
		"JUNOS 15.1R7.9": "JUNOS",
		"Ubuntu 26.04":   "Ubuntu",
		"Microsoft Windows Server 2025 10.0.26100": "Microsoft Windows Server",
		"8.0.3": "",
		"":      "",
	} {
		if got := inventory.OSProduct(in); got != want {
			t.Errorf("OSProduct(%q) = %q, want %q", in, got, want)
		}
	}
}
