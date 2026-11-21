package inventory_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// A firewall on a VDOM interface: SNMP is read at a device's management address, 100.65.253.1, while the device is 100.65.254.1. What
// answers there is that device and nothing else: the observation names the device (AssetHint.Device), so it never finds the device
// another sensor saw at 100.65.253.1, never makes a new one, never moves an address and never joins two rows.
func TestContract_AnSNMPAnswerFromTheReadAddressIsThisDeviceOnly(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "100.65.254.1", "")...)
	fw := e.idOf("100.65.254.1")
	e.record(dhcp(burnt2, "100.65.253.1", "")...) // the global VDOM interface, seen by a scan as a device of its own
	other := e.idOf("100.65.253.1")
	snmp := func(id string) []observe.Observation {
		h := observe.AssetHint{Device: id}
		return []observe.Observation{
			{AssetHint: h, Field: observe.Hostname, Value: "FGT-HQ", Source: observe.SNMP, Confidence: 0.9},
			{AssetHint: h, Field: observe.Model, Value: "FortiGate 1500D", Source: observe.SNMP, Confidence: 0.9},
		}
	}
	e.record(snmp(fw)...)
	if n := e.devices(); n != 2 {
		t.Fatalf("%d devices, want the same 2", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'snmp'`, fw); n != 2 {
		t.Errorf("the FortiGate has %d SNMP observations, want 2", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND source = 'snmp'`, other); n != 0 {
		t.Errorf("the device at the read address got %d SNMP observations, want none", n)
	}
	if e.idOf("100.65.254.1") != fw || e.idOf("100.65.253.1") != other {
		t.Error("an address moved")
	}
	// A device deleted meanwhile: the answer is dropped, nothing is made.
	e.record(snmp("a-gone")...)
	if n := e.devices(); n != 2 {
		t.Errorf("%d devices after an answer for a deleted one, want 2", n)
	}
	// Only SNMP names a device, and alone.
	for name, o := range map[string]observe.Observation{
		"another source": {AssetHint: observe.AssetHint{Device: fw}, Field: observe.Hostname, Value: "x", Source: observe.Nmap, Confidence: 0.5},
		"with an address": {AssetHint: observe.AssetHint{Device: fw, IP: netip.MustParseAddr("100.65.253.1")}, Field: observe.Hostname, Value: "x",
			Source: observe.SNMP, Confidence: 0.5},
		"a MAC": {AssetHint: observe.AssetHint{Device: fw}, Field: observe.MAC, Value: burnt2, Source: observe.SNMP, Confidence: 0.5},
	} {
		var rej *observe.ErrRejected
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); !errors.As(err, &rej) {
			t.Errorf("%s: %v, want a rejection", name, err)
		}
	}
}

// A device hint is only for SNMP observations (Record): the software and service lists and the enrolment refuse it, so none of them
// ever makes a blank device from it.
func TestContract_ADeviceHintIsRefusedOutsideRecord(t *testing.T) {
	e := newEnv(t)
	e.record(dhcp(burnt1, "100.65.254.1", "")...)
	fw := e.idOf("100.65.254.1")
	h := observe.AssetHint{Device: fw}
	sw := []observe.Software{{Display: "FortiOS 7.2.8", Vendor: "fortinet", Product: "fortios", Version: "7.2.8", Confidence: 0.9}}
	svc := []observe.Service{{Port: 161, Proto: "udp", Name: "snmp", Confidence: 0.9}}
	for name, err := range map[string]error{
		"ReplaceSoftware": e.svc.ReplaceSoftware(e.ctx(), h, observe.SNMP, nil, sw),
		"AddServices":     e.svc.AddServices(e.ctx(), h, observe.SNMP, svc),
		"ReplaceServices": e.svc.ReplaceServices(e.ctx(), h, observe.Nmap, observe.ServiceScope{}, svc),
		"ApproveEnrolled": func() error { _, err := e.svc.ApproveEnrolled(e.ctx(), h, "", "test", false); return err }(),
	} {
		if err == nil {
			t.Errorf("%s took a device hint", name)
		}
	}
	if n := e.devices(); n != 1 {
		t.Fatalf("%d devices, want the one", n)
	}
}
