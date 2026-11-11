package response_test

import (
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// INV-10 (M-C): an action that names a device part (an interface, a MAC, a VLAN, a port) acts on the device the event is about, with or
// without an address next to it, so the event's subject is checked for it. A custom action that names both a port and an address
// ("interface {interface} ... {ip}") on an event about the never-touch router is refused just like the built-in port action.
func TestContract_INV10_AddressPlusPortActionChecksTheSubject(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.dir.devices["a-gw"] = response.DeviceInfo{ID: "a-gw", Name: "Edge router", IP: "192.168.10.1", Kind: "router"}
	e.conns.list = append(e.conns.list, response.ConnectionInfo{Connection: response.Connection{ID: "cn-sw", Name: "Core switch", Enabled: true, Kind: "ssh", WriteTools: []string{"cli"}}, Target: "ssh://sw.lan"})
	cust, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Shut port and tag", ConnectionID: "cn-sw",
		Run:      response.Tpl{CLI: "interface {interface}\n    shutdown\n    description vedette-{ip}"},
		Rollback: response.Tpl{CLI: "interface {interface}\n    no shutdown"}, Risk: response.RiskMedium, Enabled: true,
		Precheck: response.Tpl{CLI: "show interfaces {interface} switchport"}, PrecheckRefuse: []string{"Administrative Mode: trunk"}})
	e.must(err)
	cid, on := "cn-sw", true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "cisco_port_shut", response.CatalogUpdate{ConnectionID: &cid, Enabled: &on, Present: map[string]bool{"connection_id": true, "enabled": true}})
	e.must(err)
	e.rule("Builtin port shut", "ioc_connection", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}}}, nil)
	e.rule("Custom port shut", "ioc_connection", []response.RuleAction{{ActionID: cust.ID, Params: map[string]string{"interface": "{{trigger.switch_port}}", "ip": "{{trigger.dest_ip}}"}}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["src_ip"], ev.Fields["device"], ev.Fields["switch_port"] = "192.168.10.1", "Edge router", "Gi1/0/1" // the router's own uplink
	e.fire(ev)
	if !e.logHas("refused", "never_touch: Builtin port shut") || !e.logHas("refused", "never_touch: Custom port shut") {
		t.Fatal("a port action on the never-touch router was not refused (built-in and custom)")
	}
	if l := e.actions(); len(l) != 0 {
		t.Fatalf("%d request(s) planned for the router's port: %s", len(l), l[0].Items[0].Change.CLI)
	}
	ev2 := e.iocEvent("e2", "198.51.100.8") // another device on another port: allowed
	ev2.Fields["switch_port"] = "Gi1/0/5"
	e.fire(ev2)
	if len(e.actions()) != 2 {
		t.Fatalf("%d requests for a device that is not never-touch, want 2", len(e.actions()))
	}
}

// INV-10: an action that names only an address acts on that address only: blocking the destination is not refused because the device
// that talked to it is the router (the router itself still cannot be blocked).
func TestContract_INV10_AddressOnlyActionIgnoresTheSubject(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.dir.devices["a-gw"] = response.DeviceInfo{ID: "a-gw", Name: "Edge router", IP: "192.168.10.1", Kind: "router"}
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["src_ip"] = "192.168.10.1"
	e.fire(ev)
	if len(e.actions()) != 1 {
		t.Fatalf("%d requests, want 1: an address-only action must not take the event's subject", len(e.actions()))
	}
	e.fire(e.iocEvent("e2", "192.168.10.1"))
	if !e.logHas("refused", "never_touch") {
		t.Fatal("blocking the router itself was not refused")
	}
}

// INV-10: an address parameter cannot be empty or optional: an event without the value is refused (invalid_target), so the "names an
// address" branch is only taken with a checked, non-empty address.
func TestContract_INV10_EmptyAddressParamIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	sum := e.fire(e.iocEvent("e1", ""))
	if sum.Refused != 1 || len(e.actions()) != 0 || !e.logHas("refused", "invalid_target") {
		t.Fatalf("an empty address was not refused: %+v", sum)
	}
}

// INV-10 (L7): a never-touch entry pasted from a Cisco device (aabb.ccdd.eeff) or a label (twelve hex digits) is stored in the
// canonical form and matches the event's subject in any form.
func TestContract_INV10_NeverTouchAcceptsCiscoAndBareMACs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	got, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{
		{Value: "AABB.CCDD.EEFF", Label: "Core switch"}, {Value: "112233445566", Label: "Uplink"}, {Value: "aa-bb-cc-00-00-01", Label: "Dashes"}})
	e.must(err)
	for _, want := range []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "aa:bb:cc:00:00:01"} {
		if !hasEntry(got, want) {
			t.Errorf("%s is not stored in the canonical form: %+v", want, got)
		}
	}
	e.rule("Shut the port", "ioc_connection", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(240)}}, nil)
	for i, mac := range []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "aa:bb:cc:00:00:01"} {
		ev := e.iocEvent("e"+itoaTest(i), "198.51.100.7")
		ev.Fields["mac"], ev.Fields["switch_port"] = mac, "Gi1/0/"+itoaTest(i+2)
		e.fire(ev)
	}
	if l := e.actions(); len(l) != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'never_touch%'`) != 3 {
		t.Fatalf("a never-touch MAC was not protected: %d request(s)", len(l))
	}
}
