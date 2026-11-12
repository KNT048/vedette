package response_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// D-325 (deferred sweep item 4): the gateway and DNS servers the box uses are never-touch without being listed (INV-10), and a source that cannot
// be read refuses, like the box's own addresses.
func TestD325_TheBoxGatewayAndDNSAreNeverTouch(t *testing.T) {
	infra := []response.HostInfra{
		{Addr: netip.MustParseAddr("192.168.10.1"), Kind: "gateway"},
		{Addr: netip.MustParseAddr("192.168.10.53"), Kind: "dns"},
		{Addr: netip.MustParseAddr("::ffff:192.168.10.54"), Kind: "dns"}, // an IPv4-mapped form is the IPv4 address
	}
	var fail error
	e := newEnv(t, func(c *response.Config) {
		c.HostInfra = func() ([]response.HostInfra, error) { return infra, fail }
	})
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	for _, want := range []string{"192.168.10.1", "192.168.10.53", "192.168.10.54"} {
		if !hasEntry(l, want) {
			t.Fatalf("%s is not on the never-touch list: %+v", want, l)
		}
	}
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "192.168.10.1"))
	if len(e.actions()) != 0 || !e.logHas("refused", "never_touch") {
		t.Fatal("an automated ban of the box's default gateway was not refused")
	}
	fail = errors.New("vedette-host has not answered")
	e.fire(e.iocEvent("e2", "198.51.100.7"))
	if len(e.actions()) != 0 {
		t.Fatal("an unreadable gateway/DNS source did not refuse (it must fail closed, not check a shorter list)")
	}
}

// D-384: the gateway's MAC is never-touch without the gateway being an inventory router: an action that names only the device's switch
// port, aimed at an event whose subject is the gateway's MAC (no gateway address in it), is refused. An IPv6 link-local gateway, which
// no action can name by address, is protected by its MAC alone.
func TestD384_TheBoxGatewayMACIsNeverTouch(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *response.Config) {
		c.HostInfra = func() ([]response.HostInfra, error) {
			return []response.HostInfra{
				{Addr: netip.MustParseAddr("192.168.10.1"), Kind: "gateway", MAC: "00:11:22:33:44:55"},
				{Addr: netip.MustParseAddr("fe80::1"), Kind: "gateway", MAC: "00:11:22:33:44:66"},
				{Addr: netip.MustParseAddr("192.168.10.53"), Kind: "dns"},
			}, nil
		}
	})
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	for _, want := range []string{"00:11:22:33:44:55", "00:11:22:33:44:66"} {
		if !hasEntry(l, want) {
			t.Fatalf("the gateway MAC %s is not on the never-touch list: %+v", want, l)
		}
	}
	if hasEntry(l, "fe80::1") {
		t.Fatalf("a link-local address became an entry: %+v", l)
	}
	e.sshSwitch("cisco_port_shut")
	e.rule("Shut the port", "ioc_connection", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(240)}}, nil)
	for i, mac := range []string{"00:11:22:33:44:55", "00-11-22-33-44-66"} {
		ev := e.iocEvent("e"+itoaTest(i), "198.51.100.7")
		ev.Fields["mac"], ev.Fields["switch_port"] = mac, "Gi1/0/"+itoaTest(i+2)
		e.fire(ev)
	}
	if n := len(e.actions()); n != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'never_touch%'`) != 2 {
		t.Fatalf("a port shut aimed at the gateway's MAC was not refused: %d request(s)", n)
	}
	other := e.iocEvent("e9", "198.51.100.7")
	other.Fields["mac"], other.Fields["switch_port"] = "00:11:22:33:44:77", "Gi1/0/9"
	e.fire(other)
	if len(e.actions()) != 1 {
		t.Fatal("a port shut aimed at another device was refused")
	}
}

// D-325 review (MEDIUM): the GUI sends back the whole list GET showed. The seeded entries come back unchanged and are not stored (a stored
// copy would outlive a gateway that changed); GET shows one row per value; the same address under the administrator's own label is a
// declared entry and stays.
func TestD325_SavingTheShownListDoesNotStoreTheSeededEntries(t *testing.T) {
	gw := netip.MustParseAddr("192.168.10.1")
	e := newEnv(t, func(c *response.Config) {
		c.HostInfra = func() ([]response.HostInfra, error) {
			return []response.HostInfra{{Addr: gw, Kind: "gateway"}, {Addr: netip.MustParseAddr("192.168.10.53"), Kind: "dns"}}, nil
		}
	})
	shown, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	shown = append(shown, response.AllowEntry{Value: "198.51.100.0/24", Label: "Declared service"})
	_, err = e.svc.SetAllowlist(e.ctx(), admin, shown)
	e.must(err)
	var stored int
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT count(*) FROM resp_allowlist`).Scan(&stored))
	if stored != 1 {
		t.Fatalf("%d rows stored, want only the declared one (the seeded entries were saved back)", stored)
	}
	_, err = e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "192.168.10.1", Label: "Core router"}})
	e.must(err)
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	n := 0
	for _, x := range l {
		if x.Value == "192.168.10.1" {
			n++
			if x.Label != "Core router" {
				t.Errorf("the administrator's label was replaced: %q", x.Label)
			}
		}
	}
	if n != 1 {
		t.Fatalf("192.168.10.1 is shown %d times, want once", n)
	}
}
