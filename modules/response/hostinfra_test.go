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
