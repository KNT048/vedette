package inventory_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// INV-25 (D-503, review #665): the enrolment approves only the row that is the agent's machine. An address the box answers on is no
// device (as in Record); a row once seen with another MAC (DHCP gave the address to a new machine) is found but left for a person;
// a row seen with the agent's MAC only, or with no MAC at all, is approved.
func TestContract_INV25_ApproveEnrolledOnlyTheAgentsMachine(t *testing.T) {
	t.Parallel()
	var decoy atomic.Bool
	owned := netip.MustParseAddr("192.168.10.240")
	e := newEnv(t, func(c *inventory.Config) {
		c.BoxOwnedIPs = func(context.Context) []netip.Addr {
			if decoy.Load() {
				return []netip.Addr{owned}
			}
			return nil
		}
	})
	seen := func(ip, mac string) {
		t.Helper()
		h := observe.AssetHint{IP: netip.MustParseAddr(ip), MAC: mac}
		o := observe.Observation{AssetHint: h, Field: observe.Hostname, Value: "seen", Source: observe.Passive, Confidence: 0.6}
		if mac != "" {
			o = observe.Observation{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}
		}
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	approve := func(ip, mac string) (found, approved bool) {
		t.Helper()
		found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, mac, "osquery on \"x\" enrolled with the token \"t\"")
		if err != nil {
			t.Fatal(err)
		}
		return found, e.count(`SELECT count(*) FROM inv_asset WHERE ip = ? AND approved = 1`, ip) == 1
	}
	const agentMAC = "52:54:00:aa:bb:01"

	seen("192.168.10.21", "52:54:00:00:00:99") // the old machine; the agent's machine got its address
	if found, ok := approve("192.168.10.21", agentMAC); !found || ok {
		t.Fatalf("a row seen with another MAC: found=%v approved=%v", found, ok)
	}
	seen("192.168.10.22", agentMAC)
	if found, ok := approve("192.168.10.22", agentMAC); !found || !ok {
		t.Fatalf("the agent's own row: found=%v approved=%v", found, ok)
	}
	seen("192.168.10.23", "") // no MAC known (a routed subnet): the address is all both sides know
	if found, ok := approve("192.168.10.23", agentMAC); !found || !ok {
		t.Fatalf("a row with no MAC: found=%v approved=%v", found, ok)
	}
	seen("192.168.10.24", "52:54:00:00:00:24")
	if found, ok := approve("192.168.10.24", ""); !found || ok {
		t.Fatalf("an agent with no MAC on a row with one: found=%v approved=%v", found, ok)
	}
	seen(owned.String(), "") // made before the address became a decoy
	decoy.Store(true)
	if found, ok := approve(owned.String(), agentMAC); found || ok {
		t.Fatalf("an address the box answers on: found=%v approved=%v", found, ok)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`); n != 2 {
		t.Fatalf("%d approval audit rows, want 2", n)
	}
}
