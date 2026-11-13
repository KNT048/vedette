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
		found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, mac, "osquery on \"x\" enrolled with the token \"t\"", false)
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

// INV-25 (D-503, the upgrade path): an OS the agent reported before agents sent a kind types the device when the enrolment approves it,
// at the agent's rank; an OS another source saw types nothing, a person's kind wins, and the row of another machine is left as it is.
func TestContract_INV25_ApproveEnrolledTypesFromTheAgentsOS(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	rec := func(ip string, src observe.Source, f observe.Field, v string) {
		t.Helper()
		o := observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: f, Value: v, Source: src, Confidence: 0.95}
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	kind := func(ip string) string {
		t.Helper()
		var k string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT kind FROM inv_asset WHERE ip = ?`, ip).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	approve := func(ip, mac string) {
		t.Helper()
		if _, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, mac, "r", false); err != nil {
			t.Fatal(err)
		}
	}
	const mac = "52:54:00:aa:bb:01"
	rec("192.168.10.31", observe.Agent, observe.OS, "Ubuntu 26.04 LTS (Resolute Raccoon)")
	approve("192.168.10.31", mac)
	if k := kind("192.168.10.31"); k != "server" {
		t.Fatalf("an agent's Ubuntu: %q", k)
	}
	rec("192.168.10.32", observe.Nmap, observe.OS, "Ubuntu 26.04 LTS")
	approve("192.168.10.32", mac)
	if k := kind("192.168.10.32"); k != "unknown" {
		t.Fatalf("an OS nmap guessed typed the device: %q", k)
	}
	rec("192.168.10.33", observe.Agent, observe.OS, "Microsoft Windows 11 Pro 10.0.22631 build 22631")
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE ip = '192.168.10.33'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	nas := "nas"
	if err := e.svc.PatchDevice(e.ctx(), "admin@acme.example", id, inventory.Patch{Kind: &nas}); err != nil {
		t.Fatal(err)
	}
	approve("192.168.10.33", mac)
	if k := kind("192.168.10.33"); k != "nas" {
		t.Fatalf("a person's kind: %q", k)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE field = 'kind' AND source = 'agent' AND value = 'pc'`); n != 1 {
		t.Fatalf("the agent's pc observation under a person's kind: %d", n)
	}
	// agentSaw (the upgrade job): only a row the agent reported this MAC on counts as found.
	rec("192.168.10.35", observe.Nmap, observe.OS, "Ubuntu 26.04 LTS")
	if found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.10.35")}, mac, "r", true); err != nil || found {
		t.Fatalf("agentSaw on a row with no agent MAC: found=%v err=%v", found, err)
	}
	rec("192.168.10.35", observe.Agent, observe.MAC, mac)
	if found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr("192.168.10.35")}, mac, "r", true); err != nil || !found ||
		e.count(`SELECT count(*) FROM inv_asset WHERE ip = '192.168.10.35' AND approved = 1`) != 1 {
		t.Fatalf("agentSaw on the agent's row: found=%v err=%v", found, err)
	}
	rec("192.168.10.34", observe.Agent, observe.OS, "Ubuntu 26.04 LTS")
	rec("192.168.10.34", observe.Passive, observe.MAC, "52:54:00:00:00:99")
	approve("192.168.10.34", mac)
	if k := kind("192.168.10.34"); k != "unknown" {
		t.Fatalf("the row of another machine was typed: %q", k)
	}
}
