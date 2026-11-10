package inventory_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Careful is the safe side: true for a fragile device and for one whose kind is still unknown, false otherwise;
// IP is the address the decision was made for, zero when denied (POST-3c).
func TestContract_VulnScanPolicy_CarefulAndIP(t *testing.T) {
	ip := netip.MustParseAddr("192.168.10.20")
	for _, c := range []struct {
		name, kind string
		fragile    bool
		careful    bool
	}{
		{"ordinary", "pc", false, false},
		{"fragile by type", "printer", false, true},
		{"fragile by flag", "pc", true, true},
		{"unknown kind", "", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.confirmScope("192.168.10.0/24")
			e.record(obs(ip, macA, observe.Vendor, "Acme", observe.Passive, 0.5))
			if c.kind != "" {
				e.record(obs(ip, macA, observe.Kind, c.kind, observe.Agent, 0.9))
			}
			id := e.idByMAC(macA)
			if c.fragile {
				if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Fragile: &c.fragile}); err != nil {
					t.Fatal(err)
				}
			}
			d, err := e.svc.VulnScanPolicy(e.ctx(), id, true)
			if err != nil || !d.Allowed {
				t.Fatalf("%+v, %v", d, err)
			}
			if d.Careful != c.careful || d.IP != ip {
				t.Errorf("Careful=%v IP=%v; want %v, %v", d.Careful, d.IP, c.careful, ip)
			}
			// denied: out of scope for the same device after the range changes
			if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings("10.1.0.0/24")); err != nil {
				t.Fatal(err)
			}
			d, err = e.svc.VulnScanPolicy(e.ctx(), id, true)
			if err != nil || d.Allowed || d.IP.IsValid() || d.Careful {
				t.Errorf("denied decision = %+v, %v; want no IP and not careful", d, err)
			}
		})
	}
}

// The batch read answers exactly what the per-device read answers, for a mixed set.
func TestContract_VulnScanPolicies_EqualsPerDevice(t *testing.T) {
	e := newEnv(t)
	in := okSettings("192.168.10.0/24")
	in.Active.Exclusions = []string{"192.168.10.99"}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	mk := func(i int, addr, kind string) string {
		mac := fmt.Sprintf("aa:bb:cc:00:00:%02x", i)
		e.record(obs(netip.MustParseAddr(addr), mac, observe.Vendor, "Acme", observe.Passive, 0.5))
		if kind != "" {
			e.record(obs(netip.MustParseAddr(addr), mac, observe.Kind, kind, observe.Agent, 0.9))
		}
		return e.idByMAC(mac)
	}
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2"})
	if err != nil {
		t.Fatal(err)
	}
	noIP := func() string {
		e.record(obsv("aa:bb:cc:00:00:63", observe.Kind, "pc", observe.Agent, 0.9))
		return e.idByMAC("aa:bb:cc:00:00:63")
	}()
	ids := []string{box, noIP, mk(1, "10.9.9.9", "pc"), mk(2, "192.168.10.21", "printer"), mk(3, "192.168.10.22", "pc"), mk(4, "192.168.10.23", "")}
	for _, explicit := range []bool{false, true} {
		got, err := e.svc.VulnScanPolicies(e.ctx(), append(slicesClone(ids), "a-gone"), explicit)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got["a-gone"]; ok || len(got) != len(ids) {
			t.Errorf("explicit=%v: %d entries, gone id present=%v; a missing id must be absent, not fail the batch", explicit, len(got), ok)
		}
		for _, id := range ids {
			want, err := e.svc.VulnScanPolicy(e.ctx(), id, explicit)
			if err != nil || got[id] != want {
				t.Errorf("explicit=%v %s: batch %+v, single %+v (%v)", explicit, id, got[id], want, err)
			}
		}
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

func TestContract_VulnScanPolicies_Cap(t *testing.T) {
	e := newEnv(t)
	ids := make([]string, inventory.MaxPolicyBatch+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("a-%d", i)
	}
	if _, err := e.svc.VulnScanPolicies(e.ctx(), ids, false); err == nil {
		t.Fatal("no error above the cap")
	}
	if got, err := e.svc.VulnScanPolicies(e.ctx(), ids[:inventory.MaxPolicyBatch], false); err != nil || len(got) != 0 {
		t.Fatalf("at the cap: %v, %v", got, err)
	}
	if got, err := e.svc.VulnScanPolicies(e.ctx(), nil, false); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
}
