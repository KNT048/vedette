package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// D-126: the policy of the vulnerability scanner. One row per rule, each asked as a schedule or a KEV rescan
// (explicit=false) and as a person's pick in "Scan now" (explicit=true). The configured rate is 50, so a quarter
// is 12.
func TestContract_VulnScanPolicy_Rules(t *testing.T) {
	deny := func(reason string) inventory.ScanDecision { return inventory.ScanDecision{Reason: reason} }
	ok := func(rate int) inventory.ScanDecision {
		return inventory.ScanDecision{Allowed: true, Rate: rate, Reason: inventory.ReasonOK}
	}
	const normal, quarter = 50, 12
	ip := netip.MustParseAddr
	// seen records a device the sensors saw, with the given kind ("" leaves the kind unknown).
	seen := func(e *env, addr, kind string) string {
		e.t.Helper()
		e.record(obs(ip(addr), macA, observe.Vendor, "Acme", observe.Passive, 0.5))
		if kind != "" {
			e.record(obs(ip(addr), macA, observe.Kind, kind, observe.Agent, 0.9))
		}
		return e.idByMAC(macA)
	}
	patch := func(e *env, id string, p inventory.Patch) {
		e.t.Helper()
		if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, p); err != nil {
			e.t.Fatal(err)
		}
	}
	regular := func(s string) inventory.Patch { return inventory.Patch{RegularScan: &s} }
	cases := []struct {
		name            string
		unconfirmed     bool
		setup           func(e *env) string
		implicit, picks inventory.ScanDecision // explicit=false, explicit=true
	}{
		{"box", false, func(e *env) string {
			id, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2"})
			if err != nil {
				e.t.Fatal(err)
			}
			return id
		}, deny(inventory.ReasonBox), deny(inventory.ReasonBox)},
		{"no IP", false, func(e *env) string {
			e.record(obsv(macA, observe.Kind, "pc", observe.Agent, 0.9))
			return e.idByMAC(macA)
		}, deny(inventory.ReasonNoIP), deny(inventory.ReasonNoIP)},
		{"scope not confirmed", true, func(e *env) string { return seen(e, "192.168.10.20", "pc") },
			deny(inventory.ReasonScopeNotConfirmed), deny(inventory.ReasonScopeNotConfirmed)},
		{"outside lan_ranges", false, func(e *env) string { return seen(e, "10.9.9.9", "pc") },
			deny(inventory.ReasonOutOfScope), deny(inventory.ReasonOutOfScope)},
		{"in the exclusions", false, func(e *env) string { return seen(e, "192.168.10.99", "pc") },
			deny(inventory.ReasonOutOfScope), deny(inventory.ReasonOutOfScope)},
		{"regular_scan=never, ordinary", false, func(e *env) string {
			id := seen(e, "192.168.10.20", "pc")
			patch(e, id, regular("never"))
			return id
		}, deny(inventory.ReasonRegularScanNever), deny(inventory.ReasonRegularScanNever)},
		{"regular_scan=never, fragile", false, func(e *env) string {
			id := seen(e, "192.168.10.20", "printer")
			patch(e, id, regular("never"))
			return id
		}, deny(inventory.ReasonRegularScanNever), deny(inventory.ReasonRegularScanNever)},
		{"fragile by type", false, func(e *env) string { return seen(e, "192.168.10.20", "printer") },
			deny(inventory.ReasonFragilePassiveOnly), ok(quarter)},
		{"fragile by flag", false, func(e *env) string {
			id := seen(e, "192.168.10.20", "pc")
			yes := true
			patch(e, id, inventory.Patch{Fragile: &yes})
			return id
		}, deny(inventory.ReasonFragilePassiveOnly), ok(quarter)},
		{"unclassified", false, func(e *env) string { return seen(e, "192.168.10.20", "") },
			deny(inventory.ReasonUnclassifiedPassiveOnly), ok(quarter)},
		{"declared by hand, ordinary", false, func(e *env) string {
			id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.30"})
			pc := "pc"
			patch(e, id, inventory.Patch{Kind: &pc})
			return id
		}, deny(inventory.ReasonDeclaredByHand), ok(normal)},
		{"declared by hand, fragile", false, func(e *env) string {
			id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.30"})
			yes := true
			patch(e, id, inventory.Patch{Fragile: &yes})
			return id
		}, deny(inventory.ReasonDeclaredByHand), ok(quarter)},
		{"declared by hand, regular_scan=allow", false, func(e *env) string {
			id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.30"})
			patch(e, id, regular("allow"))
			return id
		}, deny(inventory.ReasonDeclaredByHand), ok(normal)},
		{"fragile, regular_scan=allow", false, func(e *env) string {
			id := seen(e, "192.168.10.20", "printer")
			patch(e, id, regular("allow"))
			return id
		}, ok(normal), ok(normal)},
		{"unclassified, regular_scan=allow", false, func(e *env) string {
			id := seen(e, "192.168.10.20", "")
			patch(e, id, regular("allow"))
			return id
		}, ok(normal), ok(normal)},
		{"fragile, kind in regular_scan_kinds", false, func(e *env) string { return seen(e, "192.168.10.20", "nas") },
			ok(normal), ok(normal)},
		{"fragile, kind not in regular_scan_kinds", false, func(e *env) string { return seen(e, "192.168.10.20", "camera") },
			deny(inventory.ReasonFragilePassiveOnly), ok(quarter)},
		{"ordinary", false, func(e *env) string { return seen(e, "192.168.10.20", "pc") },
			ok(normal), ok(normal)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			in := okSettings("192.168.10.0/24")
			in.Active.Enabled, in.ScopeConfirmed = !c.unconfirmed, !c.unconfirmed
			in.Active.Exclusions = []string{"192.168.10.99"}
			in.RegularScanKinds = []string{"nas"}
			if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
				t.Fatal(err)
			}
			id := c.setup(e)
			for explicit, want := range map[bool]inventory.ScanDecision{false: c.implicit, true: c.picks} {
				got, err := e.svc.VulnScanPolicy(e.ctx(), id, explicit)
				got.Careful, got.IP = false, netip.Addr{} // asserted in TestContract_VulnScanPolicy_CarefulAndIP
				if err != nil || got != want {
					t.Errorf("explicit=%v: %+v, %v; want %+v", explicit, got, err, want)
				}
			}
			if d := e.detail(id); d.Asset.FirstScanAt != nil {
				t.Errorf("first_scan_at = %v: VulnScanPolicy must not mark the gentle scan", *d.Asset.FirstScanAt)
			}
		})
	}
}

// D-126: the sensor-active switch is not the vulnerability scanner's; scope and per-device rules still apply.
func TestContract_VulnScanPolicy_ScanningOffDoesNotBlock(t *testing.T) {
	e := newEnv(t)
	e.confirmScope("192.168.10.0/24")
	e.record(obs(netip.MustParseAddr("192.168.10.20"), macA, observe.Kind, "pc", observe.Agent, 0.9))
	id := e.idByMAC(macA)
	// switch the probe scan off while the range stays confirmed
	in := okSettings("192.168.10.0/24")
	in.Active.Enabled, in.ScopeConfirmed = false, true
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", in); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.svc.Settings(e.ctx()); st.Active.Enabled {
		t.Fatal("the test needs active scanning off")
	}
	if d, _ := e.svc.ScanPolicy(e.ctx(), id); d.Allowed || d.Reason != inventory.ReasonScanningOff {
		t.Fatalf("ScanPolicy with the switch off = %+v, the existing policy must stay unchanged", d)
	}
	for _, explicit := range []bool{false, true} {
		d, err := e.svc.VulnScanPolicy(e.ctx(), id, explicit)
		if err != nil || !d.Allowed || d.Reason != inventory.ReasonOK || d.Rate != 50 {
			t.Errorf("explicit=%v with scanning off = %+v, %v", explicit, d, err)
		}
	}
}

func TestContract_VulnScanPolicy_UnknownDevice(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.VulnScanPolicy(e.ctx(), "a-nope", true); err == nil {
		t.Fatal("no error for an unknown device")
	}
}
