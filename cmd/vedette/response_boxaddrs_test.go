package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// WP-31 review, slice R2, L9 (D-179 (6), (8)): response's never-touch list holds the honeypot's decoy addresses and the host's addresses, not only the
// interfaces of the container, and an unknown set is an error (response then refuses), never a smaller set.
func TestResponseBoxAddrsHoldTheDecoysAndTheHost(t *testing.T) {
	t.Parallel()
	decoy, host := netip.MustParseAddr("192.168.10.250"), netip.MustParseAddr("192.168.10.2")
	got, err := responseBoxAddrs(
		func() ([]netip.Addr, bool) { return []netip.Addr{host}, true },
		fakeDecoys{a: decoy},
	)()
	if err != nil || !slices.Contains(got, decoy) || !slices.Contains(got, host) {
		t.Fatalf("box addresses %v, %v", got, err)
	}
	cfg, err := responseConfig(newStack(t).d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BoxAddrs == nil || cfg.BoxMACs == nil {
		t.Fatal("responseConfig leaves BoxAddrs or BoxMACs unset")
	}
}

func TestResponseBoxAddrsFailClosedWhenASourceIsUnknown(t *testing.T) {
	known := func() ([]netip.Addr, bool) { return nil, true }
	if _, err := responseBoxAddrs(func() ([]netip.Addr, bool) { return nil, false }, fakeDecoys{})(); err == nil {
		t.Error("a host that never answered was taken for an empty set")
	}
	if _, err := responseBoxAddrs(known, fakeDecoys{err: errors.New("db closed")})(); err == nil {
		t.Error("an unreadable honeypot record was taken for no decoys")
	}
}

type fakeDecoys struct {
	a   netip.Addr
	err error
}

func (f fakeDecoys) DecoyIPsRead(context.Context) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	if !f.a.IsValid() {
		return nil, nil
	}
	return []netip.Addr{f.a}, nil
}

type fakeNetState struct {
	st  api.NetState
	err error
	n   int
}

func (f *fakeNetState) StateNet(context.Context) (api.NetState, error) {
	f.n++
	return f.st, f.err
}

// D-179 (8): the MACs of the decoys (macvlan links) and of the cards come from state/net; the last good answer is kept, and before the first the
// set is unknown.
func TestResponseBoxMACsHoldTheDecoysAndTheCards(t *testing.T) {
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	f := &fakeNetState{st: api.NetState{Interfaces: []api.NetInterface{{Name: "eth0", MAC: "AA:BB:CC:00:00:01"}}, Decoys: []api.NetDecoy{{IP: "192.168.10.250", MAC: "02:11:22:33:44:55"}}}}
	h := &hostMACs{r: f, now: func() time.Time { return now }}
	got, err := responseBoxMACs(h)()
	if err != nil || !slices.Contains(got, "02:11:22:33:44:55") || !slices.Contains(got, "aa:bb:cc:00:00:01") {
		t.Fatalf("MACs %v, %v", got, err)
	}
	f.err = errors.New("host down")
	now = now.Add(time.Minute) // stale: a refresh is tried and fails
	if got, err := responseBoxMACs(h)(); err != nil || !slices.Contains(got, "02:11:22:33:44:55") {
		t.Fatalf("after a failed refresh: %v, %v", got, err)
	}
	if _, err := responseBoxMACs(&hostMACs{r: f, now: func() time.Time { return now }})(); err == nil {
		t.Error("a host that never answered was taken for an empty set")
	}
	if got, err := responseBoxMACs(&hostMACs{})(); err != nil || got != nil {
		t.Errorf("no host: %v, %v", got, err)
	}
}

// D-325: the gateway of the kernel's default route and the gateway and DNS servers saved for the management card reach response's never-touch
// list; unknown before the first answer, kept after a failed refresh, empty without a host. Loopback and unspecified values are not addresses.
func TestResponseHostInfraHoldsTheGatewayAndDNS(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	f := &fakeNetState{st: api.NetState{
		DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1"},
		Config:       api.NetConfig{Mgmt: &api.NetMgmt{Iface: "eth0", Mode: "static", Gateway: "192.168.10.254", DNS: []string{"192.168.10.53", "127.0.0.53", "0.0.0.0", "bad"}}},
	}}
	h := &hostMACs{r: f, now: func() time.Time { return now }}
	got, err := h.Infra(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gateway 192.168.10.1", "gateway 192.168.10.254", "dns 192.168.10.53"}
	var have []string
	for _, x := range got {
		have = append(have, x.Kind+" "+x.Addr.String())
	}
	if !slices.Equal(have, want) {
		t.Fatalf("infra %v, want %v", have, want)
	}
	f.st = api.NetState{} // a moment with no default route (a lease renewing): the last gateways stay
	now = now.Add(time.Minute)
	if got, err := h.Infra(t.Context()); err != nil || len(got) != 2 || got[0].Kind != "gateway" {
		t.Fatalf("an answer without a default route: %v, %v", got, err)
	}
	f.err = errors.New("host down")
	now = now.Add(time.Minute)
	if got, err := h.Infra(t.Context()); err != nil || len(got) != 2 {
		t.Fatalf("after a failed refresh: %v, %v", got, err)
	}
	if _, err := (&hostMACs{r: f, now: func() time.Time { return now }}).Infra(t.Context()); err == nil {
		t.Error("a host that never answered was taken for no gateway")
	}
	if got, err := (&hostMACs{}).Infra(t.Context()); err != nil || got != nil {
		t.Errorf("no host: %v, %v", got, err)
	}
	cfg, err := responseConfig(newStack(t).d)
	if err != nil || cfg.HostInfra == nil {
		t.Fatalf("responseConfig leaves HostInfra unset: %v", err)
	}
}

// D-450: every IPv6 default gateway, each gateway's MAC (from the neighbour table) and the DNS servers in use (here a DHCP lease's: no
// saved configuration) reach the never-touch list. An answer whose IPv6 route or gateway MAC is missing for a moment keeps the last
// ones; a family with a route keeps only its own gateway; a host older than D-450 (no such fields) gives what D-325 gave.
func TestResponseHostInfraHoldsTheIPv6GatewayTheGatewayMACsAndTheLeaseDNS(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	full := api.NetState{
		DefaultRoute:   &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1", MAC: "00:11:22:33:44:55"},
		DefaultRoutes6: []api.NetRoute{{Iface: "eth0", Gateway: "fe80::1", MAC: "00:11:22:33:44:66"}, {Iface: "wg0", Gateway: "2001:db8::1"}},
		Resolvers:      []string{"192.168.10.53", "2001:db8::53", "127.0.0.53", "bad"},
	}
	f := &fakeNetState{st: full}
	h := &hostMACs{r: f, now: func() time.Time { return now }}
	infraText := func() []string {
		t.Helper()
		got, err := h.Infra(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var have []string
		for _, x := range got {
			have = append(have, x.Kind+" "+x.Addr.String()+" "+x.MAC)
		}
		return have
	}
	want := []string{"gateway 192.168.10.1 00:11:22:33:44:55", "gateway fe80::1 00:11:22:33:44:66", "gateway 2001:db8::1 ", "dns 192.168.10.53 ", "dns 2001:db8::53 "}
	if have := infraText(); !slices.Equal(have, want) {
		t.Fatalf("infra %v, want %v", have, want)
	}
	// The neighbour entries aged out and the router advertisement is late: the MAC and the IPv6 gateway stay.
	f.st = api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1"}, Resolvers: full.Resolvers}
	now = now.Add(time.Minute)
	if have := infraText(); !slices.Equal(have, []string{"gateway 192.168.10.1 00:11:22:33:44:55", "dns 192.168.10.53 ", "dns 2001:db8::53 ", "gateway fe80::1 00:11:22:33:44:66", "gateway 2001:db8::1 "}) {
		t.Fatalf("an answer with gaps: %v", have)
	}
	// A new IPv4 gateway is a candidate (TestNewGatewaysAndResolversAreCandidates): the old one, with its MAC, stays meanwhile.
	f.st = api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.20.1"}}
	now = now.Add(time.Minute)
	if have := infraText(); !slices.Equal(have, []string{"gateway 192.168.10.1 00:11:22:33:44:55", "gateway fe80::1 00:11:22:33:44:66", "gateway 2001:db8::1 "}) {
		t.Fatalf("a new gateway: %v", have)
	}
	// A host older than D-450 sends none of the new fields; a MAC that is not a 6-byte MAC is not one.
	old, _ := hostInfraOf(api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1", MAC: "00:11:22:33:44:55:66:77"}})
	if len(old) != 1 || old[0].Addr.String() != "192.168.10.1" || old[0].MAC != "" {
		t.Fatalf("an older host's answer: %+v", old)
	}
	var many []string
	for i := range 40 {
		many = append(many, netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String())
	}
	if dyn, _ := hostInfraOf(api.NetState{Resolvers: many}); len(dyn) != 16 {
		t.Fatalf("%d resolvers taken, want at most 16", len(dyn))
	}
	// The administrator's saved gateway and DNS are apart from what the network steers.
	dyn, saved := hostInfraOf(api.NetState{DefaultRoute: &api.NetRoute{Gateway: "192.168.10.1"}, Config: api.NetConfig{Mgmt: &api.NetMgmt{Gateway: "192.168.10.254", DNS: []string{"192.168.10.5"}}}})
	if len(dyn) != 1 || len(saved) != 2 || saved[0].Addr.String() != "192.168.10.254" {
		t.Fatalf("dynamic %+v saved %+v", dyn, saved)
	}
}

// infraReports records hostMACs.report calls as "action address".
type infraReports struct{ l []string }

func (r *infraReports) add(action string, a netip.Addr, _ string) {
	r.l = append(r.l, action+" "+a.String())
}

func (r *infraReports) of(prefix string) []string {
	var out []string
	for _, x := range r.l {
		if strings.HasPrefix(x, prefix) {
			out = append(out, x)
		}
	}
	return out
}

// clocked is a hostMACs on an injected clock whose answers are set by the test; at sets the time of the next answer and returns the
// trusted infra as "kind address mac" lines.
type clocked struct {
	t   *testing.T
	t0  time.Time
	now time.Time
	f   *fakeNetState
	h   *hostMACs
	r   *infraReports
}

func newClocked(t *testing.T) *clocked {
	c := &clocked{t: t, t0: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC), f: &fakeNetState{}, r: &infraReports{}}
	c.now = c.t0
	c.h = &hostMACs{r: c.f, now: func() time.Time { return c.now }, report: c.r.add}
	return c
}

func (c *clocked) at(d time.Duration, st api.NetState) []string {
	c.t.Helper()
	c.now, c.f.st = c.t0.Add(d), st
	got, err := c.h.Infra(c.t.Context())
	if err != nil {
		c.t.Fatal(err)
	}
	var have []string
	for _, x := range got {
		have = append(have, x.Kind+" "+x.Addr.String()+" "+x.MAC)
	}
	return have
}

// gwMACs is the MACs of gw in an at answer.
func gwMACs(have []string, gw string) []string {
	var out []string
	for _, x := range have {
		if f := strings.Fields(x); len(f) == 3 && f[0] == "gateway" && f[1] == gw {
			out = append(out, f[2])
		}
	}
	return out
}

func gwState(gw, mac string) api.NetState {
	return api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: gw, MAC: mac}}
}

// D-450 review (M1): a host on the LAN that poisons the box's ARP entry for the gateway must not become never-touch. The first MAC seen is
// pinned; a different one is reported once (per 10 minutes) and stays off the list until it has been the only MAC for 10 minutes over at
// least 3 answers in a row; the pinned MAC stays never-touch all along and after.
func TestGatewayMACIsPinnedAgainstSpoofing(t *testing.T) {
	c := newClocked(t)
	const gw, gwMAC, spoof, third = "192.168.10.1", "00:11:22:33:44:55", "66:66:66:66:66:66", "77:77:77:77:77:77"
	answer := func(at time.Duration, mac string) []string { t.Helper(); return gwMACs(c.at(at, gwState(gw, mac)), gw) }
	if got := answer(0, gwMAC); !slices.Equal(got, []string{gwMAC}) {
		t.Fatalf("first answer: %v", got)
	}
	for _, at := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		if got := answer(at, spoof); !slices.Equal(got, []string{gwMAC}) {
			t.Fatalf("at %v the spoofed MAC replaced or joined the pinned one: %v", at, got)
		}
	}
	if got := c.r.of("network.gateway_mac"); !slices.Equal(got, []string{"network.gateway_mac_changed " + gw}) {
		t.Fatalf("reports %v, want one change", got)
	}
	if got := answer(4*time.Minute, ""); !slices.Equal(got, []string{gwMAC}) { // a missing neighbour entry keeps the pinned MAC
		t.Fatalf("an answer with no MAC: %v", got)
	}
	answer(5*time.Minute, gwMAC) // the real gateway answers again: the count starts over
	for _, at := range []time.Duration{6 * time.Minute, 12 * time.Minute} {
		if got := answer(at, spoof); !slices.Equal(got, []string{gwMAC}) {
			t.Fatalf("at %v: %v", at, got)
		}
	}
	if n := len(c.r.of("network.gateway_mac")); n != 1 {
		t.Fatalf("a second report within 10 minutes: %v", c.r.l)
	}
	if got := answer(15*time.Minute, spoof); !slices.Equal(got, []string{gwMAC}) { // 3 answers in a row, but only 9 minutes
		t.Fatalf("adopted before 10 minutes: %v", got)
	}
	if got := answer(16*time.Minute, spoof); !slices.Equal(got, []string{gwMAC, spoof}) { // 4 answers over 10 minutes: adopted, the old one kept
		t.Fatalf("a MAC stable for 10 minutes (a replaced router) was not adopted next to the old one: %v", got)
	}
	answer(17*time.Minute, third)
	want := []string{"network.gateway_mac_changed " + gw, "network.gateway_mac_adopted " + gw, "network.gateway_mac_changed " + gw}
	if got := c.r.of("network.gateway_mac"); !slices.Equal(got, want) {
		t.Fatalf("reports %v, want %v", got, want)
	}
}

// Review round 2 (M2): an attacker rotating MACs, each held 10 minutes, never pushes the first pinned MAC (the real router's) out, and
// every adoption is reported.
func TestGatewayMACRotationNeverEvictsTheFirstPin(t *testing.T) {
	c := newClocked(t)
	const gw, gwMAC = "192.168.10.1", "00:11:22:33:44:55"
	c.at(0, gwState(gw, gwMAC))
	base := time.Minute
	for i := range 6 {
		mac := fmt.Sprintf("66:66:66:66:66:%02x", i)
		var got []string
		for _, d := range []time.Duration{0, 5 * time.Minute, 10 * time.Minute} {
			got = gwMACs(c.at(base+d, gwState(gw, mac)), gw)
		}
		base += 11 * time.Minute
		if !slices.Contains(got, gwMAC) || !slices.Contains(got, mac) || len(got) > gatewayMACKeep {
			t.Fatalf("after adopting %s: never-touch MACs %v (the first pin must stay, at most %d)", mac, got, gatewayMACKeep)
		}
	}
	if n := len(c.r.of("network.gateway_mac_adopted")); n != 6 {
		t.Fatalf("%d adoption reports, want 6: %v", n, c.r.l)
	}
}

// Review round 2 (M1): only the gateways and resolvers of core's first answer are trusted at once. One seen later (a rogue router
// advertisement, a rogue DHCP server) is reported and seeded neither by IP nor by MAC until it has been in 3 answers in a row spanning
// 10 minutes; an answer without it starts over. A new IPv4 gateway from DHCP is a candidate too, and the old one stays meanwhile.
func TestNewGatewaysAndResolversAreCandidates(t *testing.T) {
	c := newClocked(t)
	const gw, gwMAC, rogue, rogueMAC, dns, rogueDNS = "192.168.10.1", "00:11:22:33:44:55", "2001:db8::bad", "66:66:66:66:66:66", "192.168.10.53", "203.0.113.53"
	trusted := api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: gw, MAC: gwMAC}, Resolvers: []string{dns}}
	attacked := trusted
	attacked.DefaultRoutes6 = []api.NetRoute{{Iface: "eth0", Gateway: rogue, MAC: rogueMAC}}
	attacked.Resolvers = []string{dns, rogueDNS}
	if have := c.at(0, trusted); !slices.Equal(have, []string{"gateway " + gw + " " + gwMAC, "dns " + dns + " "}) {
		t.Fatalf("first answer: %v", have)
	}
	seeded := func(have []string) bool {
		return slices.ContainsFunc(have, func(x string) bool {
			return strings.Contains(x, rogue) || strings.Contains(x, rogueMAC) || strings.Contains(x, rogueDNS)
		})
	}
	for _, d := range []time.Duration{1, 3, 6} {
		if have := c.at(d*time.Minute, attacked); seeded(have) {
			t.Fatalf("at %d min a new gateway or resolver was seeded at once: %v", d, have)
		}
	}
	if got := c.r.of("network."); !slices.Equal(got, []string{"network.gateway_new " + rogue, "network.dns_new " + rogueDNS}) {
		t.Fatalf("reports %v", got)
	}
	c.at(8*time.Minute, trusted) // gone for one answer: the count starts over
	for _, d := range []time.Duration{9, 14} {
		if have := c.at(d*time.Minute, attacked); seeded(have) {
			t.Fatalf("at %d min: %v", d, have)
		}
	}
	if n := len(c.r.of("network.gateway_new")); n != 1 {
		t.Fatalf("reported again within 10 minutes: %v", c.r.l)
	}
	have := c.at(19*time.Minute, attacked) // 3 answers in a row over 10 minutes
	if !slices.Contains(have, "gateway "+rogue+" "+rogueMAC) || !slices.Contains(have, "dns "+rogueDNS+" ") {
		t.Fatalf("a gateway and resolver present 10 minutes were not adopted: %v", have)
	}
	if got := c.r.of("network."); !slices.Equal(got[2:], []string{"network.gateway_adopted " + rogue, "network.dns_adopted " + rogueDNS}) {
		t.Fatalf("reports %v", got)
	}
	// DHCP moves the IPv4 gateway: the new one waits, the old one (with its MAC) stays never-touch.
	have = c.at(20*time.Minute, gwState("192.168.20.1", "00:11:22:33:44:77"))
	if !slices.Contains(have, "gateway "+gw+" "+gwMAC) || slices.ContainsFunc(have, func(x string) bool { return strings.Contains(x, "192.168.20.1") }) {
		t.Fatalf("a new DHCP gateway: %v", have)
	}
}

// The production report (infraReport) is a WARN line and, from its own goroutine, this core_audit row (user system). responseConfig wires it.
func TestInfraReportWritesAnAuditRow(t *testing.T) {
	s := newStack(t)
	if err := auditInfra(t.Context(), s.d, "network.gateway_mac_changed", netip.MustParseAddr("192.168.10.1"), "now 66:66:66:66:66:66; never-touch stays 00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	var target, detail string
	if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT target, detail FROM core_audit WHERE action = 'network.gateway_mac_changed' AND user = 'system'`).Scan(&target, &detail); err != nil {
		t.Fatal(err)
	}
	if target != "192.168.10.1" || !strings.Contains(detail, "66:66:66:66:66:66") {
		t.Fatalf("row %q %q", target, detail)
	}
	if infraReport(s.d) == nil {
		t.Fatal("no production report")
	}
}
