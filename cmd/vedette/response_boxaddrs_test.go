package main

import (
	"context"
	"errors"
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

// D-384: every IPv6 default gateway, each gateway's MAC (from the neighbour table) and the DNS servers in use (here a DHCP lease's: no
// saved configuration) reach the never-touch list. An answer whose IPv6 route or gateway MAC is missing for a moment keeps the last
// ones; a family with a route keeps only its own gateway; a host older than D-384 (no such fields) gives what D-325 gave.
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
	// A new IPv4 gateway replaces the old one (its family has a route); the old MAC does not move to it.
	f.st = api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.20.1"}}
	now = now.Add(time.Minute)
	if have := infraText(); !slices.Equal(have, []string{"gateway 192.168.20.1 ", "gateway fe80::1 00:11:22:33:44:66", "gateway 2001:db8::1 "}) {
		t.Fatalf("a new gateway: %v", have)
	}
	// A host older than D-384 sends none of the new fields; a MAC that is not a 6-byte MAC is not one.
	old := hostInfraOf(api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1", MAC: "00:11:22:33:44:55:66:77"}})
	if len(old) != 1 || old[0].Addr.String() != "192.168.10.1" || old[0].MAC != "" {
		t.Fatalf("an older host's answer: %+v", old)
	}
	var many []string
	for i := range 40 {
		many = append(many, netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String())
	}
	if n := len(hostInfraOf(api.NetState{Resolvers: many})); n != 16 {
		t.Fatalf("%d resolvers taken, want at most 16", n)
	}
}

// D-384 review (M1): a host on the LAN that poisons the box's ARP entry for the gateway must not become never-touch. The first MAC seen is
// pinned; a different one is reported once (per 10 minutes) and stays off the list until it has been the only MAC for 10 minutes over at
// least 3 answers in a row; the pinned MAC stays never-touch all along and after.
func TestGatewayMACIsPinnedAgainstSpoofing(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	now := t0
	f := &fakeNetState{}
	type flip struct{ gw, seen, pinned string }
	var flips []flip
	h := &hostMACs{r: f, now: func() time.Time { return now }, macChanged: func(gw netip.Addr, pinned []string, seen string) {
		flips = append(flips, flip{gw.String(), seen, strings.Join(pinned, ",")})
	}}
	const gwMAC, spoof, third = "00:11:22:33:44:55", "66:66:66:66:66:66", "77:77:77:77:77:77"
	answer := func(at time.Duration, mac string) []string {
		t.Helper()
		now = t0.Add(at)
		f.st = api.NetState{DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.10.1", MAC: mac}}
		got, err := h.Infra(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var macs []string
		for _, x := range got {
			if x.Kind == "gateway" && x.Addr.String() == "192.168.10.1" && x.MAC != "" {
				macs = append(macs, x.MAC)
			}
		}
		return macs
	}
	if got := answer(0, gwMAC); !slices.Equal(got, []string{gwMAC}) {
		t.Fatalf("first answer: %v", got)
	}
	for _, at := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		if got := answer(at, spoof); !slices.Equal(got, []string{gwMAC}) {
			t.Fatalf("at %v the spoofed MAC replaced or joined the pinned one: %v", at, got)
		}
	}
	if len(flips) != 1 || flips[0] != (flip{"192.168.10.1", spoof, gwMAC}) {
		t.Fatalf("flips %+v, want one report of %s", flips, spoof)
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
	if len(flips) != 1 {
		t.Fatalf("a second report within 10 minutes: %+v", flips)
	}
	if got := answer(15*time.Minute, spoof); !slices.Equal(got, []string{gwMAC}) { // 3 answers in a row, but only 9 minutes
		t.Fatalf("adopted before 10 minutes: %v", got)
	}
	if got := answer(16*time.Minute, spoof); !slices.Equal(got, []string{gwMAC, spoof}) { // 4 answers over 10 minutes: adopted, the old one kept
		t.Fatalf("a MAC stable for 10 minutes (a replaced router) was not adopted next to the old one: %v", got)
	}
	answer(17*time.Minute, third)
	if len(flips) != 2 || flips[1] != (flip{"192.168.10.1", third, gwMAC + "," + spoof}) {
		t.Fatalf("flips %+v: a new change 16 minutes after the last report was not reported", flips)
	}
}

// The production report (gatewayMACChanged) is a WARN line and, from its own goroutine, this core_audit row: network.gateway_mac_changed,
// user system. responseConfig wires it.
func TestGatewayMACChangedWritesAnAuditRow(t *testing.T) {
	s := newStack(t)
	if err := auditGatewayMAC(t.Context(), s.d, netip.MustParseAddr("192.168.10.1"), []string{"00:11:22:33:44:55"}, "66:66:66:66:66:66"); err != nil {
		t.Fatal(err)
	}
	var target, detail string
	if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT target, detail FROM core_audit WHERE action = 'network.gateway_mac_changed' AND user = 'system'`).Scan(&target, &detail); err != nil {
		t.Fatal(err)
	}
	if target != "default gateway 192.168.10.1" || !strings.Contains(detail, "66:66:66:66:66:66") || !strings.Contains(detail, "00:11:22:33:44:55") {
		t.Fatalf("row %q %q", target, detail)
	}
	if gatewayMACChanged(s.d) == nil {
		t.Fatal("no production report")
	}
}
