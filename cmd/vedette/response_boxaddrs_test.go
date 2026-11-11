package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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
