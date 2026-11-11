package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

// WP-31 review, slice R2, L9 (D-179 (6)): response's never-touch list holds the honeypot's decoy addresses and the host's addresses, not only the
// interfaces of the container.
func TestResponseBoxAddrsHoldTheDecoysAndTheHost(t *testing.T) {
	decoy, host := netip.MustParseAddr("192.168.10.250"), netip.MustParseAddr("192.168.10.2")
	got := responseBoxAddrs(
		func() ([]netip.Addr, bool) { return []netip.Addr{host}, true },
		fakeDecoys{decoy},
	)()
	if !slices.Contains(got, decoy) || !slices.Contains(got, host) {
		t.Fatalf("box addresses %v", got)
	}
	cfg, err := responseConfig(newStack(t).d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BoxAddrs == nil {
		t.Fatal("responseConfig leaves BoxAddrs unset")
	}
}

type fakeDecoys struct{ a netip.Addr }

func (f fakeDecoys) DecoyIPs(context.Context) []netip.Addr { return []netip.Addr{f.a} }
