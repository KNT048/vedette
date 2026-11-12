package feeds

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// No test asks a real resolver for ipv4only.arpa: the learned prefixes are none unless a test sets them.
func init() { nat64Prefixes = func() []netip.Prefix { return nil } }

// nat64At builds a 64:ff9b:1:: address with the four IPv4 octets at the offsets of one layout.
func nat64At(prefix string, at [4]int, v4 [4]byte) netip.Addr {
	b := netip.MustParseAddr(prefix).As16()
	for i, o := range at {
		b[o] = v4[i]
	}
	return netip.AddrFrom16(b)
}

// RFC 7050: the prefix length is learned from the answer for ipv4only.arpa, which holds 192.0.0.170 and 192.0.0.171 in some layout.
func TestLearnNAT64(t *testing.T) {
	cases := []struct {
		name string
		in   []netip.Addr
		want []string
	}{
		{"/96", []netip.Addr{netip.MustParseAddr("64:ff9b:1::c000:aa")}, []string{"64:ff9b:1::/96"}},
		{"/64", []netip.Addr{nat64At("64:ff9b:1:a00::", nat64Layouts[2].at, [4]byte{192, 0, 0, 171})}, []string{"64:ff9b:1:a00::/64"}},
		{"/56", []netip.Addr{nat64At("64:ff9b:1:a00::", nat64Layouts[1].at, [4]byte{192, 0, 0, 170})}, []string{"64:ff9b:1:a00::/56"}},
		{"/48 two answers", []netip.Addr{nat64At("64:ff9b:1::", nat64Layouts[0].at, [4]byte{192, 0, 0, 170}), nat64At("64:ff9b:1::", nat64Layouts[0].at, [4]byte{192, 0, 0, 171})}, []string{"64:ff9b:1::/48"}},
		{"well-known prefix is not local-use", []netip.Addr{netip.MustParseAddr("64:ff9b::c000:aa")}, nil},
		{"outside 64:ff9b:1::/48", []netip.Addr{netip.MustParseAddr("2001:db8::c000:aa")}, nil},
		{"u octet not zero", []netip.Addr{netip.MustParseAddr("64:ff9b:1:0:ff:c000:aa:0")}, nil},
		{"no ipv4only address in it", []netip.Addr{netip.MustParseAddr("64:ff9b:1::808:808")}, nil},
		{"an IPv4 answer", []netip.Addr{netip.MustParseAddr("192.0.0.170")}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, p := range learnNAT64(c.in) {
			got = append(got, p.String())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: learned %v, want %v", c.name, got, c.want)
		}
	}
}

// With the prefix length known only that layout is judged; otherwise every layout, and a forbidden address is never missed.
func TestAddrFormsNAT64LocalLearnedLength(t *testing.T) {
	old := nat64Prefixes
	t.Cleanup(func() { nat64Prefixes = old })
	learned := func(p string) {
		nat64Prefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(p)} }
	}
	// 64:ff9b:1:a00::/64 carrying 8.8.8.8 reads as 10.0.x.x in the /48 layout
	public := nat64At("64:ff9b:1:a00::", nat64Layouts[2].at, [4]byte{8, 8, 8, 8})
	loop := nat64At("64:ff9b:1:a00::", nat64Layouts[2].at, [4]byte{127, 0, 0, 1})
	ten := netip.MustParseAddr("10.0.8.8")
	// a /64 whose first byte is 0x7f reads as 127.x in the /56 layout
	v7f := nat64At("64:ff9b:1:7f00::", nat64Layouts[2].at, [4]byte{8, 8, 8, 8})

	nat64Prefixes = func() []netip.Prefix { return nil }
	if got := addrForms(public); !slices.Contains(got, ten) {
		t.Errorf("nothing learned: the /48 reading %s is missing from %v", ten, got)
	}
	learned("64:ff9b:1:a00::/64")
	if got := addrForms(public); !slices.Equal(got, []netip.Addr{public, netip.MustParseAddr("8.8.8.8")}) {
		t.Errorf("learned /64: forms %v, want the address and 8.8.8.8 only", got)
	}
	if got := addrForms(loop); !slices.Contains(got, netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("learned /64: 127.0.0.1 is missing from %v", got)
	}
	learned("64:ff9b:1:7f00::/64")
	if got := addrForms(v7f); slices.ContainsFunc(got, func(a netip.Addr) bool { return a.Is4() && a.IsLoopback() }) {
		t.Errorf("learned /64 starting 0x7f: still read as loopback: %v", got)
	}
	// a learned prefix that does not cover the address changes nothing
	learned("64:ff9b:1:b00::/64")
	if got := addrForms(public); !slices.Contains(got, ten) {
		t.Errorf("learned prefix elsewhere: the /48 reading %s is missing from %v", ten, got)
	}
	// a learned /48 reads a /64-laid-out forbidden address as its /48 reading only; the address below carries 127.0.0.1 in the /48 layout
	learned("64:ff9b:1::/48")
	if got := addrForms(nat64At("64:ff9b:1::", nat64Layouts[0].at, [4]byte{127, 0, 0, 1})); !slices.Contains(got, netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("learned /48: 127.0.0.1 is missing from %v", got)
	}
}

func TestNAT64CacheAsksRarely(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	var err error
	c := &nat64Cache{now: func() time.Time { return now }, lookup: func(context.Context) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("64:ff9b:1::c000:aa")}, err
	}}
	for i := 0; i < 3; i++ {
		if got := c.get(); len(got) != 1 {
			t.Fatalf("learned %v", got)
		}
	}
	if calls != 1 {
		t.Errorf("%d lookups within the cache time, want 1", calls)
	}
	now = now.Add(7 * time.Hour)
	err = errors.New("timeout")
	c.get()
	now = now.Add(11 * time.Minute)
	c.get()
	if calls != 3 {
		t.Errorf("%d lookups after the cache time and a failed lookup, want 3", calls)
	}
}
