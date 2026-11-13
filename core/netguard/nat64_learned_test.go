package netguard

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
	// a /64 whose byte 6 is 0x7f reads as loopback (127.x) in the /48 layout
	v7f := nat64At("64:ff9b:1:7f00::", nat64Layouts[2].at, [4]byte{8, 8, 8, 8})

	nat64Prefixes = func() []netip.Prefix { return nil }
	if got := Forms(public); !slices.Contains(got, ten) {
		t.Errorf("nothing learned: the /48 reading %s is missing from %v", ten, got)
	}
	learned("64:ff9b:1:a00::/64")
	if got := Forms(public); !slices.Equal(got, []netip.Addr{public, netip.MustParseAddr("8.8.8.8")}) {
		t.Errorf("learned /64: forms %v, want the address and 8.8.8.8 only", got)
	}
	if got := Forms(loop); !slices.Contains(got, netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("learned /64: 127.0.0.1 is missing from %v", got)
	}
	// a /64 starting 0x7f reads as loopback in the /48 layout: loopback is judged in every layout, so it stays refused (known false positive)
	learned("64:ff9b:1:7f00::/64")
	if got := Forms(v7f); !slices.ContainsFunc(got, func(a netip.Addr) bool { return a.Is4() && a.IsLoopback() }) {
		t.Errorf("learned /64 starting 0x7f: loopback reading dropped: %v", got)
	}
	// a learned prefix that does not cover the address changes nothing
	learned("64:ff9b:1:b00::/64")
	if got := Forms(public); !slices.Contains(got, ten) {
		t.Errorf("learned prefix elsewhere: the /48 reading %s is missing from %v", ten, got)
	}
	// a learned /48 reads a /64-laid-out forbidden address as its /48 reading only; the address below carries 127.0.0.1 in the /48 layout
	learned("64:ff9b:1::/48")
	if got := Forms(nat64At("64:ff9b:1::", nat64Layouts[0].at, [4]byte{127, 0, 0, 1})); !slices.Contains(got, netip.MustParseAddr("127.0.0.1")) {
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

// A forged ipv4only.arpa answer teaches a /96 prefix; the address below then reads as 0.0.0.1 in that layout and as the metadata
// address in the /48 layout. DNS must not switch the guard off: it is refused with the forged answer as without it.
func TestForgedNAT64AnswerDoesNotOpenTheGuard(t *testing.T) {
	old := nat64Prefixes
	t.Cleanup(func() { nat64Prefixes = old })
	forged := learnNAT64([]netip.Addr{netip.MustParseAddr("64:ff9b:1:a9fe:a9:fe00:c000:aa")})
	if len(forged) != 1 || forged[0].String() != "64:ff9b:1:a9fe:a9:fe00::/96" {
		t.Fatalf("the forged answer teaches %v", forged)
	}
	nat64Prefixes = func() []netip.Prefix { return forged }
	for _, s := range []string{"64:ff9b:1:a9fe:a9:fe00:0:1", "64:ff9b:1:a9fe:a9:fe00:808:808"} {
		a := netip.MustParseAddr(s)
		if got := Forms(a); !slices.Contains(got, netip.MustParseAddr("169.254.169.254")) {
			t.Errorf("%s: the metadata reading is missing from %v", s, got)
		}
		if !refused(a) {
			t.Errorf("%s is allowed after a forged answer", s)
		}
	}
}

// Several learned prefixes covering one address: the layouts of all of them are judged.
func TestAddrFormsNAT64LocalSeveralLearned(t *testing.T) {
	old := nat64Prefixes
	t.Cleanup(func() { nat64Prefixes = old })
	nat64Prefixes = func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("64:ff9b:1:a00::/64"), netip.MustParsePrefix("64:ff9b:1::/48")}
	}
	a := nat64At("64:ff9b:1:a00::", nat64Layouts[2].at, [4]byte{8, 8, 8, 8})
	got := Forms(a)
	for _, want := range []string{"8.8.8.8", "10.0.8.8"} {
		if !slices.Contains(got, netip.MustParseAddr(want)) {
			t.Errorf("%s is missing from %v", want, got)
		}
	}
}

// One lookup at a time, and nobody waits for it.
func TestNAT64CacheDoesNotBlockReaders(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{})
	c := &nat64Cache{now: time.Now, lookup: func(context.Context) ([]netip.Addr, error) {
		close(started)
		<-release
		return []netip.Addr{netip.MustParseAddr("64:ff9b:1::c000:aa")}, nil
	}}
	done := make(chan struct{})
	go func() { c.get(); close(done) }()
	<-started
	if got := c.get(); len(got) != 0 { // returns at once, with what is known
		t.Errorf("a reader got %v while the lookup ran", got)
	}
	close(release)
	<-done
	if got := c.get(); len(got) != 1 {
		t.Errorf("after the lookup: %v", got)
	}
}
