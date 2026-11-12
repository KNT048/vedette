package authoidc

import (
	"net/netip"
	"testing"
	"time"
)

// D-299 review r1: one /48 sending each start from a new /64 cannot get past its 100 by filling the limiter's key table (a refused
// start creates no key, and the /48 counts and the box's budget are never dropped), so it cannot use up the box's budget either.
func TestOneSlash48CannotResetItsCountByFloodingKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	l := newLimiter(func() time.Time { return now })
	allowed := 0
	for i := range 25000 {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, byte(i >> 8), byte(i), 15: 1})
		if ok, _, _ := l.allowStart(a); ok {
			allowed++
		}
	}
	if allowed != limit48N {
		t.Fatalf("%d starts allowed from one /48, want %d", allowed, limit48N)
	}
	// callbacks from many /64s fill the table past limitKeys: the /48 count and the budget survive the drop
	for i := range limitKeys + 10 {
		l.allow(limitKey("callback", netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, byte(i >> 8), byte(i), 15: 1})), limitN, limitWindow)
	}
	if ok, _, _ := l.allowStart(netip.MustParseAddr("2001:db8:1:ffff::9")); ok {
		t.Fatal("the /48 count was dropped by a flood of callback keys")
	}
	if got := len(l.hits[budgetKey]); got != limit48N {
		t.Fatalf("budget holds %d starts, want %d", got, limit48N)
	}
}
