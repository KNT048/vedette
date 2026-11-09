package sensoractive

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

// The sweep cursor with random ranges, exclusions and a cursor left by an earlier pass over
// different ranges (ranges/exclusions changed between windows). Whatever the walker plus the in-memory scope yield
// (what nextBatch puts in a batch) must be inside the CURRENT ranges and outside the CURRENT exclusions by an
// independent oracle (the inventory rule written out), strictly ascending, after the cursor, never repeated, and
// complete: every in-scope host address after the cursor, except the network and broadcast address of a merged
// range wider than /31.
func TestSweepCursorNeverLeavesTheScope(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test data
	bases := []string{"10.0.0.0", "10.0.1.0", "192.168.10.0", "172.16.0.0"}
	pick := func(minBits int) string {
		b := netip.MustParseAddr(bases[r.IntN(len(bases))]).As4()
		b[3] = byte(r.IntN(256)) //nolint:gosec // IntN(256) fits a byte
		if r.IntN(4) == 0 {
			b[2] ^= 1
		}
		bits := minBits + r.IntN(33-minBits)
		return fmt.Sprintf("%s/%d", netip.AddrFrom4(b), bits) // host bits on purpose: the inventory accepts them in exclusions
	}
	oracle := func(ranges, excl []string, a netip.Addr) bool {
		in := false
		for _, s := range ranges {
			if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
				in = true
			}
		}
		for _, s := range excl {
			if x, err := netip.ParseAddr(s); err == nil && x == a {
				return false
			}
			if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
				return false
			}
		}
		return in
	}
	for iter := range 3000 {
		var ranges, excl []string
		for range 1 + r.IntN(3) {
			p := netip.MustParsePrefix(pick(23)).Masked() // the inventory stores ranges masked (host_bits)
			ranges = append(ranges, p.String())
		}
		for range r.IntN(4) {
			if r.IntN(3) == 0 {
				excl = append(excl, netip.MustParsePrefix(pick(28)).Addr().String()) // a single host
			} else {
				excl = append(excl, pick(24))
			}
		}
		var after netip.Addr
		if r.IntN(3) > 0 {
			after = netip.MustParsePrefix(pick(32)).Addr()
		}
		sc := newScope(Settings{LANRanges: ranges, Exclusions: excl})
		w := newWalker(prefixes(ranges), after)
		got := map[netip.Addr]bool{}
		var last netip.Addr
		for a, ok := w.next(); ok; a, ok = w.next() {
			if !sc.contains(a) {
				continue // what nextBatch drops
			}
			if !oracle(ranges, excl, a) {
				t.Fatalf("iter %d: %s yielded but out of scope (ranges %v, excl %v)", iter, a, ranges, excl)
			}
			if after.IsValid() && !after.Less(a) {
				t.Fatalf("iter %d: %s yielded but not after the cursor %s", iter, a, after)
			}
			if last.IsValid() && !last.Less(a) {
				t.Fatalf("iter %d: %s after %s: not ascending", iter, a, last)
			}
			if got[a] {
				t.Fatalf("iter %d: %s yielded twice", iter, a)
			}
			got[a], last = true, a
		}
		// completeness, by brute force over the merged ranges
		for _, p := range mergePrefixes(prefixes(ranges)) {
			for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
				edge := p.Bits() <= 30 && (a == p.Addr() || !p.Contains(a.Next()))
				want := oracle(ranges, excl, a) && !edge && (!after.IsValid() || after.Less(a))
				if want != got[a] {
					t.Fatalf("iter %d: %s yielded=%v want %v (ranges %v, excl %v, after %v)", iter, a, got[a], want, ranges, excl, after)
				}
			}
		}
	}
}
