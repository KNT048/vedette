package sensoractive

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// allowed applies INV-2: no work when scanning is off, the scope is not confirmed, or there is no range.
func (st Settings) allowed() error {
	switch {
	case !st.Enabled:
		return ErrScanningOff
	case !st.ScopeConfirmed:
		return ErrScopeNotConfirmed
	case len(st.LANRanges) == 0:
		return ErrNoRanges
	}
	return nil
}

// minutes parses HH:MM.
func minutes(s string) (int, bool) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || len(h) != 2 || len(m) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*60 + mm, true
}

// window returns the window that contains t (INV-3): its start and its end, in t's own location (the organization's
// time zone; the caller passes t in that zone). A window that crosses midnight belongs to the day it
// starts on: "Friday 23:00 to 05:00" runs until Saturday 05:00. ok is false outside every window.
func (st Settings) window(t time.Time) (start, end time.Time, ok bool) {
	from, ok1 := minutes(st.From)
	to, ok2 := minutes(st.To)
	if !ok1 || !ok2 || from == to {
		return time.Time{}, time.Time{}, false
	}
	for back := 0; back <= 1; back++ { // a window starting today, or one that started yesterday and crosses midnight
		d := t.AddDate(0, 0, -back)
		wd := int(d.Weekday())
		if wd == 0 {
			wd = 7
		}
		if !slices.Contains(st.Days, wd) {
			continue
		}
		start = time.Date(d.Year(), d.Month(), d.Day(), from/60, from%60, 0, 0, t.Location())
		endDay := d
		if to < from {
			endDay = d.AddDate(0, 0, 1)
		}
		end = time.Date(endDay.Year(), endDay.Month(), endDay.Day(), to/60, to%60, 0, 0, t.Location())
		if !t.Before(start) && t.Before(end) {
			return start, end, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// windowLength is how long one window lasts (To after From on the same day, or across midnight); 0 when the
// times are not valid.
func (st Settings) windowLength() time.Duration {
	from, ok1 := minutes(st.From)
	to, ok2 := minutes(st.To)
	if !ok1 || !ok2 || from == to {
		return 0
	}
	if to < from {
		to += 24 * 60
	}
	return time.Duration(to-from) * time.Minute
}

// prefixes parses the ranges, skipping anything that is not an IPv4 CIDR (the inventory validates them
// already; this is the second look at a value that came from storage).
func prefixes(ranges []string) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range ranges {
		if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// exclusionPrefixes parses exclusions, each an IPv4 address or an IPv4 CIDR; anything else is skipped.
func exclusionPrefixes(xs []string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range xs {
		if p, err := netip.ParsePrefix(x); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(x); err == nil && a.Is4() {
			out = append(out, netip.PrefixFrom(a, 32))
		}
	}
	return out
}

// mergePrefixes sorts the prefixes by address and drops those another one contains (CIDR blocks are either
// nested or disjoint), so what is left is disjoint and ascending.
func mergePrefixes(ps []netip.Prefix) []netip.Prefix {
	s := slices.Clone(ps)
	slices.SortFunc(s, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var out []netip.Prefix
	for _, p := range s {
		if n := len(out); n > 0 && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func prefixSize(p netip.Prefix) int { return 1 << (32 - p.Bits()) }

// scope is the scan scope of one settings snapshot, parsed once so that testing an address costs no storage
// read (D-84 (6), M5). It follows the inventory's rule (SYS-7): inside a range, outside every exclusion.
type scope struct{ ranges, excl []netip.Prefix }

func newScope(st Settings) scope {
	return scope{ranges: mergePrefixes(prefixes(st.LANRanges)), excl: mergePrefixes(exclusionPrefixes(st.Exclusions))}
}

func (sc scope) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	return slices.ContainsFunc(sc.ranges, func(p netip.Prefix) bool { return p.Contains(ip) }) &&
		!slices.ContainsFunc(sc.excl, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// count estimates how many addresses a sweep covers: the ranges minus what the exclusions take out of them.
func (sc scope) count() int {
	n := 0
	for _, r := range sc.ranges {
		n += prefixSize(r)
	}
	for _, x := range sc.excl {
		for _, r := range sc.ranges {
			switch {
			case r.Contains(x.Addr()) && r.Bits() <= x.Bits():
				n -= prefixSize(x)
			case x.Contains(r.Addr()) && x.Bits() <= r.Bits():
				n -= prefixSize(r)
			}
		}
	}
	return max(n, 0)
}

// within is the part of the scope inside the prefixes ps, with the same exclusions (CIDR blocks are nested or disjoint, so
// the overlap of two is the smaller one or nothing).
func (sc scope) within(ps []netip.Prefix) scope {
	var in []netip.Prefix
	for _, r := range sc.ranges {
		for _, p := range ps {
			if !p.Addr().Is4() {
				continue
			}
			p = p.Masked()
			switch {
			case r.Contains(p.Addr()) && r.Bits() <= p.Bits():
				in = append(in, p)
			case p.Contains(r.Addr()) && p.Bits() <= r.Bits():
				in = append(in, r)
			}
		}
	}
	return scope{ranges: mergePrefixes(in), excl: sc.excl}
}

// InScope reports whether ip is inside LANRanges and outside Exclusions, the same rule as the inventory's
// (SYS-7), applied to a settings snapshot already in memory.
func (st Settings) InScope(ip netip.Addr) bool { return newScope(st).contains(ip) }

// walker yields every host address of the ranges once, in ascending order: no network or broadcast address of
// a range wider than /31. It holds no list, so a /8 costs no memory, and it can start after an address (the
// sweep cursor, so a window that cut a pass is continued where it stopped).
type walker struct {
	ps    []netip.Prefix
	after netip.Addr // yield only addresses above this one (invalid: from the start)
	i     int
	cur   netip.Addr
	begun bool
}

func newWalker(ps []netip.Prefix, after netip.Addr) *walker {
	return &walker{ps: mergePrefixes(ps), after: after}
}

// startOf is where p is entered; ok is false when the cursor is already past p.
func (w *walker) startOf(p netip.Prefix) (netip.Addr, bool) {
	if !w.after.IsValid() || w.after.Less(p.Addr()) {
		return p.Addr(), true
	}
	if p.Contains(w.after) {
		n := w.after.Next()
		return n, n.IsValid() && p.Contains(n)
	}
	return netip.Addr{}, false
}

func (w *walker) next() (netip.Addr, bool) {
	for w.i < len(w.ps) {
		p := w.ps[w.i]
		if !w.begun {
			w.begun = true
			var ok bool
			if w.cur, ok = w.startOf(p); !ok {
				w.i, w.begun = w.i+1, false
				continue
			}
		}
		for w.cur.IsValid() && p.Contains(w.cur) {
			a := w.cur
			w.cur = a.Next()
			if p.Bits() <= 30 && (a == p.Addr() || !p.Contains(a.Next())) {
				continue // network and broadcast address
			}
			return a, true
		}
		w.i, w.begun = w.i+1, false
	}
	return netip.Addr{}, false
}
