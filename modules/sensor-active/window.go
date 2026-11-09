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

// window returns the window that contains t (INV-3): its start and its end, in t's own location (the box's
// local time zone; the caller passes t.In(time.Local)). A window that crosses midnight belongs to the day it
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

// walker yields every host address of the ranges once, in order: no network or broadcast address of a range
// wider than /31, and no address an earlier range already yielded. It holds no list, so a /8 costs no memory.
type walker struct {
	ps  []netip.Prefix
	i   int
	cur netip.Addr
}

func newWalker(ps []netip.Prefix) *walker {
	w := &walker{ps: ps}
	if len(ps) > 0 {
		w.cur = ps[0].Addr()
	}
	return w
}

func (w *walker) next() (netip.Addr, bool) {
	for w.i < len(w.ps) {
		p := w.ps[w.i]
		for w.cur.IsValid() && p.Contains(w.cur) {
			a := w.cur
			w.cur = a.Next()
			if p.Bits() <= 30 && (a == p.Addr() || !p.Contains(a.Next())) {
				continue // network and broadcast address
			}
			if slices.ContainsFunc(w.ps[:w.i], func(q netip.Prefix) bool { return q.Contains(a) }) {
				continue
			}
			return a, true
		}
		w.i++
		if w.i < len(w.ps) {
			w.cur = w.ps[w.i].Addr()
		}
	}
	return netip.Addr{}, false
}
