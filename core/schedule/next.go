package schedule

import (
	"slices"
	"time"
)

// Next returns when a validated rule next comes due strictly after after, in UTC, read in loc (the rule's zone); the zero time
// when it never does again (a once rule whose time has passed). It is a pure function of its arguments: the stored next_due_at
// of every schedule equals Next of its rule from its reference time (Reference), and the self-check recomputes it.
//
// Clock times are wall-clock times in loc:
//   - a time the clocks skip (the hour lost when summer time starts) comes due at the moment the clocks jump;
//   - a time the clocks show twice (the hour repeated when summer time ends) comes due once, the first time;
//   - a monthly day the month does not have (the 31st in April) comes due on the month's last day;
//   - "every N days at HH:MM" comes due at HH:MM on the Nth calendar day after the day of after, whatever its length in hours;
//   - "every N minutes" without a time of day is elapsed time, so it does not move with summer time.
//
// A custom window moves a time outside it to the next opening of the window. A window that crosses midnight belongs to the day it
// opens on: "Friday 23:00 to 05:00" lasts until Saturday 05:00. The scan window (WindowGlobal) is not part of the rule: the
// ticker holds a due schedule until it opens.
func Next(r Rule, after time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	var t time.Time
	at, _ := clockOf(r.At)
	switch r.Freq {
	case Interval:
		if r.EveryMinutes == nil || *r.EveryMinutes < 1 {
			return time.Time{}
		}
		n := *r.EveryMinutes
		if r.At != nil && n%MinuteOfDay == 0 {
			d := after.In(loc)
			t = localAt(d.Year(), d.Month(), d.Day()+n/MinuteOfDay, at, loc)
		} else {
			t = after.Add(time.Duration(n) * time.Minute)
		}
	case Daily:
		t = firstDay(after, loc, at, func(time.Time) bool { return true })
	case Weekly:
		t = firstDay(after, loc, at, func(d time.Time) bool { return slices.Contains(r.Weekdays, isoWeekday(d)) })
	case Monthly:
		if r.MonthDay == nil {
			return time.Time{}
		}
		t = monthly(after, loc, at, *r.MonthDay)
	case Once:
		if r.OnceAt != nil && r.OnceAt.After(after) {
			t = *r.OnceAt
		}
	}
	if t.IsZero() {
		return t
	}
	if w, ok := r.window(); ok {
		t = w.OpenAt(t, loc)
	}
	return t.UTC()
}

func clockOf(s *string) (int, bool) {
	if s == nil {
		return 0, false
	}
	return clock(*s)
}

// isoWeekday is 1 for Monday ... 7 for Sunday.
func isoWeekday(t time.Time) int {
	wd := int(t.Weekday())
	if wd == 0 {
		return 7
	}
	return wd
}

// firstDay is the first time at minutes-after-midnight on a day that match accepts, strictly after after. Every rule that uses it
// matches at least one day a week, so it looks at most 8 days ahead.
func firstDay(after time.Time, loc *time.Location, at int, match func(time.Time) bool) time.Time {
	d := after.In(loc)
	for i := 0; i <= 8; i++ {
		day := time.Date(d.Year(), d.Month(), d.Day()+i, 12, 0, 0, 0, loc) // noon: never in a clock change
		if !match(day) {
			continue
		}
		if t := localAt(day.Year(), day.Month(), day.Day(), at, loc); t.After(after) {
			return t
		}
	}
	return time.Time{}
}

// monthly is the first time at minutes-after-midnight on day of a month (0 = the last day; a day past the month's end is its last
// day), strictly after after.
func monthly(after time.Time, loc *time.Location, at, day int) time.Time {
	d := after.In(loc)
	for i := 0; i <= 2; i++ {
		first := time.Date(d.Year(), d.Month()+time.Month(i), 1, 12, 0, 0, 0, loc)
		last := time.Date(first.Year(), first.Month()+1, 0, 12, 0, 0, 0, loc).Day()
		dd := day
		if dd == 0 || dd > last {
			dd = last
		}
		if t := localAt(first.Year(), first.Month(), dd, at, loc); t.After(after) {
			return t
		}
	}
	return time.Time{}
}

// localAt is the instant the clocks of loc show y-m-d at minutes after midnight (d may overflow the month, as in time.Date). A time
// the clocks show twice is the first of the two; a time they skip is the instant they jump.
func localAt(y int, m time.Month, d, minutes int, loc *time.Location) time.Time {
	day := time.Date(y, m, d, 12, 0, 0, 0, loc) // normalizes an overflowing day
	y, m, d = day.Date()
	hh, mm := minutes/60, minutes%60
	naive := time.Date(y, m, d, hh, mm, 0, 0, time.UTC)
	var best time.Time
	var offs []int
	for _, probe := range []time.Duration{-36 * time.Hour, 0, 36 * time.Hour} {
		_, off := naive.Add(probe).In(loc).Zone()
		if slices.Contains(offs, off) {
			continue
		}
		offs = append(offs, off)
		t := naive.Add(-time.Duration(off) * time.Second)
		l := t.In(loc)
		ly, lm, ld := l.Date()
		if ly == y && lm == m && ld == d && l.Hour() == hh && l.Minute() == mm && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if !best.IsZero() {
		return best
	}
	// Skipped by the clocks: the jump lies between the instant read with the offset after it and the one read with the offset
	// before it. Find the first instant whose offset is the later one.
	lo, hi := naive.Add(-time.Duration(maxOf(offs))*time.Second), naive.Add(-time.Duration(minOf(offs))*time.Second)
	if !lo.Before(hi) {
		return time.Date(y, m, d, hh, mm, 0, 0, loc) // not a jump this function knows: let time.Date decide
	}
	_, offHi := hi.In(loc).Zone()
	for hi.Sub(lo) > time.Second {
		mid := lo.Add(hi.Sub(lo) / 2).Truncate(time.Second)
		if mid.Equal(lo) {
			break
		}
		if _, off := mid.In(loc).Zone(); off == offHi {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

func maxOf(xs []int) int { return slices.Max(xs) }
func minOf(xs []int) int { return slices.Min(xs) }

// Window is days of the week with hours, in a zone given when it is read: a custom window of a rule, or the box's scan window.
type Window struct {
	Days     []int  // 1 = Monday ... 7 = Sunday
	From, To string // HH:MM; To earlier than From crosses midnight; To equal to From is 24 hours
}

// span returns the window that opened on day (a date in loc), if day is one of its days.
func (w Window) span(day time.Time, loc *time.Location) (start, end time.Time, ok bool) {
	from, ok1 := clock(w.From)
	to, ok2 := clock(w.To)
	if !ok1 || !ok2 || !slices.Contains(w.Days, isoWeekday(day)) {
		return time.Time{}, time.Time{}, false
	}
	y, m, d := day.Date()
	start = localAt(y, m, d, from, loc)
	if to > from {
		end = localAt(y, m, d, to, loc)
	} else {
		end = localAt(y, m, d+1, to, loc)
	}
	return start, end, end.After(start)
}

// Contains reports whether t is inside the window.
func (w Window) Contains(t time.Time, loc *time.Location) bool {
	l := t.In(loc)
	for back := 0; back <= 1; back++ { // opened today, or yesterday and crosses midnight
		day := time.Date(l.Year(), l.Month(), l.Day()-back, 12, 0, 0, 0, loc)
		if s, e, ok := w.span(day, loc); ok && !t.Before(s) && t.Before(e) {
			return true
		}
	}
	return false
}

// OpenAt returns t when the window is open at t, otherwise the next time it opens; t itself when it never opens (no valid day or
// hours), so a broken window never stops a schedule for good.
func (w Window) OpenAt(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	if w.Contains(t, loc) {
		return t
	}
	l := t.In(loc)
	for i := 0; i <= 8; i++ {
		day := time.Date(l.Year(), l.Month(), l.Day()+i, 12, 0, 0, 0, loc)
		if s, _, ok := w.span(day, loc); ok && s.After(t) {
			return s.UTC()
		}
	}
	return t
}
