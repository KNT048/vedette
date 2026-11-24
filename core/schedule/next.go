package schedule

import (
	"slices"
	"time"
)

// Next returns when a validated rule next comes due strictly after after, counted from after, in UTC, read in loc (the rule's
// zone); the zero time when it never does again (a once rule whose time has passed). It is a pure function of its arguments. The
// stored next_due_at of a schedule is Due, which is Next for the calendar rules and keeps the asked times of an interval.
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
	return place(r, regular(r, after, loc), loc)
}

// place returns an asked time t of a rule where it starts, in UTC: t itself, or the next opening of the rule's custom window when t
// is outside it. Moved to an opening, a calendar rule (and every N days at a time) whose next asked time falls in the same opening
// runs at that time instead, so one opening never starts the work twice (daily 03:00 in Friday 23:00-05:00 runs Saturday 03:00, not
// also Friday 23:00). An elapsed interval starts at the opening: the asked times it missed while the window was closed start once.
func place(r Rule, t time.Time, loc *time.Location) time.Time {
	if t.IsZero() {
		return t
	}
	if w, ok := r.window(); ok {
		start, end, ok := w.opening(t, loc)
		if ok && t.Before(start) {
			moved := start
			if !r.elapsed() {
				n := t
				for i := 0; i < 64 && !n.IsZero() && n.Before(start); i++ { // the opening is at most 8 days on
					n = regular(r, n, loc)
				}
				if !n.IsZero() && !n.Before(start) && n.Before(end) {
					moved = n
				}
			}
			t = moved
		}
	}
	return t.UTC()
}

// elapsed reports whether r is an interval of elapsed time (every N minutes or hours, no time of day): its asked times are a fixed
// step from where they start, not times on the calendar.
func (r Rule) elapsed() bool {
	return r.Freq == Interval && (r.At == nil || r.EveryMinutes == nil || *r.EveryMinutes%MinuteOfDay != 0)
}

// regular is the first time of a rule strictly after after, without its window.
func regular(r Rule, after time.Time, loc *time.Location) time.Time {
	at := clockOf(r.At)
	switch r.Freq {
	case Interval:
		if r.EveryMinutes == nil || *r.EveryMinutes < 1 {
			return time.Time{}
		}
		n := *r.EveryMinutes
		if r.At == nil || n%MinuteOfDay != 0 {
			return after.Add(time.Duration(n) * time.Minute)
		}
		// Every N days at HH:MM: the first HH:MM at least N-1 calendar days after the day of after, compared on the wall
		// clock (so every 1 day is daily, and a change in the morning runs that evening).
		d := after.In(loc)
		days := n/MinuteOfDay - 1
		if at*60 <= d.Hour()*3600+d.Minute()*60+d.Second() {
			days++
		}
		t := localAt(d.Year(), d.Month(), d.Day()+days, at, loc)
		if !t.After(after) {
			t = localAt(d.Year(), d.Month(), d.Day()+days+1, at, loc)
		}
		return t
	case Daily:
		return firstDay(after, loc, at, func(time.Time) bool { return true })
	case Weekly:
		return firstDay(after, loc, at, func(d time.Time) bool { return slices.Contains(r.Weekdays, isoWeekday(d)) })
	case Monthly:
		if r.MonthDay == nil {
			return time.Time{}
		}
		return monthly(after, loc, at, *r.MonthDay)
	case Once:
		if r.OnceAt != nil && r.OnceAt.After(after) {
			return *r.OnceAt
		}
	}
	return time.Time{}
}

// Due is the next due time of a schedule (zero: never), from the times stored on it: when it last came due (lastDue: the due time,
// or the moment it started when that was late), when a person last changed it, and the end of its pause.
//
// A calendar rule (daily, weekly, monthly, once) is Next from Reference: its asked times are on the calendar, so a moved or late
// start never shifts them. An interval keeps the asked times the person chose: they start at the change (the first time after it;
// "every 7 days, paused until Monday" at the end of the pause, with a time of day at the first such time after it) and follow one
// another a whole interval apart. The next due time is the first asked time after the last start, so a start the window moved, the
// scan window held, an owner held or the box started late is followed by the asked times again, never counted from the moved start.
// An elapsed interval also leaves out an asked time less than half an interval after a late or moved start, so two runs of "every 6
// hours" are never minutes apart. The custom window then moves the time into it (place).
func Due(r Rule, lastDue *time.Time, updated time.Time, pausedUntil *time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	if r.Freq != Interval || r.EveryMinutes == nil || *r.EveryMinutes < 1 {
		return Next(r, Reference(lastDue, updated, pausedUntil), loc)
	}
	anchor, fromPause := updated, false
	if pausedUntil != nil && pausedUntil.After(updated) {
		anchor, fromPause = *pausedUntil, true
	}
	var g time.Time // the first asked time
	switch {
	case fromPause && r.elapsed():
		g = anchor
	case fromPause:
		day := r
		one := MinuteOfDay
		day.EveryMinutes = &one
		g = regular(day, anchor, loc)
	default:
		g = regular(r, anchor, loc)
	}
	if lastDue != nil && !lastDue.Before(anchor) {
		g = askedAfter(r, g, *lastDue, loc)
	}
	return place(r, g, loc)
}

// askedAfter is the first asked time of an interval, of those that start at g, strictly after s; for an elapsed interval also at
// least half an interval after s.
func askedAfter(r Rule, g, s time.Time, loc *time.Location) time.Time {
	if g.IsZero() {
		return g
	}
	if r.elapsed() {
		step := time.Duration(*r.EveryMinutes) * time.Minute
		if from := s.Add(step / 2); g.Before(from) {
			g = g.Add((from.Sub(g) + step - 1) / step * step)
		}
		return g
	}
	if g.After(s) {
		return g
	}
	// Every N days at a time: jump close to s by whole steps, then step (a step from an asked time is N days at the time).
	n := *r.EveryMinutes / MinuteOfDay
	at := clockOf(r.At)
	gl, sl := g.In(loc), s.In(loc)
	days := int(civil(sl).Sub(civil(gl)).Hours()) / 24
	if k := days/n - 1; k > 0 {
		g = localAt(gl.Year(), gl.Month(), gl.Day()+k*n, at, loc)
	}
	for i := 0; i < 8 && !g.IsZero() && !g.After(s); i++ {
		g = regular(r, g, loc)
	}
	return g
}

// civil is the date of a local time as noon UTC, for counting calendar days.
func civil(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 12, 0, 0, 0, time.UTC)
}

// clockOf is the minutes after midnight of a validated HH:MM; 0 for none.
func clockOf(s *string) int {
	if s == nil {
		return 0
	}
	m, _ := clock(*s)
	return m
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

// opening returns the opening of the window that contains t, or the next one after t; ok is false when it never opens.
func (w Window) opening(t time.Time, loc *time.Location) (start, end time.Time, ok bool) {
	l := t.In(loc)
	for i := -1; i <= 8; i++ { // one that opened yesterday and crosses midnight, then today and the days after
		day := time.Date(l.Year(), l.Month(), l.Day()+i, 12, 0, 0, 0, loc)
		if s, e, ok := w.span(day, loc); ok && t.Before(e) {
			return s, e, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// OpenAt returns t when the window is open at t, otherwise the next time it opens; t itself when it never opens (no valid day or
// hours), so a broken window never stops a schedule for good.
func (w Window) OpenAt(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	s, _, ok := w.opening(t, loc)
	if !ok || !t.Before(s) {
		return t
	}
	return s.UTC()
}
