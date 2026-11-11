package reports

import "time"

// slotAt is the latest send slot (the chosen weekday at the chosen hour, box time) that is not after now.
func slotAt(now time.Time, loc *time.Location, dayOfWeek, hour int) time.Time {
	n := now.In(loc)
	d := time.Date(n.Year(), n.Month(), n.Day(), hour, 0, 0, 0, loc)
	want := dayOfWeek % 7 // 1 = Monday … 7 = Sunday; time.Weekday: Sunday = 0
	back := (int(d.Weekday()) - want + 7) % 7
	d = time.Date(d.Year(), d.Month(), d.Day()-back, hour, 0, 0, 0, loc)
	if d.After(n) {
		d = time.Date(d.Year(), d.Month(), d.Day()-7, hour, 0, 0, 0, loc)
	}
	return d.UTC()
}

// nextRun is the first slot after now.
func nextRun(now time.Time, loc *time.Location, dayOfWeek, hour int) time.Time {
	s := slotAt(now, loc, dayOfWeek, hour).In(loc)
	return time.Date(s.Year(), s.Month(), s.Day()+7, hour, 0, 0, 0, loc).UTC()
}

// catchUp is how late the job may still send a slot it missed because the box was off or the module was off (POST-2): once, and
// only within this window. A report that arrives days late would show the wrong week.
const catchUp = 24 * time.Hour
