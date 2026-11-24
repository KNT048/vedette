// Package orgtime writes times for people: every date and time a page, an alert, an email or an AI fact shows is in the
// organization's time zone (Settings › General), the zone the web uses too, so one moment reads as the same day everywhere.
// Stored and compared times stay UTC; only the text changes.
//
// Two kinds of value are written:
//   - an instant (a scan, a report from an agent, a backup): Day, Stamp, Clock and ISODay convert it to the zone first;
//   - a calendar day without a time of day (a CVE's published day, the day a CVE was added to an exploited list, the last day
//     of a risk acceptance, a vendor's release day): CalendarDay and CalendarMonth write it as it is stored, at 00:00 UTC;
//     converting it to a zone west of UTC would move it a day back.
package orgtime

import (
	"context"
	"time"
)

const (
	dayLayout   = "2 Jan 2006"
	stampLayout = "2 Jan 2006, 15:04"
	clockLayout = "15:04"
	monthLayout = "January 2006"
	shortLayout = "2 Jan"
)

// Source gives the organization's time zone at the moment of use (it can change in Settings › General); nil, or a nil
// answer, when it cannot be read.
type Source func(context.Context) *time.Location

// At is the zone src gives now, UTC when there is no source or it cannot be read (a box before its first-run setup, a test).
func At(ctx context.Context, src Source) *time.Location {
	if src != nil {
		if l := src(ctx); l != nil {
			return l
		}
	}
	return time.UTC
}

func in(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc)
}

// Day is the day of instant t in loc: "15 Nov 2026".
func Day(t time.Time, loc *time.Location) string { return in(t, loc).Format(dayLayout) }

// Short is the day of instant t in loc without its year, for a sentence about a recent period: "15 Nov".
func Short(t time.Time, loc *time.Location) string { return in(t, loc).Format(shortLayout) }

// Stamp is instant t in loc to the minute: "15 Nov 2026, 04:11".
func Stamp(t time.Time, loc *time.Location) string { return in(t, loc).Format(stampLayout) }

// StampZone is Stamp with the zone's abbreviation, for a text read away from the box (an alert, an email, a chat message), where
// the reader cannot tell the zone from the page around it: "15 Nov 2026, 04:11 +07", "15 Nov 2026, 04:11 CET". When the
// organization's zone could not be read (loc nil, or At's fallback) it says "UTC", so the fallback is never silent.
func StampZone(t time.Time, loc *time.Location) string {
	l := in(t, loc)
	return l.Format(stampLayout) + " " + l.Format("MST")
}

// Clock is the time of day of instant t in loc: "04:11".
func Clock(t time.Time, loc *time.Location) string { return in(t, loc).Format(clockLayout) }

// ClockZone is Clock with the zone's abbreviation (see StampZone): "04:11 +07", "08:30 UTC".
func ClockZone(t time.Time, loc *time.Location) string {
	l := in(t, loc)
	return l.Format(clockLayout) + " " + l.Format("MST")
}

// ISODay is the day of instant t in loc as the API sends a date: "2026-11-15".
func ISODay(t time.Time, loc *time.Location) string { return in(t, loc).Format(time.DateOnly) }

// FileStamp is instant t in loc to the minute for a file name, with no character a file system refuses: "2026-11-15-0411".
// Two files made the same day get different names, and they sort by time.
func FileStamp(t time.Time, loc *time.Location) string { return in(t, loc).Format("2006-01-02-1504") }

// CalendarDay writes a calendar day stored at 00:00 UTC (see the package comment): "15 Nov 2026".
func CalendarDay(d time.Time) string { return d.UTC().Format(dayLayout) }

// CalendarMonth writes the month of a calendar day stored at 00:00 UTC: "November 2026".
func CalendarMonth(d time.Time) string { return d.UTC().Format(monthLayout) }

// CalendarShort writes a calendar day stored at 00:00 UTC without its year, for a sentence about this week: "3 Nov".
func CalendarShort(d time.Time) string { return d.UTC().Format(shortLayout) }
