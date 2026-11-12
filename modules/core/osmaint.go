package core

import (
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// The maintenance window (S-CORE-7, D-53) is core's own setting: days and hours in the organization time
// zone. It restricts when a reboot may be scheduled and when the automatic mode of the software update may start a run
// (updates_auto.go, update-manifest §6); OS installs are not tied to it, and unattended-upgrades runs on apt's own
// timers (host-api 6.3). Same rules as web/src/features/core/osMock.ts.

// Error codes of the OS endpoints that core decides itself (the host's own are in oshost.go).
const (
	CodeInvalidWindow  = "invalid_window"
	CodeNoDays         = "no_days"
	CodeInvalidTime    = "invalid_time"
	CodeEmptyWindow    = "empty_window"
	CodeInvalidScope   = "invalid_scope"
	CodeInvalidWhen    = "invalid_when"
	CodeNoWindow       = "no_window"
	CodeOutsideWindow  = "outside_window"
	CodeNothingToDo    = "nothing_to_install"
	CodeNothingPlanned = "nothing_scheduled"
	CodeCheckOff       = "check_off"
)

const (
	windowAlways = "always"
	windowOnly   = "window"
	// rebootMinLead and rebootMaxLead keep a scheduled reboot inside what the host accepts (at least 60 seconds
	// and at most 7 days ahead of its clock) with a margin on both sides.
	rebootMinLead = 2 * time.Minute
	rebootMaxLead = 7*24*time.Hour - time.Minute
)

var hhmmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// maintWindow is the contract's MaintenanceWindow.
type maintWindow struct {
	Mode string `json:"mode"` // "always" | "window"
	Days []int  `json:"days"` // 1 = Monday … 7 = Sunday; used only when Mode is "window"
	From string `json:"from"` // HH:MM
	To   string `json:"to"`   // earlier than From: crosses midnight
}

func defaultWindow() maintWindow {
	return maintWindow{Mode: windowAlways, Days: []int{7}, From: "02:00", To: "05:00"}
}

// normalize validates a window sent by a client and returns it with days sorted and unique. "always" keeps the
// days and hours already stored (the form remembers them), as the mock does.
func (w maintWindow) normalize(stored maintWindow) (maintWindow, *apierr.Error) {
	switch w.Mode {
	case windowAlways:
		stored.Mode = windowAlways
		return stored, nil
	case windowOnly:
	default:
		return maintWindow{}, apierr.New(400, CodeInvalidWindow, `The maintenance window is "any time" or "only in a window".`)
	}
	if len(w.Days) == 0 || slices.ContainsFunc(w.Days, func(d int) bool { return d < 1 || d > 7 }) {
		return maintWindow{}, apierr.New(400, CodeNoDays, "Pick at least one day for the maintenance window.")
	}
	if !hhmmRE.MatchString(w.From) || !hhmmRE.MatchString(w.To) {
		return maintWindow{}, apierr.New(400, CodeInvalidTime, "Enter the start and end as hours and minutes, for example 02:00.")
	}
	if w.From == w.To {
		return maintWindow{}, apierr.New(400, CodeEmptyWindow, "The start and the end are the same, so the window is empty. Choose different times.")
	}
	days := slices.Clone(w.Days)
	slices.Sort(days)
	return maintWindow{Mode: windowOnly, Days: slices.Compact(days), From: w.From, To: w.To}, nil
}

func isoDay(t time.Time) int {
	if d := int(t.Weekday()); d != 0 {
		return d
	}
	return 7
}

func minutesOf(hhmm string) int { // hhmm passed hhmmRE
	return int(hhmm[0]-'0')*600 + int(hhmm[1]-'0')*60 + int(hhmm[3]-'0')*10 + int(hhmm[4]-'0')
}

// contains reports whether t falls inside the window; t is read in loc. A window that crosses midnight
// belongs to the day it starts on.
func (w maintWindow) contains(t time.Time, loc *time.Location) bool {
	if w.Mode == windowAlways {
		return true
	}
	t = t.In(loc)
	m := t.Hour()*60 + t.Minute()
	from, to := minutesOf(w.From), minutesOf(w.To)
	if from < to {
		return slices.Contains(w.Days, isoDay(t)) && m >= from && m < to
	}
	prev := t.AddDate(0, 0, -1)
	return (m >= from && slices.Contains(w.Days, isoDay(t))) || (m < to && slices.Contains(w.Days, isoDay(prev)))
}

// at returns hh:mm of the calendar day that is i days after now's day, in loc.
func at(now time.Time, i int, hhmm string, loc *time.Location) time.Time {
	n := now.In(loc)
	m := minutesOf(hhmm)
	return time.Date(n.Year(), n.Month(), n.Day()+i, m/60, m%60, 0, 0, loc)
}

func reachable(c, now time.Time) bool {
	return c.After(now.Add(rebootMinLead)) && !c.After(now.Add(rebootMaxLead))
}

// nextStart is the first start of the window after now that the host will take (two minutes to a week ahead).
// The instant it returns lies inside the window: on a day a clock change removes the start time (02:00 on a
// spring-forward day), time.Date moves it to a time that may be outside, and that day is skipped.
func (w maintWindow) nextStart(now time.Time, loc *time.Location) (time.Time, bool) {
	if w.Mode != windowOnly {
		return time.Time{}, false
	}
	for i := 0; i <= 8; i++ {
		if c := at(now, i, w.From, loc); reachable(c, now) && slices.Contains(w.Days, isoDay(c)) && w.contains(c, loc) {
			return c, true
		}
	}
	return time.Time{}, false
}

// nextAt is the first time of day hhmm after now that lies inside the window and that the host will take.
func (w maintWindow) nextAt(now time.Time, hhmm string, loc *time.Location) (time.Time, bool) {
	for i := 0; i <= 8; i++ {
		if c := at(now, i, hhmm, loc); reachable(c, now) && w.contains(c, loc) {
			return c, true
		}
	}
	return time.Time{}, false
}
