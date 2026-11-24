package schedule

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Freq is how often a schedule comes due (core_schedule.freq). It is an open vocabulary checked by shape in the database; this
// type is its one owner.
type Freq string

// The frequencies.
const (
	Interval Freq = "interval" // every EveryMinutes; with At (a whole number of days) every N days at that time
	Daily    Freq = "daily"    // every day at At
	Weekly   Freq = "weekly"   // on the Weekdays at At
	Monthly  Freq = "monthly"  // on MonthDay (0 = the last day) at At
	Once     Freq = "once"     // once, at OnceAt
)

// Freqs lists every frequency, in the order the editor offers them.
var Freqs = []Freq{Interval, Daily, Weekly, Monthly, Once}

// Valid reports whether f is one of Freqs.
func (f Freq) Valid() bool { return slices.Contains(Freqs, f) }

// WindowMode says when a due schedule may start (core_schedule.window_mode).
type WindowMode string

// The window modes.
const (
	WindowGlobal WindowMode = "global" // only inside the box's scan window (Settings, Scanning, Safety): the run starts when it opens
	WindowNone   WindowMode = "none"   // at any time
	WindowCustom WindowMode = "custom" // only inside its own days and hours (WindowDays, WindowFrom, WindowTo)
)

// WindowModes lists every window mode.
var WindowModes = []WindowMode{WindowGlobal, WindowNone, WindowCustom}

// Valid reports whether w is one of WindowModes.
func (w WindowMode) Valid() bool { return slices.Contains(WindowModes, w) }

// OrgZone is the tz of every schedule: the box has one time zone (Settings, General, which the operating system follows too), and
// every schedule reads its times of day, days and window in it. The column and the field stay for the versions before this one: a
// zone one of them stored is read as the box's zone (scanRow), and a zone a client still sends is ignored (Validate).
const OrgZone = "org"

// Limits of a rule, whatever its owner allows.
const (
	MaxEveryMinutes = 366 * 24 * 60 // a year
	MinuteOfDay     = 24 * 60
)

// Rule is when a schedule comes due: the rule columns of core_schedule, and the rule of the API. The fields a frequency does not
// use are nil (Validate clears them).
type Rule struct {
	Freq         Freq       `json:"freq"`
	EveryMinutes *int       `json:"every_minutes"` // interval: 1 to MaxEveryMinutes
	At           *string    `json:"at_time"`       // HH:MM; daily, weekly and monthly; interval only for a whole number of days
	Weekdays     []int      `json:"weekdays"`      // weekly: 1 = Monday ... 7 = Sunday
	MonthDay     *int       `json:"month_day"`     // monthly: 1 to 31 (a shorter month runs on its last day), 0 = the last day
	OnceAt       *time.Time `json:"once_at"`       // once
	TZ           string     `json:"tz"`            // always OrgZone: the box's zone is the zone of At, the days and the window
	Window       WindowMode `json:"window"`
	WindowDays   []int      `json:"window_days"` // custom: 1 = Monday ... 7 = Sunday
	WindowFrom   *string    `json:"window_from"` // custom: HH:MM; equal to WindowTo = the whole day
	WindowTo     *string    `json:"window_to"`   // custom: HH:MM; earlier than WindowFrom = the window crosses midnight
}

// The constructors owners use for their default rules.

// Every is a rule due every n minutes, at any time.
func Every(minutes int) Rule {
	return Rule{Freq: Interval, EveryMinutes: &minutes, TZ: OrgZone, Window: WindowNone}
}

// DailyAt is a rule due every day at hhmm.
func DailyAt(hhmm string) Rule { return Rule{Freq: Daily, At: &hhmm, TZ: OrgZone, Window: WindowNone} }

// WeeklyAt is a rule due on the given weekdays (1 = Monday) at hhmm.
func WeeklyAt(hhmm string, weekdays ...int) Rule {
	return Rule{Freq: Weekly, At: &hhmm, Weekdays: weekdays, TZ: OrgZone, Window: WindowNone}
}

// MonthlyAt is a rule due on day (0 = the last day) of every month at hhmm.
func MonthlyAt(hhmm string, day int) Rule {
	return Rule{Freq: Monthly, At: &hhmm, MonthDay: &day, TZ: OrgZone, Window: WindowNone}
}

// InWindow returns r limited to the box's scan window.
func (r Rule) InWindow() Rule { r.Window = WindowGlobal; return r }

// RuleError is a rule that cannot be saved: Field names the field (as in the API), Message says why, for the person.
type RuleError struct {
	Field   string
	Message string
}

func (e *RuleError) Error() string { return "schedule: " + e.Field + ": " + e.Message }

func ruleErr(field, format string, args ...any) error {
	return &RuleError{Field: field, Message: fmt.Sprintf(format, args...)}
}

var hhmmRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// clock parses HH:MM into minutes after midnight.
func clock(s string) (int, bool) {
	if !hhmmRE.MatchString(s) {
		return 0, false
	}
	h, _ := strconv.Atoi(s[:2])
	m, _ := strconv.Atoi(s[3:])
	return h*60 + m, true
}

// days checks a list of weekdays and returns it sorted without repeats.
func days(field string, ds []int) ([]int, error) {
	if len(ds) == 0 {
		return nil, ruleErr(field, "Choose at least one day of the week.")
	}
	out := slices.Clone(ds)
	slices.Sort(out)
	out = slices.Compact(out)
	if out[0] < 1 || out[len(out)-1] > 7 {
		return nil, ruleErr(field, "Days of the week are 1 (Monday) to 7 (Sunday).")
	}
	return out, nil
}

// Validate checks a rule and returns it normalized: the fields its frequency does not use are cleared, day lists are sorted, the tz
// is OrgZone whatever was sent (a client of an earlier version may still send a zone of its own: the save goes through and the
// answer says the zone the rule is read in, rather than refusing a field the person can no longer see) and an empty window is
// none. The error is a *RuleError.
func Validate(r Rule) (Rule, error) {
	out := Rule{Freq: r.Freq, TZ: OrgZone, Window: r.Window}
	at := func() error {
		if r.At == nil {
			return ruleErr("at_time", "Choose the time of day.")
		}
		if _, ok := clock(*r.At); !ok {
			return ruleErr("at_time", "The time of day is HH:MM, from 00:00 to 23:59.")
		}
		v := *r.At
		out.At = &v
		return nil
	}
	switch r.Freq {
	case Interval:
		if r.EveryMinutes == nil || *r.EveryMinutes < 1 || *r.EveryMinutes > MaxEveryMinutes {
			return Rule{}, ruleErr("every_minutes", "The interval is 1 minute to 366 days.")
		}
		n := *r.EveryMinutes
		out.EveryMinutes = &n
		if r.At != nil {
			if n%MinuteOfDay != 0 {
				return Rule{}, ruleErr("at_time", "A time of day goes with an interval of whole days only.")
			}
			if err := at(); err != nil {
				return Rule{}, err
			}
		}
	case Daily:
		if err := at(); err != nil {
			return Rule{}, err
		}
	case Weekly:
		if err := at(); err != nil {
			return Rule{}, err
		}
		ds, err := days("weekdays", r.Weekdays)
		if err != nil {
			return Rule{}, err
		}
		out.Weekdays = ds
	case Monthly:
		if err := at(); err != nil {
			return Rule{}, err
		}
		if r.MonthDay == nil || *r.MonthDay < 0 || *r.MonthDay > 31 {
			return Rule{}, ruleErr("month_day", "The day of the month is 1 to 31, or the last day.")
		}
		d := *r.MonthDay
		out.MonthDay = &d
	case Once:
		if r.OnceAt == nil || r.OnceAt.IsZero() {
			return Rule{}, ruleErr("once_at", "Choose the date and time.")
		}
		t := r.OnceAt.UTC().Truncate(time.Millisecond)
		out.OnceAt = &t
	default:
		return Rule{}, ruleErr("freq", "Choose how often: every N minutes, hours or days, daily, weekly, monthly or once.")
	}
	switch out.Window {
	case "":
		out.Window = WindowNone
	case WindowNone, WindowGlobal:
	case WindowCustom:
		ds, err := days("window_days", r.WindowDays)
		if err != nil {
			return Rule{}, err
		}
		if r.WindowFrom == nil || r.WindowTo == nil {
			return Rule{}, ruleErr("window_from", "Choose when the window opens and when it closes.")
		}
		if _, ok := clock(*r.WindowFrom); !ok {
			return Rule{}, ruleErr("window_from", "The window opens at HH:MM, from 00:00 to 23:59.")
		}
		if _, ok := clock(*r.WindowTo); !ok {
			return Rule{}, ruleErr("window_to", "The window closes at HH:MM, from 00:00 to 23:59.")
		}
		from, to := *r.WindowFrom, *r.WindowTo
		out.WindowDays, out.WindowFrom, out.WindowTo = ds, &from, &to
	default:
		return Rule{}, ruleErr("window", "The window is the scan window, none, or its own days and hours.")
	}
	return out, nil
}

// window returns the custom window of a validated rule; ok is false for the other modes.
func (r Rule) window() (Window, bool) {
	if r.Window != WindowCustom || r.WindowFrom == nil || r.WindowTo == nil {
		return Window{}, false
	}
	return Window{Days: r.WindowDays, From: *r.WindowFrom, To: *r.WindowTo}, true
}

// Limits are what an owner allows people to choose, and the sentence that says why (shown in the editor next to the limit).
type Limits struct {
	Freqs           []Freq       `json:"freqs"`             // the frequencies allowed; empty = all
	MinEveryMinutes int          `json:"min_every_minutes"` // the shortest interval; 0 = 1 minute
	MaxEveryMinutes int          `json:"max_every_minutes"` // the longest interval; 0 = MaxEveryMinutes
	Windows         []WindowMode `json:"windows"`           // the window modes allowed; empty = all
	Reason          string       `json:"reason"`            // why the choices are limited; "" when they are not
}

// normalized fills the zero values with what they mean.
func (l Limits) normalized() Limits {
	if len(l.Freqs) == 0 {
		l.Freqs = slices.Clone(Freqs)
	}
	if l.MinEveryMinutes < 1 {
		l.MinEveryMinutes = 1
	}
	if l.MaxEveryMinutes < 1 || l.MaxEveryMinutes > MaxEveryMinutes {
		l.MaxEveryMinutes = MaxEveryMinutes
	}
	if len(l.Windows) == 0 {
		l.Windows = slices.Clone(WindowModes)
	}
	return l
}

// Check refuses a validated rule its owner does not allow. The error is a *RuleError whose message ends with the reason.
func (l Limits) Check(r Rule) error {
	l = l.normalized()
	why := ""
	if l.Reason != "" {
		why = " " + strings.TrimSpace(l.Reason)
	}
	if !slices.Contains(l.Freqs, r.Freq) {
		names := make([]string, len(l.Freqs))
		for i, f := range l.Freqs {
			names[i] = string(f)
		}
		return ruleErr("freq", "This schedule can only be %s.%s", strings.Join(names, " or "), why)
	}
	if r.Freq == Interval && r.EveryMinutes != nil {
		if *r.EveryMinutes < l.MinEveryMinutes {
			return ruleErr("every_minutes", "The interval is at least %s.%s", span(l.MinEveryMinutes), why)
		}
		if *r.EveryMinutes > l.MaxEveryMinutes {
			return ruleErr("every_minutes", "The interval is at most %s.%s", span(l.MaxEveryMinutes), why)
		}
	}
	if !slices.Contains(l.Windows, r.Window) {
		return ruleErr("window", "This schedule cannot use that window.%s", why)
	}
	return nil
}

// span writes a number of minutes for a person: "5 minutes", "1 hour", "36 hours", "2 days".
func span(minutes int) string {
	unit := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.Itoa(n) + " " + one + "s"
	}
	switch {
	case minutes%MinuteOfDay == 0:
		return unit(minutes/MinuteOfDay, "day")
	case minutes%60 == 0:
		return unit(minutes/60, "hour")
	}
	return unit(minutes, "minute")
}
