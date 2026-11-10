package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"
)

// Window is when scheduled scans may run (INV-5). Days are ISO weekdays, 1 = Monday ... 7 = Sunday (D-57 (9)).
type Window struct {
	Days []int  `json:"days"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Schedule is the periodic scan (S-SCAN-4).
type Schedule struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // daily | weekly
	Weekday   int    `json:"weekday"`
	At        string `json:"at"`
}

// Settings is the scan configuration (contract.ts ScanConfig).
type Settings struct {
	Window             Window   `json:"window"`
	Rate               int      `json:"rate"` // requests per second
	Exclusions         []string `json:"exclusions"`
	StopOnUnresponsive bool     `json:"stop_on_unresponsive"`
	UnresponsiveAfter  int      `json:"unresponsive_after"`
	AutoRescan         bool     `json:"auto_rescan"`
	Schedule           Schedule `json:"schedule"`
}

// Patch is a partial PUT /scans/config: a nil field keeps the stored value (POST-3).
type Patch struct {
	Days               []int // nil: keep
	From, To           *string
	Rate               *int
	Exclusions         []string // nil: keep; empty: clear
	StopOnUnresponsive *bool
	UnresponsiveAfter  *int
	AutoRescan         *bool
	SchedEnabled       *bool
	SchedFrequency     *string
	SchedWeekday       *int
	SchedAt            *string
	DangerousChecks    *bool
}

// Limits of INV-5.
const (
	MaxRate          = 20
	MaxExclusions    = 200
	MinUnresponsive  = 2
	MaxUnresponsive  = 20
	nextRunSearchDay = 15 // the mock looks this many days ahead for the next scheduled run
)

var hhmmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func (p Patch) apply(cur Settings) Settings {
	next := cur
	next.Window.Days = slices.Clone(cur.Window.Days)
	next.Exclusions = slices.Clone(cur.Exclusions)
	if p.Days != nil {
		// stored sorted and once each: [7, 1, 1] and [1, 7] are the same window
		next.Window.Days = slices.Compact(slices.Sorted(slices.Values(p.Days)))
	}
	set(&next.Window.From, p.From)
	set(&next.Window.To, p.To)
	set(&next.Rate, p.Rate)
	if p.Exclusions != nil {
		next.Exclusions = slices.Clone(p.Exclusions)
	}
	set(&next.StopOnUnresponsive, p.StopOnUnresponsive)
	set(&next.UnresponsiveAfter, p.UnresponsiveAfter)
	set(&next.AutoRescan, p.AutoRescan)
	set(&next.Schedule.Enabled, p.SchedEnabled)
	set(&next.Schedule.Frequency, p.SchedFrequency)
	set(&next.Schedule.Weekday, p.SchedWeekday)
	set(&next.Schedule.At, p.SchedAt)
	return next
}

func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// validate checks INV-5 on a whole configuration, in the order and with the words of the mock's validateConfig.
func (c Settings) validate() error {
	w := c.Window
	if len(w.Days) == 0 || len(w.Days) > 7 || slices.ContainsFunc(w.Days, func(d int) bool { return d < 1 || d > 7 }) {
		return invalidConfig("Choose at least one day for the scan window.")
	}
	if !hhmmRE.MatchString(w.From) || !hhmmRE.MatchString(w.To) {
		return invalidConfig("Time must look like HH:MM, for example 22:00.")
	}
	if w.From == w.To {
		return invalidConfig("The start and end times must differ. To scan all day, set 00:00 to 23:59.")
	}
	if c.Rate < 1 || c.Rate > MaxRate {
		return invalidConfig("The rate must be 1 to 20 requests per second. A lower rate is safer for old devices.")
	}
	if len(c.Exclusions) > MaxExclusions {
		return invalidConfig("The exclusion list can have at most 200 lines.")
	}
	for i, e := range c.Exclusions {
		if !validExclusion(e) {
			return invalidConfig("Line %d: \"%s\" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.", i+1, clip(e, 40))
		}
	}
	if c.UnresponsiveAfter < MinUnresponsive || c.UnresponsiveAfter > MaxUnresponsive {
		return invalidConfig("The number of non-responses before auto-stop must be 2 to 20.")
	}
	s := c.Schedule
	if s.Frequency != "daily" && s.Frequency != "weekly" {
		return invalidConfig("The schedule must be daily or weekly.")
	}
	if !hhmmRE.MatchString(s.At) {
		return invalidConfig("The schedule time must look like HH:MM.")
	}
	if s.Weekday < 1 || s.Weekday > 7 {
		return invalidConfig("The schedule day is not valid.")
	}
	if s.Enabled {
		if !inTimeRange(s.At, w.From, w.To) {
			return invalidConfig("The schedule time %s is outside the %s to %s window. Pick a time inside the window or widen the window.", s.At, w.From, w.To)
		}
		if s.Frequency == "weekly" && !slices.Contains(w.Days, s.Weekday) {
			return invalidConfig("The weekly schedule day must be one of the scan window days.")
		}
	}
	return nil
}

// validExclusion accepts one IPv4 address or one IPv4 CIDR range in dotted form (netip refuses leading zeros, so
// "010.0.0.1" cannot mean two things). The text is kept as the admin typed it.
func validExclusion(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4()
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4()
}

// clip cuts s to n runes for an error message.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func minutes(hhmm string) int {
	return int(hhmm[0]-'0')*600 + int(hhmm[1]-'0')*60 + int(hhmm[3]-'0')*10 + int(hhmm[4]-'0')
}

// inTimeRange says whether at falls in [from, to), a range that may cross midnight.
func inTimeRange(at, from, to string) bool {
	a, f, t := minutes(at), minutes(from), minutes(to)
	if f < t {
		return a >= f && a < t
	}
	return a >= f || a < t
}

func isoDay(t time.Time) int {
	if d := int(t.Weekday()); d != 0 {
		return d
	}
	return 7
}

// NextRun is the next scheduled run after now in loc, or nil when the schedule is off (POST-3; the mock's nextRun):
// the first slot within two weeks that slotOK accepts.
func (c Settings) NextRun(now time.Time, loc *time.Location) *time.Time {
	if !c.Schedule.Enabled || !hhmmRE.MatchString(c.Schedule.At) {
		return nil
	}
	at := minutes(c.Schedule.At)
	local := now.In(loc)
	for i := range nextRunSearchDay {
		d := time.Date(local.Year(), local.Month(), local.Day()+i, at/60, at%60, 0, 0, loc)
		if d.After(now) && c.slotOK(d) {
			return &d
		}
	}
	return nil
}

// slotOK says whether the schedule runs at slot (a day at the schedule time): the window the slot falls in starts on
// a window day, and a weekly schedule runs on its weekday (the slot's own calendar day). A window that crosses
// midnight counts by its start day (the GUI's words), so a slot after midnight belongs to the window of the day
// before: Monday 02:00 is in Sunday's 22:00 to 05:00 window (#164 review M1).
func (c Settings) slotOK(slot time.Time) bool {
	if _, ok := c.slotWindowEnd(slot); !ok {
		return false
	}
	return c.Schedule.Frequency == "daily" || isoDay(slot) == c.Schedule.Weekday
}

// slotWindowEnd is when the window of slot closes; ok is false when that window does not start on a window day. The
// schedule time is inside the window (INV-5), so the slot is never before its window starts.
func (c Settings) slotWindowEnd(slot time.Time) (time.Time, bool) {
	from, to := minutes(c.Window.From), minutes(c.Window.To)
	start := slot
	if from > to && minutes(c.Schedule.At) < to { // after midnight: the window began the day before
		start = slot.AddDate(0, 0, -1)
	}
	if !slices.Contains(c.Window.Days, isoDay(start)) {
		return time.Time{}, false
	}
	end := time.Date(start.Year(), start.Month(), start.Day(), to/60, to%60, 0, 0, slot.Location())
	if from > to {
		end = end.AddDate(0, 0, 1)
	}
	return end, true
}

// ---- storage ----

func loadSettings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Settings, error) {
	var c Settings
	var days, excl string
	err := q.QueryRowContext(ctx, `SELECT days, win_from, win_to, rate, exclusions, stop_on_unresponsive, unresponsive_after, auto_rescan,
sched_enabled, sched_frequency, sched_weekday, sched_at FROM scan_setting WHERE id = 1`).Scan(&days, &c.Window.From, &c.Window.To, &c.Rate, &excl,
		&c.StopOnUnresponsive, &c.UnresponsiveAfter, &c.AutoRescan, &c.Schedule.Enabled, &c.Schedule.Frequency, &c.Schedule.Weekday, &c.Schedule.At)
	if err != nil {
		return Settings{}, fmt.Errorf("scan: reading the settings: %w", err)
	}
	if err := json.Unmarshal([]byte(days), &c.Window.Days); err != nil {
		return Settings{}, fmt.Errorf("scan: reading the window days: %w", err)
	}
	if err := json.Unmarshal([]byte(excl), &c.Exclusions); err != nil {
		return Settings{}, fmt.Errorf("scan: reading the exclusions: %w", err)
	}
	if c.Exclusions == nil {
		c.Exclusions = []string{}
	}
	return c, nil
}

func saveSettings(ctx context.Context, tx *sql.Tx, c Settings, user, at string) error {
	days, err := json.Marshal(c.Window.Days)
	if err != nil {
		return fmt.Errorf("scan: encoding the window days: %w", err)
	}
	excl, err := json.Marshal(c.Exclusions)
	if err != nil {
		return fmt.Errorf("scan: encoding the exclusions: %w", err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE scan_setting SET days = ?, win_from = ?, win_to = ?, rate = ?, exclusions = ?, stop_on_unresponsive = ?,
unresponsive_after = ?, auto_rescan = ?, sched_enabled = ?, sched_frequency = ?, sched_weekday = ?, sched_at = ?, updated_at = ?, updated_by = ? WHERE id = 1`,
		string(days), c.Window.From, c.Window.To, c.Rate, string(excl), c.StopOnUnresponsive, c.UnresponsiveAfter, c.AutoRescan,
		c.Schedule.Enabled, c.Schedule.Frequency, c.Schedule.Weekday, c.Schedule.At, at, user)
	if err != nil {
		return fmt.Errorf("scan: saving the settings: %w", err)
	}
	return nil
}
