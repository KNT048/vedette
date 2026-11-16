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
	// Version is the shared block's version read with the window, rate and exclusions above, in the same read (Checks; review #860
	// r2 L3); "" without SharedChecks. Not part of the stored row or of contract.ts ScanConfig.
	Version string `json:"-"`
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
	Version            string // the shared block's version the page read (ConfigView.Version); "" = none, no check
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

// validate checks INV-5 on a whole configuration, in the order and with the words of the mock's validateConfig. had is how many
// exclusions the stored configuration held: a list over MaxExclusions passes when it does not grow (the merge of #850 can leave a
// longer one, and a save of something else must still go through: review #857 L7).
func (c Settings) validate(had int) error {
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
	if len(c.Exclusions) > MaxExclusions && len(c.Exclusions) > had {
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
// the first slot within two weeks that slotOK accepts. first is true while no scheduled run has ever started (firstPending,
// W3-9): the first run is then the next window day at the schedule time, whatever the weekday of a weekly schedule (W3-6).
func (c Settings) NextRun(now time.Time, loc *time.Location, first bool) *time.Time {
	if !c.Schedule.Enabled || !hhmmRE.MatchString(c.Schedule.At) {
		return nil
	}
	at := minutes(c.Schedule.At)
	local := now.In(loc)
	for i := range nextRunSearchDay {
		d := time.Date(local.Year(), local.Month(), local.Day()+i, at/60, at%60, 0, 0, loc)
		if d.After(now) && c.slotOK(d, first) {
			return &d
		}
	}
	return nil
}

// slotOK says whether the schedule runs at slot (a day at the schedule time): the window the slot falls in starts on
// a window day, and a weekly schedule runs on its weekday (the slot's own calendar day). A window that crosses
// midnight counts by its start day (the GUI's words), so a slot after midnight belongs to the window of the day
// before: Monday 02:00 is in Sunday's 22:00 to 05:00 window (#164 review M1). The first scheduled run of a box (first) runs in
// the next window of any window day, so a new box with the weekly default does not wait up to a week for it (W3-6, D-504); the
// weekday counts from the second run on.
func (c Settings) slotOK(slot time.Time, first bool) bool {
	// The window is shared with discovery since #850 and saved on its own (PUT /scanning/safety): a schedule time it no longer holds
	// is no slot, so nothing scheduled runs outside the window (INV-5).
	if !inTimeRange(c.Schedule.At, c.Window.From, c.Window.To) {
		return false
	}
	if _, ok := c.slotWindowEnd(slot); !ok {
		return false
	}
	return first || c.Schedule.Frequency == "daily" || isoDay(slot) == c.Schedule.Weekday
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

// Checks is the part of the settings every LAN engine shares since #850 (INV-16): the window, the check rate and the exclusions.
type Checks struct {
	Window     Window
	Rate       int // requests per second
	Exclusions []string
	// MergedFrom names the copy of this module (scan_setting) the inventory last took in, by that copy's updated_at ("" for a copy
	// nobody saved); nil when it never took one in. While the copy's updated_at is not exactly that (a failed merge, or a version
	// before #850 that wrote it after a rollback), settings reads the union of both lists and the slower rate, so nothing either list
	// excludes is scanned (review #857 M1; equality only, no clock order: r2 L1). On SaveChecks it is the stamp the save wrote.
	MergedFrom *string
	// Version names the shared block as read (Checks); on SaveChecks it is the one the page read ("" = none: no check), and another
	// one refuses the save with 409 safety_changed (review #860 M1).
	Version string
}

// SharedChecks is the inventory as the one store of Checks (#850, INV-16). The Inventory adapter of cmd/vedette implements it; an
// Inventory without it (the module's own tests) leaves them in scan_setting, as before.
type SharedChecks interface {
	Checks(ctx context.Context) (Checks, error)
	// SaveChecks writes them inside tx, the transaction of PUT /scans/config; Settle is called once tx is over, with whether it
	// committed (the inventory announces inventory.settings.changed then).
	SaveChecks(ctx context.Context, tx *sql.Tx, user string, c Checks) error
	Settle(ctx context.Context, tx *sql.Tx, committed bool)
}

func (s *Service) shared() (SharedChecks, bool) {
	sc, ok := s.cfg.Inventory.(SharedChecks)
	return sc, ok
}

// settings is scan_setting with the shared window, check rate and exclusions of the inventory over it (INV-16). scan_setting keeps
// its own copy (written along by SaveConfig) so a rollback to a version before #850 finds the values of PUT /scans/config.
func (s *Service) settings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Settings, error) {
	c, err := loadSettings(ctx, q)
	if err != nil {
		return Settings{}, err
	}
	sh, ok := s.shared()
	if !ok {
		return c, nil
	}
	ch, err := sh.Checks(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("scan: reading the shared window, rate and exclusions: %w", err)
	}
	var updated sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT updated_at FROM scan_setting WHERE id = 1`).Scan(&updated); err != nil {
		return Settings{}, fmt.Errorf("scan: reading when the settings were saved: %w", err)
	}
	own := c
	c.Version = ch.Version
	c.Window = Window{Days: slices.Clone(ch.Window.Days), From: ch.Window.From, To: ch.Window.To}
	c.Rate = ch.Rate
	c.Exclusions = slices.Clone(ch.Exclusions)
	if ch.MergedFrom == nil || *ch.MergedFrom != updated.String { // not this copy taken in: both lists bind, the slower rate wins
		for _, x := range own.Exclusions {
			if !slices.Contains(c.Exclusions, x) {
				c.Exclusions = append(c.Exclusions, x)
			}
		}
		c.Rate = min(c.Rate, own.Rate)
	}
	if c.Exclusions == nil {
		c.Exclusions = []string{}
	}
	return c, nil
}

// LegacyChecks reads scan_setting's own window, rate and exclusions, who saved them last and when ("" when nobody did): what the
// merge into the inventory reads at every start (#850, cmd/vedette).
func LegacyChecks(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (c Checks, savedBy, savedAt string, err error) {
	st, err := loadSettings(ctx, q)
	if err != nil {
		return Checks{}, "", "", err
	}
	var by, at sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT updated_by, updated_at FROM scan_setting WHERE id = 1`).Scan(&by, &at); err != nil {
		return Checks{}, "", "", fmt.Errorf("scan: reading who saved the settings: %w", err)
	}
	return Checks{Window: st.Window, Rate: st.Rate, Exclusions: st.Exclusions}, by.String, at.String, nil
}

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
