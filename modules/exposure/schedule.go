package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The scan schedule of a target (INV-36): each target is scanned by itself daily, weekly (the default, also of every target that
// existed before the schedule) or monthly, or only when a person presses Scan now (off). A scheduled scan is the same scan as Scan
// now (the same steps; OpenVAS joins only while it is turned on, greenbonePlan), run as the box (SystemUser), only while the target's
// ownership proof holds and its testing terms (and so its commitment) of the current version are accepted, and only inside the scan
// window of the shared safety block (Settings, Scanning, Safety). It waits in the box's one queue like any other scan (queue.go).
// Its next run is computed from the start of the newest scan of the target (exp_target.last_scan_at, any scan: a Scan now resets it),
// so a restart loses nothing.

// Every is how often a target is scanned by its schedule.
type Every string

// The values of exp_target.scan_every.
const (
	EveryOff     Every = "off"
	EveryDaily   Every = "daily"
	EveryWeekly  Every = "weekly"
	EveryMonthly Every = "monthly"
)

// valid says whether e is one of the four values.
func (e Every) valid() bool {
	return slices.Contains([]Every{EveryOff, EveryDaily, EveryWeekly, EveryMonthly}, e)
}

// after is the time one period after base, counted in the calendar of loc (a month is a calendar month).
func (e Every) after(base time.Time, loc *time.Location) time.Time {
	b := base.In(loc)
	switch e {
	case EveryDaily:
		return b.AddDate(0, 0, 1)
	case EveryWeekly:
		return b.AddDate(0, 0, 7)
	case EveryMonthly:
		return b.AddDate(0, 1, 0)
	}
	return time.Time{}
}

// ScheduleTick is how often the scan-schedule job wakes up to see whether a target is due; most wake-ups do nothing.
const ScheduleTick = time.Minute

// ScheduleRetry is how long the schedule waits before it tries a target again after the scan gate refused it right before the scan
// (the TXT record or the proof not found, the box no longer going out through the IP, the address excluded): those checks ask the
// network, so they are not repeated every minute.
const ScheduleRetry = 6 * time.Hour

// ScheduleView is the schedule of a target as the page sees it (contract.ts ScanSchedule).
type ScheduleView struct {
	Every Every `json:"every"`
	// NextAt is when the next scheduled scan is expected to start: when it is due, moved to the next opening of the scan window; nil
	// when the schedule is off or the target cannot be scanned on schedule now (Note says why).
	NextAt *string `json:"next_at"`
	// Note says why the target is not scanned on schedule ("Not scanned on schedule: terms need confirming again"); nil otherwise.
	Note *string `json:"note"`
}

// schedState is the stored schedule of a target.
type schedState struct {
	every   Every
	skip    string    // why the last due scheduled scan was not run; "" none
	skipAt  time.Time // when that was decided
	retryAt time.Time // the earliest next try after a skip the gate decided; zero for none
}

func loadSchedules(ctx context.Context, q querier) (map[string]schedState, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, scan_every, sched_skip, sched_skip_at, sched_retry_at FROM exp_target`)
	if err != nil {
		return nil, fmt.Errorf("scan schedules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]schedState{}
	for rows.Next() {
		var id, every string
		var skip, skipAt, retryAt sql.NullString
		if err := rows.Scan(&id, &every, &skip, &skipAt, &retryAt); err != nil {
			return nil, fmt.Errorf("scan schedules: %w", err)
		}
		st := schedState{every: Every(every), skip: skip.String}
		if st.skipAt, err = optTS(skipAt); err != nil {
			return nil, fmt.Errorf("scan schedule of %s: %w", id, err)
		}
		if st.retryAt, err = optTS(retryAt); err != nil {
			return nil, fmt.Errorf("scan schedule of %s: %w", id, err)
		}
		out[id] = st
	}
	return out, rows.Err()
}

// due is when the next scheduled scan of t is due: one period after the start of its newest scan (now when it was never scanned),
// and not before the retry time of a skip the gate decided after that scan. Zero when the schedule is off.
func (st schedState) due(t Target, loc *time.Location, now time.Time) time.Time {
	if st.every == EveryOff || !st.every.valid() {
		return time.Time{}
	}
	at := now
	if !t.LastScanAt.IsZero() {
		at = st.every.after(clampTS(t.LastScanAt, now), loc)
	}
	if !st.retryAt.IsZero() && st.skipAt.After(t.LastScanAt) && st.retryAt.After(at) {
		at = st.retryAt
	}
	return at.UTC()
}

// scheduleWhy is why t cannot be scanned on schedule judged from what is stored, without asking the network; "" when the schedule may
// try it (the gate still checks the TXT record, the proof and the box's IP right before the scan). A scheduled scan is always a scan
// under accepted testing terms: they are the person's consent to scans the box starts by itself.
func scheduleWhy(t Target, now time.Time) string {
	switch t.blocked(now) {
	case BlockedUnverified:
		return "ownership is not proved"
	case BlockedExpired:
		return "the ownership proof expired"
	}
	if !t.Commitment.current() || !t.mode().Full {
		if t.Terms == nil {
			return "the testing terms are not accepted"
		}
		return "terms need confirming again"
	}
	return ""
}

// gateWhy is the short reason of a refusal of the gate right before a scheduled scan.
func gateWhy(t Target, r BlockedReason, now time.Time) string {
	switch r {
	case BlockedTxtMissing:
		return "the DNS TXT record was not found right before the scan"
	case BlockedProofMissing:
		return "the proof was not found right before the scan"
	case BlockedNotCurrent:
		return "the box no longer goes out through this IP"
	}
	if why := scheduleWhy(t, now); why != "" {
		return why
	}
	return "it could not be scanned (" + string(r) + ")"
}

// scheduleNote is the sentence the page shows when a target is not scanned on schedule.
func scheduleNote(why string) *string {
	if why == "" {
		return nil
	}
	n := "Not scanned on schedule: " + why
	return &n
}

// Window is the scan window of the shared safety block: the days of the week (1 Monday to 7 Sunday) and the hours ("HH:MM") between
// which the box may start a scan by itself. A window whose To is not after its From crosses midnight and counts by its start day.
type Window struct {
	Days     []int
	From, To string
}

// ScanWindow reads the scan window now (cmd/vedette: the inventory's shared block). An error means it could not be read: no scheduled
// scan starts.
type ScanWindow interface {
	ScanWindow(ctx context.Context) (Window, error)
}

// hhmm is the minute of the day of "HH:MM"; ok is false for anything else.
func hhmm(v string) (int, bool) {
	t, err := time.Parse("15:04", v)
	if err != nil || len(v) != 5 {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

// usable says whether the window can ever open: at least one day and two times.
func (w Window) usable() bool {
	_, okF := hhmm(w.From)
	_, okT := hhmm(w.To)
	return okF && okT && slices.ContainsFunc(w.Days, func(d int) bool { return d >= 1 && d <= 7 })
}

func isoWeekday(t time.Time) int {
	if d := int(t.Weekday()); d != 0 {
		return d
	}
	return 7
}

// open says whether the window holds at, in loc.
func (w Window) open(at time.Time, loc *time.Location) bool {
	f, okF := hhmm(w.From)
	to, okT := hhmm(w.To)
	if !okF || !okT {
		return false
	}
	l := at.In(loc)
	m := l.Hour()*60 + l.Minute()
	today := slices.Contains(w.Days, isoWeekday(l))
	if f < to {
		return today && m >= f && m < to
	}
	yesterday := slices.Contains(w.Days, isoWeekday(l.AddDate(0, 0, -1))) // the part after midnight is the day before's window
	return (today && m >= f) || (yesterday && m < to)
}

// nextOpen is the first moment at or after `after` at which the window holds, in loc; ok is false when it never opens.
func (w Window) nextOpen(after time.Time, loc *time.Location) (time.Time, bool) {
	if !w.usable() {
		return time.Time{}, false
	}
	if w.open(after, loc) {
		return after, true
	}
	f, _ := hhmm(w.From)
	l := after.In(loc)
	for i := range 9 {
		d := time.Date(l.Year(), l.Month(), l.Day()+i, f/60, f%60, 0, 0, loc)
		if d.After(after) && slices.Contains(w.Days, isoWeekday(d)) {
			return d, true
		}
	}
	return time.Time{}, false
}

// window reads the scan window; without a ScanWindow (tests, an older wiring) it is always open.
func (s *Service) window(ctx context.Context) (Window, error) {
	if s.cfg.Window == nil {
		return Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "00:00", To: "00:00"}, nil
	}
	return s.cfg.Window.ScanWindow(ctx)
}

// notWindowRead and notWindowDays are the notes of a schedule the scan window stops.
const (
	notWindowRead = "the scan window under Settings, Scanning, Safety could not be read"
	notWindowDays = "the scan window under Settings, Scanning, Safety has no day or time"
)

// scheduleViews sets the schedule of every view (one read of the schedules and of the window).
func (s *Service) scheduleViews(ctx context.Context, q querier, ts []Target, views []TargetView, c checks) error {
	states, err := loadSchedules(ctx, q)
	if err != nil {
		return err
	}
	var win Window
	var winErr error
	read := false
	byID := map[string]Target{}
	for _, t := range ts {
		byID[t.ID] = t
	}
	loc := s.loc()
	for i := range views {
		t, ok := byID[views[i].ID]
		if !ok {
			continue
		}
		st := states[t.ID]
		if !st.every.valid() {
			st.every = EveryWeekly
		}
		v := &ScheduleView{Every: st.every}
		views[i].Schedule = v
		if st.every == EveryOff {
			continue
		}
		why := scheduleWhy(t, c.now)
		if why == "" && t.Kind == KindIP && !t.Typed && c.paused(t) {
			why = gateWhy(t, BlockedNotCurrent, c.now)
		}
		if why != "" { // nothing is tried until that changes: no next time
			v.Note = scheduleNote(why)
			continue
		}
		if st.skip != "" && !st.retryAt.IsZero() && st.skipAt.After(t.LastScanAt) {
			v.Note = scheduleNote(st.skip) // the gate refused the last due scan: the schedule tries again at NextAt
		}
		if !read {
			win, winErr = s.window(ctx)
			read = true
		}
		due := st.due(t, loc, c.now)
		if due.Before(c.now) {
			due = c.now
		}
		switch at, ok := win.nextOpen(due, loc); {
		case winErr != nil:
			v.Note = scheduleNote(notWindowRead)
		case !ok:
			v.Note = scheduleNote(notWindowDays)
		default:
			x := store.FormatTS(at.UTC().Truncate(time.Millisecond))
			v.NextAt = &x
		}
	}
	return nil
}

// SetSchedule sets how often target id is scanned by itself (PUT /exposure/targets/{id}/schedule, admin), audited as
// exposure.schedule with the old and new value. Setting the same value changes nothing.
func (s *Service) SetSchedule(ctx context.Context, user, id string, every Every) (TargetView, error) {
	if !every.valid() {
		return TargetView{}, apiErr(400, "bad_value", "Choose Off, Daily, Weekly or Monthly.")
	}
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT scan_every FROM exp_target WHERE id = ?`, id).Scan(&old); err != nil {
			return fmt.Errorf("reading the schedule: %w", err)
		}
		if Every(old) == every {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET scan_every = ?, sched_skip = NULL, sched_skip_at = NULL, sched_retry_at = NULL WHERE id = ?`, string(every), id); err != nil {
			return fmt.Errorf("saving the schedule: %w", err)
		}
		return s.audit(ctx, tx, user, "exposure.schedule", t.Value, fmt.Sprintf("%s (was %s)", every, old))
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: setting the scan schedule: %w", err)
	}
	if every == EveryOff { // a scheduled scan of it that waits in the queue does not run any more
		s.dropScheduled(id)
	}
	return s.Target(ctx, id)
}

// noteSkip stores why the due scheduled scan of t was not run, with its audit row: a reason judged from what is stored is looked at
// every tick and written only when it is new since the target's newest scan; a refusal of the gate (retry) is written each time and
// also sets when the schedule tries again.
func (s *Service) noteSkip(ctx context.Context, t Target, st schedState, why string, retry bool) {
	if !retry && st.skip == why && st.skipAt.After(t.LastScanAt) {
		return
	}
	now := s.clock()
	var retryAt any
	if retry {
		retryAt = store.FormatTS(now.Add(ScheduleRetry))
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		res, err := tx.ExecContext(wctx, `UPDATE exp_target SET sched_skip = ?, sched_skip_at = ?, sched_retry_at = ? WHERE id = ?`, clipText(why, 1000), store.FormatTS(now), retryAt, t.ID)
		if err != nil {
			return fmt.Errorf("noting a skipped scheduled scan: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // deleted meanwhile
		}
		return s.audit(wctx, tx, SystemUser, "exposure.scan", t.Value, "scheduled scan not done: "+why)
	})
	if err != nil {
		s.cfg.Log.ErrorContext(wctx, "exposure: noting a skipped scheduled scan failed", "target", t.Value, "error", err)
	}
}

// RunSchedule is the body of the scan-schedule job (INV-36): every target whose scheduled scan is due, whose stored state allows it
// and whose scan window is open now joins the box's queue (a target already queued or scanned now is left alone); a target that is due
// but cannot be scanned on schedule gets its reason stored once. Then the queue is started. The job fails only on a failure of the box.
func (s *Service) RunSchedule(ctx context.Context) error {
	db := s.cfg.DB.Reader()
	ts, err := listTargets(ctx, db)
	if err != nil {
		return fmt.Errorf("exposure: scan schedule: %w", err)
	}
	states, err := loadSchedules(ctx, db)
	if err != nil {
		return fmt.Errorf("exposure: scan schedule: %w", err)
	}
	now, loc := s.clock(), s.loc()
	var win Window
	read := false
	for _, t := range ts {
		st, ok := states[t.ID]
		if !ok || st.every == EveryOff || !st.every.valid() {
			continue
		}
		due := st.due(t, loc, now)
		if due.After(now) || s.inQueue(t.ID) {
			continue
		}
		if why := scheduleWhy(t, now); why != "" {
			s.noteSkip(ctx, t, st, why, false)
			continue
		}
		if !read {
			if win, err = s.window(ctx); err != nil {
				s.cfg.Log.WarnContext(ctx, "exposure: the scan window could not be read; no scheduled scan starts", "error", err)
				return nil
			}
			read = true
		}
		if !win.open(now, loc) {
			continue
		}
		s.enqueue(&queuedScan{targetID: t.ID, value: t.Value, by: SystemUser, scheduled: true, state: st})
	}
	s.dispatch()
	return nil
}

// errOutsideWindow: the window closed while a scheduled scan waited in the queue; it is left for the next opening, with no note.
var errOutsideWindow = errors.New("exposure: the scan window is closed")
