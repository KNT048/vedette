package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// Job timing.
const (
	// JobTick is how often the schedule and the KEV rescans are looked at: well inside the 60 minutes of S-SCAN-2.
	JobTick = time.Minute
	// rescanSettle lets the inventory and findings match a new KEV entry first (the same event makes the findings).
	rescanSettle = time.Minute
	// pendingFor is how long a KEV event waits for its template to reach the installed pack before it is dropped.
	pendingFor = 7 * 24 * time.Hour
	// eventRetention keeps the rescan log one year (DATA_MODEL [ĐX]).
	eventRetention = 365 * 24 * time.Hour
	systemUser     = "system"
)

const noteWindowEnded = "The scan window ended; the devices not reached are scanned at the next scheduled run."

// Jobs are the module's background work; core/jobs runs them only while the module is on (SYS-5).
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "rescan", Every: JobTick, Run: svc.RunRescans},
		{Module: ModuleID, Name: "schedule", Every: JobTick, Run: svc.RunSchedule},
		{Module: ModuleID, Name: "retention", Every: time.Hour, Run: svc.RunRetention},
		{Module: ModuleID, Name: "recover", Every: RecoverEvery, Run: svc.RunRecover},
	}
}

// NewKEV is what scan needs of feeds.vuln.new_kev.
type NewKEV struct {
	CVE         string
	Vendor      string
	Product     string
	HasTemplate bool
}

// OnNewKEV records a new KEV entry that has a scan template, for the rescan job (PRE-4). The handler only writes a
// row: the bus gives it 5 seconds, a scan takes longer.
func (s *Service) OnNewKEV(ctx context.Context, ev NewKEV) error {
	if !ev.HasTemplate || !validCVE(ev.CVE) {
		return nil
	}
	product := clip(ev.Vendor+" "+ev.Product, 300)
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO scan_event (id, ts, cve, product) VALUES (?, ?, ?, ?) ON CONFLICT (cve) DO NOTHING`,
			store.NewID("ev"), store.FormatTS(s.now()), ev.CVE, product)
		return err
	})
}

func validCVE(c string) bool {
	if len(c) < 13 || len(c) > 20 || c[:4] != "CVE-" || c[8] != '-' {
		return false
	}
	for i, r := range c[4:] {
		if i == 4 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type pendingEvent struct {
	id, cve, runID string
	ts             time.Time
}

// RunRescans moves every pending KEV event on (INV-9, POST-4): auto rescan off → skipped_off; no device with an
// open finding for the CVE that may be scanned without a pick → no_match; otherwise one new_kev run with only that
// CVE's templates, outside the time window (D-126 (3)); when the run has ended → matched or clear.
func (s *Service) RunRescans(ctx context.Context) error {
	if err := s.reapOrphan(ctx); err != nil {
		return err
	}
	evs, err := s.pendingEvents(ctx)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		if err := s.rescan(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) pendingEvents(ctx context.Context) ([]pendingEvent, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, cve, coalesce(run_id, ''), ts FROM scan_event WHERE result IS NULL ORDER BY ts`)
	if err != nil {
		return nil, fmt.Errorf("scan: reading the rescan queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []pendingEvent
	for rows.Next() {
		var e pendingEvent
		var ts string
		if err := rows.Scan(&e.id, &e.cve, &e.runID, &ts); err != nil {
			return nil, err
		}
		if e.ts, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return nil, fmt.Errorf("scan: reading the rescan queue: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) closeEvent(ctx context.Context, id, result string, devices []string, runID *string, latency *float64) error {
	if devices == nil {
		devices = []string{}
	}
	b, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_event SET result = ?, devices = ?, run_id = coalesce(?, run_id), latency_min = coalesce(?, latency_min) WHERE id = ?`,
			result, string(b), runID, latency, id)
		return err
	})
}

func (s *Service) rescan(ctx context.Context, ev pendingEvent) error {
	if ev.runID != "" { // the run is under way or over
		v, err := s.Run(ctx, ev.runID)
		if err != nil {
			return err
		}
		if v.Status == "running" || v.Status == "stopping" {
			return nil
		}
		// "clear" means only that no match was reported (D-133 (5)), never "not affected"; it changes no finding.
		result := "clear"
		if v.Matched > 0 {
			result = "matched"
		}
		return s.closeEvent(ctx, ev.id, result, labels(v.Results), nil, nil)
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return err
	}
	if !st.AutoRescan {
		return s.closeEvent(ctx, ev.id, "skipped_off", nil, nil, nil)
	}
	now := s.now()
	if now.Sub(ev.ts) < rescanSettle {
		return nil
	}
	if s.cfg.Pack == nil || len(s.cfg.Pack.ForCVE(ev.cve)) == 0 {
		if now.Sub(ev.ts) > pendingFor { // the template never reached the installed pack
			return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `DELETE FROM scan_event WHERE id = ?`, ev.id)
				return err
			})
		}
		return nil
	}
	ids, names, first, err := s.affected(ctx, st, ev.cve)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return s.closeEvent(ctx, ev.id, "no_match", nil, nil, nil)
	}
	if s.liveRun() != "" || !s.scannerReady(ctx) {
		return nil // try again at the next tick: still inside the 60 minutes, or the scanner is back
	}
	note := "New KEV entry with a scan template: " + ev.cve
	v, err := s.startAuto(ctx, "new_kev", &note, ids, first, ev.cve, time.Time{})
	if errors.Is(err, errRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	latency := now.Sub(ev.ts).Minutes()
	b, err := json.Marshal(names)
	if err != nil {
		return fmt.Errorf("scan: encoding the devices of a rescan: %w", err)
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_event SET run_id = ?, latency_min = ?, devices = ? WHERE id = ?`, v.ID, latency, string(b), ev.id)
		return err
	})
}

// affected are the devices with an open finding for cve that may be scanned without a pick (D-126 (2)).
func (s *Service) affected(ctx context.Context, st Settings, cve string) (ids, names []string, first Current, err error) {
	if s.cfg.Findings == nil {
		return nil, nil, Current{}, nil
	}
	fs, err := s.cfg.Findings.List(ctx, "")
	if err != nil {
		return nil, nil, Current{}, fmt.Errorf("scan: reading the findings: %w", err)
	}
	devs, err := s.devicesByID(ctx)
	if err != nil {
		return nil, nil, Current{}, err
	}
	for _, f := range fs {
		if f.CVE != cve || (f.Status != "suspected" && f.Status != "confirmed") || slices.Contains(ids, f.AssetID) {
			continue
		}
		d, ok := devs[f.AssetID]
		if !ok {
			continue
		}
		why, _, err := s.consent(ctx, st, d, false)
		if err != nil {
			return nil, nil, Current{}, err
		}
		if why != "" || len(ids) == MaxRunTargets {
			continue
		}
		if len(ids) == 0 {
			first = Current{Label: d.Label, IP: d.IP}
		}
		ids, names = append(ids, d.ID), append(names, d.Label)
	}
	return ids, names, first, nil
}

func labels(rows []RunRow) []string {
	var out []string
	for _, r := range rows {
		if !slices.Contains(out, r.Label) {
			out = append(out, r.Label)
		}
	}
	return out
}

// startAuto starts a run nobody picked: schedule or new_kev. Devices are checked with explicit=false (D-126 (2)).
// onlyCVE limits the run to one CVE (the KEV rescan); end, when set, is where the run stops by itself (the end of
// the window of a scheduled run).
func (s *Service) startAuto(ctx context.Context, trigger string, note *string, ids []string, first Current, onlyCVE string, end time.Time) (RunView, error) {
	return s.start(ctx, runSpec{trigger: trigger, note: note, user: systemUser, ids: ids, first: first, onlyCVE: onlyCVE, end: end})
}

// RunSchedule starts the scheduled run when its slot has come and the window is open (S-SCAN-4, POST-3). The run
// stops when the window ends. A slot that found a scan running is tried again at the next tick while the window
// is still open; it starts at most one run.
func (s *Service) RunSchedule(ctx context.Context) error {
	var last sql.NullString
	row := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT sched_last FROM scan_setting WHERE id = 1`)
	if err := row.Scan(&last); err != nil {
		return fmt.Errorf("scan: reading the schedule: %w", err)
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return err
	}
	now := s.now()
	slot := st.lastSlot(now, s.loc(ctx))
	if slot == nil || (last.Valid && last.String >= store.FormatTS(*slot)) {
		return nil
	}
	end, open := st.windowEnd(now, s.loc(ctx))
	if !open {
		return nil
	}
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil || sc.ConfirmedAt == "" || s.liveRun() != "" || !s.scannerReady(ctx) {
		return err
	}
	devs, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return err
	}
	var ids []string
	var first Current
	for _, d := range devs {
		why, _, err := s.consent(ctx, st, d, false)
		if err != nil {
			return err
		}
		if why != "" || len(ids) == MaxRunTargets {
			continue
		}
		if len(ids) == 0 {
			first = Current{Label: d.Label, IP: d.IP}
		}
		ids = append(ids, d.ID)
	}
	if len(ids) > 0 {
		if _, err := s.startAuto(ctx, "schedule", nil, ids, first, "", end); err != nil && !errors.Is(err, errRunning) {
			return err
		}
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_setting SET sched_last = ? WHERE id = 1`, store.FormatTS(*slot))
		return err
	})
}

// lastSlot is the latest schedule time at or before now (within eight days), or nil when the schedule is off.
func (c Settings) lastSlot(now time.Time, loc *time.Location) *time.Time {
	if !c.Schedule.Enabled || !hhmmRE.MatchString(c.Schedule.At) {
		return nil
	}
	at := minutes(c.Schedule.At)
	local := now.In(loc)
	for i := range 8 {
		d := time.Date(local.Year(), local.Month(), local.Day()-i, at/60, at%60, 0, 0, loc)
		if d.After(now) || !slices.Contains(c.Window.Days, isoDay(d)) {
			continue
		}
		if c.Schedule.Frequency == "daily" || isoDay(d) == c.Schedule.Weekday {
			return &d
		}
	}
	return nil
}

// windowEnd says whether the window is open at now, and when it closes. A window that crosses midnight counts by
// its start day (the GUI's words): 22:00 to 05:00 on Monday runs until Tuesday 05:00.
func (c Settings) windowEnd(now time.Time, loc *time.Location) (time.Time, bool) {
	l := now.In(loc)
	m := l.Hour()*60 + l.Minute()
	from, to := minutes(c.Window.From), minutes(c.Window.To)
	day := func(offset, mins int) time.Time {
		return time.Date(l.Year(), l.Month(), l.Day()+offset, mins/60, mins%60, 0, 0, loc)
	}
	today := slices.Contains(c.Window.Days, isoDay(l))
	if from < to {
		return day(0, to), today && m >= from && m < to
	}
	if today && m >= from {
		return day(1, to), true
	}
	yesterday := slices.Contains(c.Window.Days, isoDay(l.AddDate(0, 0, -1)))
	return day(0, to), yesterday && m < to
}

// RunRetention deletes probe rows older than RetentionDays and rescan events older than a year (INV-7).
func (s *Service) RunRetention(ctx context.Context) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM scan_probe WHERE ts < ? AND result IS NOT NULL`, store.FormatTS(now.Add(-RetentionDays*24*time.Hour))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM scan_event WHERE ts < ? AND result IS NOT NULL`, store.FormatTS(now.Add(-eventRetention)))
		return err
	})
}

// EventView is contract.ts RescanEvent.
type EventView struct {
	ID         string   `json:"id"`
	TS         string   `json:"ts"`
	CVE        string   `json:"cve"`
	Product    string   `json:"product"`
	Devices    []string `json:"devices"`
	LatencyMin *float64 `json:"latency_min"`
	RunID      *string  `json:"run_id"`
	Result     string   `json:"result"`
}

// Events is the rescan log, newest first (S-SCAN-2). Events still waiting or running are not listed yet.
func (s *Service) Events(ctx context.Context) ([]EventView, bool, error) {
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, false, err
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, ts, cve, product, devices, latency_min, run_id, result FROM scan_event
WHERE result IS NOT NULL ORDER BY ts DESC LIMIT 1000`)
	if err != nil {
		return nil, false, fmt.Errorf("scan: reading the rescan log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []EventView{}
	for rows.Next() {
		var v EventView
		var devs string
		if err := rows.Scan(&v.ID, &v.TS, &v.CVE, &v.Product, &devs, &v.LatencyMin, &v.RunID, &v.Result); err != nil {
			return nil, false, err
		}
		if err := json.Unmarshal([]byte(devs), &v.Devices); err != nil {
			return nil, false, err
		}
		if v.Devices == nil {
			v.Devices = []string{}
		}
		out = append(out, v)
	}
	return out, st.AutoRescan, rows.Err()
}

// RecoverEvery is how often the recover job looks for a run a restart left live. core/jobs runs a job as soon as its
// module is on, so after a restart the run is closed at once; later passes are cheap.
const RecoverEvery = 10 * time.Minute

// RunRecover closes a run the database says is live while this process runs none (review M4): it shows stopped and
// its open probe rows are closed (INV-7).
func (s *Service) RunRecover(ctx context.Context) error { return s.reapOrphan(ctx) }

// Close stops the live run and waits for it to end, at most the time a stopped run needs (review M4). Called when
// Vedette shuts down; the run ends as stopped with the reason.
func (s *Service) Close() {
	s.closing.Store(true)
	s.mu.Lock()
	l := s.live
	s.mu.Unlock()
	if l == nil {
		return
	}
	l.cancel()
	select {
	case <-l.done:
	case <-time.After(stopGrace + finishTimeout):
		s.cfg.Log.Error("scan: the live run did not stop at shutdown", "run", l.id)
	}
}

// stopReason is why a run ended before its last device: Vedette shut down, the window of a scheduled run closed, or a
// person pressed Stop now.
func (s *Service) stopReason(ctx context.Context) string {
	switch {
	case s.closing.Load():
		return stopShutdown
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return noteWindowEnded
	}
	return stopNow
}
