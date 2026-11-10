package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// Job timing.
const (
	// JobTick is how often the schedule and the KEV rescans are looked at: well inside the 60 minutes of S-SCAN-2.
	JobTick = time.Minute
	// rescanSettle lets the inventory and findings match a new KEV entry first (the same event makes the findings).
	rescanSettle = time.Minute
	// pendingFor is how long a KEV event waits for its template to reach the installed pack before it is dropped.
	pendingFor = 7 * 24 * time.Hour
	// rescanPage is how many waiting events one pass of the rescan job looks at, oldest first; the rest wait for the
	// next minute (#164 review L1).
	rescanPage = 100
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
	product := plainLine(ev.Vendor+" "+ev.Product, 300) // from a feed: untrusted text (SYS-6, #164 review L5)
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO scan_event (id, ts, cve, product) VALUES (?, ?, ?, ?) ON CONFLICT (cve) DO NOTHING`,
			store.NewID("ev"), store.FormatTS(s.now()), ev.CVE, product)
		return err
	})
}

// plainLine is untrusted text (a feed's vendor and product) as one plain line: valid UTF-8, no control, format or bidi
// characters (nucleiout.Clean), spaces and line breaks collapsed, at most n characters.
func plainLine(s string, n int) string {
	return clip(strings.Join(strings.Fields(nucleiout.Clean(s, 4*n)), " "), n)
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
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// One bad event does not hold up the queue (#164 review L2): it is logged and tried again next minute.
			s.cfg.Log.ErrorContext(ctx, "scan: a KEV rescan event failed", "event", ev.id, "cve", ev.cve, "error", err)
		}
	}
	return nil
}

func (s *Service) pendingEvents(ctx context.Context) ([]pendingEvent, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, cve, coalesce(run_id, ''), ts FROM scan_event WHERE result IS NULL ORDER BY ts LIMIT ?`, rescanPage)
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
	expired := now.Sub(ev.ts) > pendingFor
	if s.cfg.Pack == nil || len(s.cfg.Pack.ForCVE(ev.cve)) == 0 {
		if expired {
			return s.dropEvent(ctx, ev, "its scan template never reached the installed pack")
		}
		return nil
	}
	// Wait first, before reading every finding and device (#164 review L1): try again at the next tick, still inside
	// the 60 minutes, or when the scanner is back; a scanner that never comes back drops the event like a template
	// that never comes (#164 review L3).
	if s.liveRun() != "" {
		return nil
	}
	if !s.scannerReady(ctx) {
		if expired {
			return s.dropEvent(ctx, ev, "the scanner was not ready for 7 days")
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
	latency := now.Sub(ev.ts).Minutes()
	b, err := json.Marshal(names)
	if err != nil {
		return fmt.Errorf("scan: encoding the devices of a rescan: %w", err)
	}
	// The event is linked in the transaction that writes the run (#164 review L4): no run the event does not know of,
	// which the next pass would start again.
	link := func(ctx context.Context, tx *sql.Tx, runID string) error {
		res, err := tx.ExecContext(ctx, `UPDATE scan_event SET run_id = ?, latency_min = ?, devices = ? WHERE id = ? AND run_id IS NULL`, runID, latency, string(b), ev.id)
		if err != nil {
			return fmt.Errorf("scan: linking the rescan event: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("scan: linking the rescan event: %w", err)
		}
		if n != 1 {
			return fmt.Errorf("scan: the rescan event %s is gone or already has a run", ev.id)
		}
		return nil
	}
	note := "New KEV entry with a scan template: " + ev.cve
	if _, err := s.startAuto(ctx, "new_kev", &note, ids, first, ev.cve, time.Time{}, link); err != nil && !errors.Is(err, errRunning) {
		return err
	}
	return nil
}

// dropEvent removes an event that waited pendingFor without a scan, and says why in the log. The scheduled scan still
// covers the CVE's devices.
func (s *Service) dropEvent(ctx context.Context, ev pendingEvent, why string) error {
	s.cfg.Log.WarnContext(ctx, "scan: a KEV rescan was dropped after 7 days", "cve", ev.cve, "reason", why)
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM scan_event WHERE id = ?`, ev.id)
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
// the window of a scheduled run); inTx records what the run is for in the transaction of its row (runSpec.inTx).
func (s *Service) startAuto(ctx context.Context, trigger string, note *string, ids []string, first Current, onlyCVE string, end time.Time,
	inTx func(ctx context.Context, tx *sql.Tx, runID string) error) (RunView, error) {
	return s.start(ctx, runSpec{trigger: trigger, note: note, user: systemUser, ids: ids, first: first, onlyCVE: onlyCVE, end: end, inTx: inTx})
}

// RunSchedule starts the scheduled run of the latest slot while that slot's own window is open (S-SCAN-4, POST-3);
// the run stops when that window ends. A slot that found a scan running, or the scanner not ready, is tried again at
// the next tick while its window is open; once the window has closed the slot is recorded as missed, never run late
// in a later window (#164 review M1). A slot starts at most one run.
func (s *Service) RunSchedule(ctx context.Context) error {
	var last, saved sql.NullString
	row := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT sched_last, updated_at FROM scan_setting WHERE id = 1`)
	if err := row.Scan(&last, &saved); err != nil {
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
	end, _ := st.slotWindowEnd(*slot)
	if !now.Before(end) {
		// A slot from before the schedule was last saved (turned on, moved) was never due: it is passed over quietly.
		return s.missSlot(ctx, *slot, !saved.Valid || saved.String < store.FormatTS(*slot))
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
	if len(ids) == 0 { // nothing may be scanned without a pick: the slot is done
		return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return markSlot(ctx, tx, *slot) })
	}
	// The slot is recorded in the transaction that writes its run (#164 review L4): a failure leaves neither, so a slot
	// never has a run and still looks open. A start refused because a run or the engine is busy leaves the slot open
	// for the next tick while its window lasts.
	mark := func(ctx context.Context, tx *sql.Tx, _ string) error { return markSlot(ctx, tx, *slot) }
	if _, err := s.startAuto(ctx, "schedule", nil, ids, first, "", end, mark); err != nil && !errors.Is(err, errRunning) {
		return err
	}
	return nil
}

func markSlot(ctx context.Context, tx *sql.Tx, slot time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE scan_setting SET sched_last = ? WHERE id = 1`, store.FormatTS(slot))
	return err
}

// missSlot records a slot whose window closed before its run could start, with an audit row when it was due.
func (s *Service) missSlot(ctx context.Context, slot time.Time, due bool) error {
	ts := store.FormatTS(slot)
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := markSlot(ctx, tx, slot); err != nil {
			return err
		}
		if !due {
			return nil
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: systemUser, Action: "scan.schedule.missed", Target: "scan",
			Detail: "the scheduled run of " + ts + " did not start before its window closed; the next slot runs as planned"})
	})
}

// lastSlot is the latest slot of the schedule at or before now (within eight days), or nil when the schedule is off.
func (c Settings) lastSlot(now time.Time, loc *time.Location) *time.Time {
	if !c.Schedule.Enabled || !hhmmRE.MatchString(c.Schedule.At) {
		return nil
	}
	at := minutes(c.Schedule.At)
	local := now.In(loc)
	for i := range 8 {
		d := time.Date(local.Year(), local.Month(), local.Day()-i, at/60, at%60, 0, 0, loc)
		if !d.After(now) && c.slotOK(d) {
			return &d
		}
	}
	return nil
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
