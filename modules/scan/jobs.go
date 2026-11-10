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
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
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
	// The entries announced while scan was off or down are queued first (S4b, D-144); feeds unreadable does not hold up
	// the queue: the bus events are there, and the next pass reads from the same point.
	if err := s.catchUp(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "scan: catching up on announced KEV entries failed", "error", err)
	}
	evs, err := s.pendingEvents(ctx)
	if err != nil {
		return err
	}
	var batch []readyEvent
	room := nucleiargv.MaxTemplates // the templates the run may still take: a device gets at most this many
	for _, ev := range evs {
		r, err := s.rescan(ctx, ev, room)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// One bad event does not hold up the queue (#164 review L2): it is logged and tried again next minute.
			s.cfg.Log.ErrorContext(ctx, "scan: a KEV rescan event failed", "event", ev.id, "cve", ev.cve, "error", err)
			continue
		}
		if r != nil {
			batch = append(batch, *r)
			room -= r.templates
		}
	}
	if err := s.startRescan(ctx, batch); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "scan: starting a KEV rescan failed", "events", len(batch), "error", err)
	}
	return nil
}

// readyEvent is a waiting KEV event whose devices may be scanned now; the ready events of a pass share one run.
type readyEvent struct {
	ev         pendingEvent
	ids, names []string
	first      Current
	templates  int
	latency    float64
}

// startRescan starts one new_kev run for the events of a pass (S4b: a backlog is not rescanned one CVE at a time):
// their CVEs' templates only, at most MaxRunTargets devices (an event that would go over waits for the next run),
// outside the time window (D-126 (3)). Each event is linked to the run in the transaction that writes it (#164 review
// L4), with its own devices and latency.
func (s *Service) startRescan(ctx context.Context, batch []readyEvent) error {
	var ids, cves []string
	var take []readyEvent
	for _, r := range batch {
		u := ids
		for _, id := range r.ids {
			if !slices.Contains(u, id) {
				u = append(u, id)
			}
		}
		if len(take) > 0 && len(u) > MaxRunTargets {
			continue
		}
		ids, cves, take = u, append(cves, r.ev.cve), append(take, r)
	}
	if len(take) == 0 {
		return nil
	}
	link := func(ctx context.Context, tx *sql.Tx, runID string) error {
		for _, r := range take {
			b, err := json.Marshal(r.names)
			if err != nil {
				return fmt.Errorf("scan: encoding the devices of a rescan: %w", err)
			}
			res, err := tx.ExecContext(ctx, `UPDATE scan_event SET run_id = ?, latency_min = ?, devices = ? WHERE id = ? AND run_id IS NULL`, runID, r.latency, string(b), r.ev.id)
			if err != nil {
				return fmt.Errorf("scan: linking the rescan event: %w", err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("scan: linking the rescan event: %w", err)
			}
			if n != 1 {
				return fmt.Errorf("scan: the rescan event %s is gone or already has a run", r.ev.id)
			}
		}
		return nil
	}
	note := rescanNote(cves)
	if _, err := s.startAuto(ctx, "new_kev", &note, ids, take[0].first, cves, time.Time{}, link); err != nil && !errors.Is(err, errRunning) {
		return err
	}
	return nil
}

// rescanNote is the trigger note of a rescan run: its CVEs, as many as fit the 300 characters of the column.
func rescanNote(cves []string) string {
	if len(cves) == 1 {
		return "New KEV entry with a scan template: " + cves[0]
	}
	note := "New KEV entries with a scan template: " + cves[0]
	for i, c := range cves[1:] {
		more := fmt.Sprintf(" and %d more", len(cves)-1-i)
		if len(note)+2+len(c)+len(more) > 300 {
			return note + more
		}
		note += ", " + c
	}
	return note
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

// closeEvent writes the result of an event; its run, if any, was linked when the run started (runSpec.inTx).
func (s *Service) closeEvent(ctx context.Context, id, result string, devices []string) error {
	var arg any // nil: keep the devices written when the event was queued or linked to its run
	if devices != nil {
		b, err := json.Marshal(devices)
		if err != nil {
			return err
		}
		arg = string(b)
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_event SET result = ?, devices = coalesce(?, devices) WHERE id = ?`, result, arg, id)
		return err
	})
}

// rescan moves one waiting event on. It returns the event when its devices may be scanned now and its templates fit in
// room; RunRescans then scans the ready events of the pass in one run.
func (s *Service) rescan(ctx context.Context, ev pendingEvent, room int) (*readyEvent, error) {
	if ev.runID != "" { // the run is under way or over
		v, err := s.Run(ctx, ev.runID)
		if err != nil {
			return nil, err
		}
		if v.Status == "running" || v.Status == "stopping" {
			return nil, nil
		}
		// "clear" means only that no match was reported (D-133 (5)), never "not affected"; it changes no finding. A run
		// stopped before every device was done is "stopped" (D-145 (7)): "clear" would hide what was not checked.
		// A run may hold the CVEs of several events (S4b): each closes on the rows of its own CVE's templates, and keeps
		// the devices it was linked with.
		result := "clear"
		switch {
		case s.matchedCVE(v, ev.cve):
			result = "matched"
		case v.Status != "done":
			result = "stopped"
		}
		return nil, s.closeEvent(ctx, ev.id, result, nil)
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	if !st.AutoRescan {
		return nil, s.closeEvent(ctx, ev.id, "skipped_off", nil)
	}
	now := s.now()
	if now.Sub(ev.ts) < rescanSettle {
		return nil, nil
	}
	expired := now.Sub(ev.ts) > pendingFor
	if s.cfg.Pack == nil || len(s.cfg.Pack.ForCVE(ev.cve)) == 0 {
		if expired {
			return nil, s.dropEvent(ctx, ev, "its scan template never reached the installed pack")
		}
		return nil, nil
	}
	// Wait first, before reading every finding and device (#164 review L1): try again at the next tick, still inside
	// the 60 minutes, or when the scanner is back; a scanner that never comes back drops the event like a template
	// that never comes (#164 review L3).
	if s.liveRun() != "" {
		return nil, nil
	}
	if !s.scannerReady(ctx) {
		if expired {
			return nil, s.dropEvent(ctx, ev, "the scanner was not ready for 7 days")
		}
		return nil, nil
	}
	// No automated run starts while the organization zone is unknown, the rescan too (it is not windowed, but it is
	// automated like the schedule): the event waits, and is dropped after 7 days like one whose scanner never came.
	if _, ok := s.loc(ctx); !ok {
		if expired {
			return nil, s.dropEvent(ctx, ev, "the organization time zone could not be read for 7 days")
		}
		return nil, nil
	}
	n := len(s.cfg.Pack.ForCVE(ev.cve))
	if n > room { // this pass's run is full: the event waits for the next, before anything is read
		return nil, nil
	}
	ids, names, pickOnly, first, err := s.affected(ctx, st, ev.cve)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 && len(pickOnly) > 0 { // matching devices, all of them a hand pick only (D-126 (2), D-145 (7))
		return nil, s.closeEvent(ctx, ev.id, "pick_only", pickOnly)
	}
	if len(ids) == 0 {
		return nil, s.closeEvent(ctx, ev.id, "no_match", nil)
	}
	return &readyEvent{ev: ev, ids: ids, names: names, first: first, templates: n, latency: now.Sub(ev.ts).Minutes()}, nil
}

// matchedCVE says whether the run confirmed cve on a device: a matched row of one of its templates. Without the pack
// (it was removed) any match counts, as when a run held one CVE.
func (s *Service) matchedCVE(v RunView, cve string) bool {
	if s.cfg.Pack == nil {
		return v.Matched > 0
	}
	tpls := s.cfg.Pack.ForCVE(cve)
	return slices.ContainsFunc(v.Results, func(r RunRow) bool {
		return r.Result == "matched" && r.Template != nil && slices.ContainsFunc(tpls, func(t pack.Template) bool { return t.Path == *r.Template })
	})
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

// affected are the devices with an open finding for cve that may be scanned without a pick (D-126 (2)), and the names
// of those that may be scanned only by a hand pick (pickOnly, for the pick_only result of D-145 (7)).
func (s *Service) affected(ctx context.Context, st Settings, cve string) (ids, names, pickOnly []string, first Current, err error) {
	if s.cfg.Findings == nil {
		return nil, nil, nil, Current{}, nil
	}
	fs, err := s.cfg.Findings.List(ctx, "")
	if err != nil {
		return nil, nil, nil, Current{}, fmt.Errorf("scan: reading the findings: %w", err)
	}
	devs, err := s.devicesByID(ctx)
	if err != nil {
		return nil, nil, nil, Current{}, err
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
			return nil, nil, nil, Current{}, err
		}
		if why != "" {
			picked, _, err := s.consent(ctx, st, d, true)
			if err != nil {
				return nil, nil, nil, Current{}, err
			}
			if picked == "" && !slices.Contains(pickOnly, d.Label) {
				pickOnly = append(pickOnly, d.Label)
			}
			continue
		}
		if len(ids) == MaxRunTargets {
			continue
		}
		if len(ids) == 0 {
			first = Current{Label: d.Label, IP: d.IP}
		}
		ids, names = append(ids, d.ID), append(names, d.Label)
	}
	return ids, names, pickOnly, first, nil
}

// startAuto starts a run nobody picked: schedule or new_kev. Devices are checked with explicit=false (D-126 (2)).
// onlyCVEs limits the run to those CVEs (the KEV rescan); end, when set, is where the run stops by itself (the end of
// the window of a scheduled run); inTx records what the run is for in the transaction of its row (runSpec.inTx).
func (s *Service) startAuto(ctx context.Context, trigger string, note *string, ids []string, first Current, onlyCVEs []string, end time.Time,
	inTx func(ctx context.Context, tx *sql.Tx, runID string) error) (RunView, error) {
	return s.start(ctx, runSpec{trigger: trigger, note: note, user: systemUser, ids: ids, first: first, onlyCVEs: onlyCVEs, end: end, inTx: inTx})
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
	loc, ok := s.loc(ctx)
	if !ok { // the zone unknown: the tick is skipped, the slot stays open (fail closed)
		return nil
	}
	slot := st.lastSlot(now, loc)
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
	if _, err := s.startAuto(ctx, "schedule", nil, ids, first, nil, end, mark); err != nil && !errors.Is(err, errRunning) {
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
