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

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// Job timing.
const (
	// JobTick is how often the KEV rescans are looked at: well inside the 60 minutes of S-SCAN-2.
	JobTick = time.Minute
	// rescanSettle lets the inventory and findings match a new KEV entry first (the same event makes the findings).
	rescanSettle = time.Minute
	// pendingFor is how long a KEV event waits for its template to reach the installed pack before it is dropped.
	pendingFor = 7 * 24 * time.Hour
	// rescanPage is how many waiting events one pass of the rescan job looks at, oldest first; the rest wait for the
	// next minute (#164 review L1).
	rescanPage = 100
	// eventRetention keeps the rescan log one year (DATA_MODEL [proposed]).
	eventRetention = 365 * 24 * time.Hour
	systemUser     = "system"
)

const noteWindowEnded = "The scan window ended; the devices not reached are scanned at the next scheduled run."

// Jobs are the module's background work; core/jobs runs them only while the module is on (SYS-5), except retention: it only
// deletes rows past the retention (INV-7), so it is housekeeping and keeps its timer while the module is off.
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "rescan", Every: JobTick, Run: svc.RunRescans},
		{Module: ModuleID, Name: "retention", Every: time.Hour, Housekeeping: true, Run: svc.RunRetention},
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
// CVE's templates, outside the time window; when the run has ended → matched or clear.
func (s *Service) RunRescans(ctx context.Context) error {
	if err := s.closeOrphanProbes(ctx); err != nil {
		return err
	}
	// The entries announced while scan was off or down are queued first (S4b); feeds unreadable does not hold up
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
// outside the time window. Each event is linked to the run in the transaction that writes it (#164 review
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
	// each device is probed only for the CVEs of the events that listed it, not for every CVE of the run (#189 review L2)
	pairs := map[string][]string{}
	for _, r := range take {
		for _, id := range r.ids {
			pairs[id] = append(pairs[id], r.ev.cve)
		}
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
	if _, err := s.startAuto(ctx, "new_kev", &note, ids, take[0].first, pairs, time.Time{}, link); err != nil && !errors.Is(err, errRunning) {
		return err
	}
	return nil
}

// rescanNote is the trigger note of a rescan run: its CVEs, as many as fit the 200 characters core/run keeps of a trigger note.
func rescanNote(cves []string) string {
	if len(cves) == 1 {
		return "New KEV entry with a scan template: " + cves[0]
	}
	note := "New KEV entries with a scan template: " + cves[0]
	for i, c := range cves[1:] {
		more := fmt.Sprintf(" and %d more", len(cves)-1-i)
		if len(note)+2+len(c)+len(more) > 200 {
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
		// "clear" means only that no match was reported, never "not affected"; it changes no finding. A run
		// stopped before every device was done is "stopped": "clear" would hide what was not checked.
		// A run may hold the CVEs of several events (S4b): each closes on the rows of its own CVE's templates, and keeps
		// the devices it was linked with.
		hit, err := s.matchedCVE(ctx, v, ev.cve)
		if err != nil {
			return nil, err
		}
		result := "clear"
		switch {
		case hit:
			result = "matched"
		case v.Status != "done":
			result = "stopped"
		}
		return nil, s.closeEvent(ctx, ev.id, result, nil)
	}
	st, err := s.settings(ctx, s.cfg.DB.Reader())
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
			return nil, s.dropEvent(ctx, ev, "expired_no_template", "its scan template never reached the installed pack")
		}
		return nil, nil
	}
	// Wait first, before reading every finding and device (#164 review L1): try again at the next tick, still inside
	// the 60 minutes, or when the scanner is back; a scanner that never comes back drops the event like a template
	// that never comes (#164 review L3).
	if busy, err := s.activeRun(ctx, s.cfg.DB.Reader()); err != nil || busy != "" {
		return nil, err
	}
	if !s.scannerReady(ctx) {
		if expired {
			return nil, s.dropEvent(ctx, ev, "expired_scanner", "the scanner was not ready for 7 days")
		}
		return nil, nil
	}
	// No automated run starts while the organization zone is unknown, the rescan too (it is not windowed, but it is
	// automated like the schedule): the event waits, and is dropped after 7 days like one whose scanner never came.
	if _, ok := s.loc(ctx); !ok {
		if expired {
			return nil, s.dropEvent(ctx, ev, "expired_zone", "the organization time zone could not be read for 7 days")
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
	if len(ids) == 0 && len(pickOnly) > 0 { // matching devices, all of them a hand pick only
		return nil, s.closeEvent(ctx, ev.id, "pick_only", pickOnly)
	}
	if len(ids) == 0 {
		return nil, s.closeEvent(ctx, ev.id, "no_match", nil)
	}
	return &readyEvent{ev: ev, ids: ids, names: names, first: first, templates: n, latency: now.Sub(ev.ts).Minutes()}, nil
}

// matchedCVE says whether the run confirmed cve on a device: a matched row whose finding is a finding of that CVE. A
// finding id belongs to one CVE, while a template path may serve two (#189 review L1). Without findings no row has a
// finding and any match counts, as when a run held one CVE.
func (s *Service) matchedCVE(ctx context.Context, v RunView, cve string) (bool, error) {
	if s.cfg.Findings == nil {
		return v.Matched > 0, nil
	}
	fs, err := s.cfg.Findings.List(ctx, "")
	if err != nil {
		return false, fmt.Errorf("scan: reading the findings: %w", err)
	}
	of := map[string]bool{}
	for _, f := range fs {
		if f.CVE == cve {
			of[f.ID] = true
		}
	}
	return slices.ContainsFunc(v.Results, func(r RunRow) bool {
		return r.Result == "matched" && r.FindingID != nil && of[*r.FindingID]
	}), nil
}

// dropEvent closes an event that waited pendingFor without a scan with an expired_* result, so the rescan log shows it
// and why; the log says it too. The scheduled scan still covers the CVE's devices. The row stays (cve is
// unique), so the catch-up does not queue the CVE again.
func (s *Service) dropEvent(ctx context.Context, ev pendingEvent, result, why string) error {
	s.cfg.Log.WarnContext(ctx, "scan: a KEV rescan was dropped after 7 days", "cve", ev.cve, "reason", why)
	return s.closeEvent(ctx, ev.id, result, nil)
}

// affected are the devices with an open finding for cve that may be scanned without a pick, and the names
// of those that may be scanned only by a hand pick (pickOnly, for the pick_only result).
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
	var cands []Device // in the order of the findings, each device once
	seen := map[string]bool{}
	for _, f := range fs {
		if f.CVE != cve || (f.Status != "suspected" && f.Status != "confirmed") || seen[f.AssetID] {
			continue
		}
		if d, ok := devs[f.AssetID]; ok {
			seen[f.AssetID] = true
			cands = append(cands, d)
		}
	}
	// One batch read per decision kind; a KEV of a common product matches hundreds of devices.
	auto, err := s.policies(ctx, cands, false)
	if err != nil {
		return nil, nil, nil, Current{}, err
	}
	var refused []Device
	for _, d := range cands {
		if why, _ := fold(st, d, auto[d.ID]); why != "" {
			refused = append(refused, d)
		}
	}
	byPick, err := s.policies(ctx, refused, true)
	if err != nil {
		return nil, nil, nil, Current{}, err
	}
	for _, d := range cands {
		if why, _ := fold(st, d, auto[d.ID]); why != "" {
			if picked, _ := fold(st, d, byPick[d.ID]); picked == "" && !slices.Contains(pickOnly, d.Label) {
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

// startAuto starts a run nobody picked: schedule or new_kev. Devices are checked with explicit=false.
// onlyCVEs limits each device to the CVEs listed for it (the KEV rescan); end, when set, is where the run stops by itself (the end of
// the window of a scheduled run); inTx records what the run is for in the transaction of its row (runSpec.inTx).
func (s *Service) startAuto(ctx context.Context, trigger string, note *string, ids []string, first Current, onlyCVEs map[string][]string, end time.Time,
	inTx func(ctx context.Context, tx *sql.Tx, runID string) error) (RunView, error) {
	return s.start(ctx, runSpec{trigger: trigger, note: note, user: systemUser, ids: ids, first: first, onlyCVEs: onlyCVEs, end: end, inTx: inTx})
}

// ScheduleKey is the owner key of the regular vulnerability check in core/schedule.
const ScheduleKey = "scan.vuln"

// ScheduleOwner is what the vulnerability checks register with core/schedule: when they come due is the person's rule (the
// shared editor); what starts is one run over every device that may be scanned without a pick. By default they run on Sundays at
// 23:00 inside the scan window, and the first check of a new box is in its first open window. The window is always the scan window.
// A refusal that passes (no scope yet, a check running, the scanner not ready, the window just closed) holds the due time instead of
// using it up, so the check starts as soon as it can.
func (s *Service) ScheduleOwner() schedule.Owner {
	return schedule.Owner{Module: ModuleID, Key: ScheduleKey, AdminOnly: true, Default: schedule.WeeklyAt("23:00", 7).InWindow(), DefaultOn: true, FirstInWindow: true,
		Limits: schedule.Limits{Windows: []schedule.WindowMode{schedule.WindowGlobal}, Reason: "Scheduled checks run only inside the scan window (Settings, Scanning, Safety)."},
		Start:  s.startScheduled}
}

// startScheduled starts the regular check (S-SCAN-4) inside the schedule's transaction: the run, its steps and its audit rows are
// written with the schedule's due time. A run that starts because the schedule came due stops by itself when the window it was
// held for closes (the box's scan window, or the schedule's own); a person's run once now does not. Nothing starts, and the reason is
// said, while the scope is not confirmed, the scanner is not ready, another check runs or no device may be scanned without a pick.
func (s *Service) startScheduled(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
	st, err := s.settings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return "", err
	}
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return "", err
	}
	if sc.ConfirmedAt == "" {
		return "", schedule.Hold(msgNoCommitment)
	}
	var end time.Time
	if f.Trigger == run.Schedule {
		if end, err = s.windowEnd(ctx, st, f.Rule); err != nil {
			return "", err
		}
	}
	if busy, err := s.activeRun(ctx, tx); err != nil {
		return "", err
	} else if busy != "" {
		return "", schedule.Hold("A vulnerability check is already running; the scheduled check starts when it ends.")
	}
	if !s.scannerReady(ctx) {
		return "", schedule.Hold(msgScannerDown)
	}
	devs, err := s.cfg.Inventory.Devices(ctx)
	if err != nil {
		return "", err
	}
	auto, err := s.policies(ctx, devs, false) // one batch read
	if err != nil {
		return "", err
	}
	var ids []string
	var first Current
	for _, d := range devs {
		if why, _ := fold(st, d, auto[d.ID]); why != "" || len(ids) == MaxRunTargets {
			continue
		}
		if len(ids) == 0 {
			first = Current{Label: d.Label, IP: d.IP}
		}
		ids = append(ids, d.ID)
	}
	if len(ids) == 0 {
		reason := "No device may be checked without someone picking it, so there was nothing to check."
		if f.First { // a new box has no devices yet: its first check waits for them
			return "", schedule.Hold(reason)
		}
		return "", schedule.Skip(reason)
	}
	user := systemUser
	trigger := "schedule"
	if f.Trigger == run.Manual {
		user, trigger = f.By, "manual"
	}
	return s.startTx(ctx, tx, runSpec{trigger: trigger, user: user, ids: ids, first: first, end: end, scheduleID: f.ScheduleID})
}

// windowEnd is when a check that a rule started now must stop: the end of the window the rule holds its starts in (the box's scan
// window, or the rule's own); zero for a rule without a window. A window that is not open now means the start is refused: the
// schedule holds a due time until its window opens, so this is a window that closed or moved between the two reads.
func (s *Service) windowEnd(ctx context.Context, st Settings, r schedule.Rule) (time.Time, error) {
	var w schedule.Window
	switch r.Window {
	case schedule.WindowGlobal:
		w = schedule.Window{Days: st.Window.Days, From: st.Window.From, To: st.Window.To}
	case schedule.WindowCustom:
		if r.WindowFrom == nil || r.WindowTo == nil {
			return time.Time{}, nil
		}
		w = schedule.Window{Days: r.WindowDays, From: *r.WindowFrom, To: *r.WindowTo}
	default:
		return time.Time{}, nil
	}
	loc, ok := s.loc(ctx)
	if !ok {
		return time.Time{}, schedule.Hold(msgZoneUnknown)
	}
	now := s.now()
	if !w.Contains(now, loc) {
		return time.Time{}, schedule.Hold("The scan window is closed; the check starts when it opens.")
	}
	_, end, _ := w.Span(now, loc)
	return end, nil
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
	st, err := s.settings(ctx, s.cfg.DB.Reader())
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

// RecoverEvery is how often the recover job looks for probe rows of a run that is no longer live. core/run records the run itself
// at every start; core/jobs runs a job as soon as its module is on, so after a restart the log is closed at once.
const RecoverEvery = 10 * time.Minute

// RunRecover closes the probe rows of a run that a restart cut (review M4, INV-7): they show stopped.
func (s *Service) RunRecover(ctx context.Context) error {
	s.forgetPending(ctx)
	return s.closeOrphanProbes(ctx)
}

// forgetPending drops what a run that ended while it was queued (a stop, its module turned off) was started with.
func (s *Service) forgetPending(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		var st string
		if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT status FROM core_run WHERE id = ?`, id).Scan(&st); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return
		} else if err == nil && !run.Status(st).Ended() {
			continue
		}
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}
}
