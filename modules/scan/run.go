package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
)

// Limits of a run.
const (
	MaxRunTargets = 200              // INV-3
	keepRuns      = 100              // GET /scans/runs lists the newest runs (the mock keeps 100)
	deviceTimeout = 15 * time.Minute // one device's job; nuclei's own per-request timeout is 10 s
	// stopGrace is how long a stopped run waits for the engine to confirm before it is shown stopped anyway: Stop
	// now takes effect within 5 seconds (INV-6). The engine's lease still kills nuclei.
	stopGrace = 4 * time.Second
	// finishTimeout bounds the writes that must happen after the run's context is gone.
	finishTimeout = 30 * time.Second
)

// Event names published by this module (CONTRACT, Events).
const (
	EventRunStarted       = "scan.run.started"
	EventRunFinished      = "scan.run.finished"
	EventRunStopped       = "scan.run.stopped"
	EventFindingConfirmed = "scan.finding.confirmed"
)

// RunEvent is the payload of scan.run.*.
type RunEvent struct {
	RunID   string `json:"run_id"`
	Status  string `json:"status"`
	Matched int    `json:"matched"`
}

// FindingConfirmedEvent is the payload of scan.finding.confirmed. findings is told directly (ConfirmFromScan); the
// event is for everyone else.
type FindingConfirmedEvent struct {
	AssetID  string `json:"asset_id"`
	CVE      string `json:"cve"`
	Template string `json:"template"`
	Evidence string `json:"evidence"` // the summary
}

// Notes of result rows and stop reasons: the mock's words.
const (
	noteSkipped       = "Not scanned because the scan was stopped. This device was not touched."
	noteNoResp        = "No response; scanning stopped so the device is not hung."
	noteNoRespGoOn    = "The device did not respond within the timeout; skipped."
	noteStoppedMid    = "Stopped while this device was being scanned: no result. The requests on their way are in the probe log as stopped."
	noteRecheckFailed = "The device changed and Vedette could not check it again, so it was stopped to be safe: no result. The requests on their way are in the probe log as stopped."
	noteTurnedOff     = "Its network scan was turned off (or it may no longer be scanned) while it was being checked: stopped at once, no result. The requests on their way are in the probe log as stopped."
	noteNoApply       = "No scan template applies to the software on this device."
	noteEngine        = "The scanner could not finish this device, so nothing was concluded. Try again later."
	stopNow           = "You pressed Stop now."
)

// RunRow is contract.ts RunResultRow.
type RunRow struct {
	TargetID  string  `json:"target_id"`
	Label     string  `json:"label"`
	IP        string  `json:"ip"`
	Template  *string `json:"template"`
	Result    string  `json:"result"` // matched | not_matched | not_applicable | no_template | no_response | skipped
	FindingID *string `json:"finding_id"`
	Note      string  `json:"note"`
}

// Current is the device a running scan is on.
type Current struct {
	Label string `json:"label"`
	IP    string `json:"ip"`
}

// RunView is contract.ts ScanRun.
type RunView struct {
	ID          string   `json:"id"`
	Trigger     string   `json:"trigger"`
	TriggerNote *string  `json:"trigger_note"`
	StartedAt   string   `json:"started_at"`
	StartedBy   string   `json:"started_by"`
	EndedAt     *string  `json:"ended_at"`
	Status      string   `json:"status"`
	Total       int      `json:"total"`
	Done        int      `json:"done"`
	Current     *Current `json:"current"`
	// Progress is how far the current device is (#830): its phase, how far into it, an estimate of the end. Only while the run
	// goes on in this process; null otherwise. It lives in memory and goes with the run.
	Progress   *progress.View `json:"progress"`
	Results    []RunRow       `json:"results"`
	Matched    int            `json:"matched"`
	StopReason *string        `json:"stop_reason"`
	// Identification is one row per device of a Scan now run: what it was identified as, or why it was not. Empty for
	// schedules and KEV rescans, which do not identify, and while the run is going.
	Identification []IdentRow `json:"identification"`
}

// live is the run this process is executing.
type live struct {
	id   string
	cur  Current           // the device being checked: shown while the run goes on, never stored
	prog *progress.Tracker // of the current device (#830); guarded by Service.mu, nil before the first device
}

var (
	errCommitment = apiErr(400, "commitment_required", "Vedette does not scan until the scope commitment is ticked. Do it under Settings › Scanning › Safety.")
	errNoTargets  = apiErr(400, "no_targets", "Choose at least one device to scan.")
	errTooMany    = apiErr(400, "too_many", "A scan can include at most 200 devices.")
	errRunning    = apiErr(409, "already_running", "A scan is already running. Wait for it to finish or press Stop now.")
	errNotRunning = apiErr(409, "not_running", "This scan has already ended, so there is nothing to stop.")
	errNoRun      = apiErr(404, "not_found", "No such item.")
)

// ready is INV-2's scanner half: an Engine that answers Ready, and a template pack to choose from.
func (s *Service) scannerReady(ctx context.Context) bool { return s.cfg.Pack != nil && s.ready(ctx) }

// StartRun starts a scan of the targets a person picked in Scan now (PRE-1, POST-1): the commitment, 1..200 known
// targets that can be picked (INV-1..INV-3), the scanner ready. The pick is the consent for each device;
// it is audited with the person and the ids.
func (s *Service) StartRun(ctx context.Context, user string, ids []string) (RunView, error) {
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return RunView{}, fmt.Errorf("scan: reading the scope: %w", err)
	}
	if sc.ConfirmedAt == "" {
		return RunView{}, errCommitment
	}
	if len(ids) == 0 {
		return RunView{}, errNoTargets
	}
	if len(ids) > MaxRunTargets {
		return RunView{}, errTooMany
	}
	if s.cfg.Runs == nil {
		return RunView{}, errors.New("scan: no run manager is wired")
	}
	if busy, err := s.activeRun(ctx, s.cfg.DB.Reader()); err != nil {
		return RunView{}, err
	} else if busy != "" {
		return RunView{}, errRunning
	}
	all, err := s.Targets(ctx) // one batch policy read for every device
	if err != nil {
		return RunView{}, err
	}
	byID := make(map[string]TargetView, len(all))
	for _, t := range all {
		byID[t.ID] = t
	}
	var chosen, picked, nothing []string
	var first Current
	for _, id := range ids {
		if slices.Contains(chosen, id) || slices.Contains(nothing, id) {
			continue
		}
		t, ok := byID[id]
		if !ok {
			return RunView{}, unknownTarget(id)
		}
		if !t.Selectable {
			return RunView{}, refusal(t)
		}
		if !t.checks().any() { // nothing a check could confirm, rule out or check again: not part of the run
			nothing = append(nothing, id)
			continue
		}
		if len(chosen) == 0 {
			first = Current{Label: t.Label, IP: t.IP}
		}
		chosen = append(chosen, id)
		if t.PickOnly { // M1: the pick is the consent of this device only, as it stood now
			picked = append(picked, id)
		}
	}
	if !s.scannerReady(ctx) {
		return RunView{}, ErrScannerUnavailable
	}
	if len(chosen) == 0 {
		labels := make([]string, len(nothing))
		for i, id := range nothing {
			labels[i] = byID[id].Label
		}
		return RunView{}, errNothingToCheck(labels)
	}
	return s.start(ctx, runSpec{trigger: "manual", user: user, ids: chosen, picked: picked, first: first})
}

// runSpec is what a run is started with.
type runSpec struct {
	trigger  string // manual | schedule | new_kev
	note     *string
	user     string
	ids      []string
	picked   []string            // the ids picked by a person that needed the pick; empty for schedules and KEV rescans
	first    Current             // the device the run begins with: shown as current from the start (POST-1)
	onlyCVEs map[string][]string // nil: every CVE of the devices' findings; else device id -> the only CVEs it is probed for (the KEV rescan, INV-9; a backlog in one run keeps each event's pairs, #189 review L2)
	end      time.Time           // zero: none; else the run stops by itself then (the end of the window of a scheduled run)
	// scheduleID is the core_schedule row that came due ("" for any other start).
	scheduleID string
	// identBusy is set (by identify) once discovery was busy during this run: the rest of the run does not wait for it again.
	identBusy *bool
	// inTx, when set, runs in the transaction that writes the run row: what the run is for (the schedule slot, the
	// KEV event) is recorded with it or not at all (#164 review L4).
	inTx func(ctx context.Context, tx *sql.Tx, runID string) error
}

// Run kind of a vulnerability check on core/run (DB-DESIGN core_run): one run per Scan now, schedule slot or KEV rescan, one step
// per device (total 1: the run's done and total count devices), one item per result row. The lane is nuclei: the database holds
// one live run in it. A restart records a running check as stopped by core/run itself and does not resume it: the consent of a
// pick and the CVEs a rescan was linked with live in the process that started the run, so the owners start a new one (the
// schedule on its next tick, a KEV event while its result is open).
const (
	runKindName = "vuln_check"
	runLane     = "nuclei"
	// noteLost is the end of a queued check a restart left without the picks it was started with.
	noteLost = "Vedette restarted before this scan began, so it did not run. Start it again."
)

// registerKind adds the kind of run to the box's run manager; without one the module cannot start a check.
func (s *Service) registerKind() error {
	return s.cfg.Runs.Register(run.Kind{Module: ModuleID, Name: runKindName, Lane: runLane, Run: s.runVulnCheck})
}

// runTitle is what the run says it does.
func runTitle(sp runSpec, labels []string) string {
	what := fmt.Sprintf("%d devices", len(sp.ids))
	if len(sp.ids) == 1 && len(labels) == 1 {
		what = labels[0]
	}
	switch sp.trigger {
	case "schedule":
		return "Scheduled vulnerability check of " + what
	case "new_kev":
		return "Vulnerability check after a new known-exploited entry: " + what
	}
	return "Vulnerability check of " + what
}

var triggers = map[string]run.Trigger{"manual": run.Manual, "schedule": run.Schedule, "new_kev": run.Event}

// start queues the run with its steps, the audit rows and what the run is for, in one transaction; core/run starts it once the
// nuclei lane is free.
func (s *Service) start(ctx context.Context, sp runSpec) (RunView, error) {
	if s.cfg.Runs == nil {
		return RunView{}, errors.New("scan: no run manager is wired")
	}
	if s.engineBusy() {
		return RunView{}, errRunning
	}
	var id string
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.startTx(ctx, tx, sp)
		return err
	})
	if err != nil {
		if id != "" {
			s.mu.Lock()
			delete(s.pending, id)
			s.mu.Unlock()
		}
		return RunView{}, err
	}
	return s.Run(ctx, id)
}

// startTx writes the run with its steps and audit rows inside tx and keeps what it was started with for the moment core/run
// begins it, which is after the commit. The schedule of the checks starts its runs this way, inside its own transaction.
func (s *Service) startTx(ctx context.Context, tx *sql.Tx, sp runSpec) (string, error) {
	devs, _ := s.devicesByID(ctx) // for the names of the steps; a failed read names them by id
	labels := make([]string, len(sp.ids))
	steps := make([]run.StepPlan, len(sp.ids))
	for i, id := range sp.ids {
		labels[i] = id
		if d, ok := devs[id]; ok && d.Label != "" {
			labels[i] = d.Label
		}
		steps[i] = run.StepPlan{Name: labels[i], Total: 1}
	}
	spec := run.Spec{Module: ModuleID, Kind: runKindName, Title: runTitle(sp, labels), Trigger: triggers[sp.trigger], RequestedBy: sp.user, ScheduleID: sp.scheduleID, Steps: steps}
	if sp.note != nil {
		spec.TriggerNote = *sp.note
	}
	if len(sp.ids) == 1 {
		spec.Subject = &run.Subject{Kind: "device", ID: sp.ids[0], Label: labels[0]}
	}
	if busy, err := s.activeRun(ctx, tx); err != nil {
		return "", err
	} else if busy != "" {
		return "", errRunning
	}
	id, err := s.cfg.Runs.CreateTx(ctx, tx, spec)
	if err != nil {
		if store.IsUniqueViolation(err) {
			return "", errRunning
		}
		return "", fmt.Errorf("scan: writing the run: %w", err)
	}
	// The start counts and hashes the whole list; each pick, the consent, is a row of its own.
	sum := sha256.Sum256([]byte(strings.Join(sp.ids, ",")))
	detail := fmt.Sprintf("%d targets, %d picked by hand, sha256 %s", len(sp.ids), len(sp.picked), hex.EncodeToString(sum[:8]))
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: sp.user, Action: "scan.start", Target: id, Detail: detail}); err != nil {
		return id, err
	}
	for _, p := range sp.picked {
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: sp.user, Action: "scan.pick", Target: p, Detail: "run " + id}); err != nil {
			return id, err
		}
	}
	if sp.inTx != nil {
		if err := sp.inTx(ctx, tx, id); err != nil {
			return id, err
		}
	}
	// Before the commit: the dispatcher cannot start the run until it, and then finds what it needs.
	s.mu.Lock()
	s.pending[id] = sp
	s.mu.Unlock()
	return id, nil
}

// takePending hands the run the spec it was started with, once.
func (s *Service) takePending(id string) (runSpec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.pending[id]
	delete(s.pending, id)
	return sp, ok
}

// engineBusy says an Engine.Run call has not returned yet (review M2).
func (s *Service) engineBusy() bool { return s.busy.Load() > 0 }

// activeRun is the id of a vulnerability check that has not ended (queued, running or stopping), "" when none: a second one is
// refused (INV-3).
func (s *Service) activeRun(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (string, error) {
	var id string
	err := q.QueryRowContext(ctx, `SELECT id FROM core_run WHERE module = ? AND kind = ? AND status IN ('queued', 'running', 'stopping') LIMIT 1`, ModuleID, runKindName).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("scan: reading the live run: %w", err)
	}
	return id, nil
}

// closeOrphanProbes closes the probe rows of a run that is no longer live: a restart cut it (core/run records the run itself), and
// INV-7 wants the log to keep what was on its way, as stopped.
func (s *Service) closeOrphanProbes(ctx context.Context) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = 'stopped' WHERE result IS NULL AND run_id IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM core_run r WHERE r.id = scan_probe.run_id AND r.status IN ('running', 'stopping'))`)
		return err
	})
}

// StopRun is Stop now (PRE-2, POST-2, INV-6): the run becomes stopping, no new request leaves, and it is stopped within 5
// seconds. Stopping a run that is already stopping is not an error. core/run records the stop and its audit row.
func (s *Service) StopRun(ctx context.Context, user, id string) (RunView, error) {
	v, err := s.Run(ctx, id)
	if err != nil {
		return RunView{}, err
	}
	if v.Status != "running" && v.Status != "stopping" {
		return RunView{}, errNotRunning
	}
	if err := s.cfg.Runs.Stop(ctx, id, user, stopNow); err != nil && !errors.Is(err, run.ErrEnded) {
		return RunView{}, fmt.Errorf("scan: stopping the run: %w", err)
	}
	return s.Run(ctx, id)
}

// ---- executing a run ----

// runVulnCheck is the Run of the kind: core/run calls it once the nuclei lane is free.
func (s *Service) runVulnCheck(ctx context.Context, x *run.Exec) (run.Result, error) {
	sp, ok := s.takePending(x.ID())
	if !ok { // a queued run a restart left: the picks and the CVEs it was started with are gone
		return run.Result{Status: run.Failed, Error: noteLost}, nil
	}
	s.mu.Lock()
	s.live = &live{id: x.ID(), cur: sp.first}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.live = nil; s.mu.Unlock() }()
	s.publish(ctx, EventRunStarted, RunEvent{RunID: x.ID(), Status: "running"})
	if !sp.end.IsZero() { // by the injected clock, so a test can put the end close
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sp.end.Sub(s.now()))
		defer cancel()
	}
	return s.execute(ctx, x, sp), nil
}

// execute scans the targets one device at a time. Every device is checked again right before its job leaves core
// (INV-1); a person's Stop now or an unresponsive device (INV-6) ends the run, and the devices not reached are not
// touched. Each device is a step of the run and its rows are items, written as the device ends.
// sp.picked are the ids whose pick is their consent (M1): each other device is checked as for an automatic run.
func (s *Service) execute(ctx context.Context, x *run.Exec, sp runSpec) run.Result {
	ids := sp.ids
	sp.identBusy = new(bool)
	res := run.Result{}
	event, matched := "done", 0
	next := len(ids) // first device not touched
	rec := func(rows []RunRow, ident *IdentRow) {
		for _, r := range rows {
			if r.Result == "matched" {
				matched++
			}
		}
		s.record(ctx, x, rows, ident)
	}
	for i, id := range ids {
		if ctx.Err() != nil {
			res, event = s.interrupted(ctx)
			next = i
			break
		}
		seq := i + 1
		s.step(ctx, "start", x.StartStep(context.WithoutCancel(ctx), seq))
		got, ident, end := s.scanTarget(ctx, x.ID(), id, sp)
		rec(got, ident)
		fctx := context.WithoutCancel(ctx)
		switch end {
		case "":
			s.step(ctx, "progress", x.Progress(fctx, seq, 1, 1))
			s.step(ctx, "end", x.EndStep(fctx, seq, run.Done, ""))
			continue
		case "stopped":
			s.step(ctx, "end", x.EndStep(fctx, seq, run.Stopped, ""))
			res, event = s.interrupted(ctx)
		default:
			s.step(ctx, "end", x.EndStep(fctx, seq, run.Partial, end))
			res, event = run.Result{Status: run.Partial, Error: end}, "auto_stopped"
		}
		next = i + 1
		break
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	devs, _ := s.devicesByID(fctx) // for the labels of the rows below; a failed read leaves dashes
	for i := next; i < len(ids); i++ {
		d := devs[ids[i]]
		rec([]RunRow{{TargetID: ids[i], Label: orDash(d.Label), IP: orDash(d.IP), Result: "skipped", Note: noteSkipped}}, nil)
		if identifies(sp) {
			d.ID = ids[i]
			r := identRow(d, nil, "not_scanned")
			r.Note = noteSkipped
			s.record(fctx, x, nil, &r)
		}
		s.step(fctx, "end", x.EndStep(fctx, i+1, run.Stopped, noteSkipped))
	}
	// Review L4: a probe row closeProbes could not close does not stay open for good (INV-7).
	left := "no_response"
	if res.Status != run.Done {
		left = "stopped"
	}
	s.closeRunProbes(fctx, x.ID(), left)
	s.publish(fctx, eventNameOf(event), RunEvent{RunID: x.ID(), Status: event, Matched: matched})
	return res
}

func eventNameOf(status string) string {
	if status == "done" {
		return EventRunFinished
	}
	return EventRunStopped
}

// interrupted is how a run ended before its last device: the window of a scheduled run closed (it stopped by itself), or the run's
// context ended for a stop or a shutdown (core/run records which: a person's stop makes it stopped, a shutdown leaves it running
// for the next start to record).
func (s *Service) interrupted(ctx context.Context) (run.Result, string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return run.Result{Status: run.Partial, Error: noteWindowEnded}, "auto_stopped"
	}
	return run.Result{Status: run.Partial, Error: stopNow}, "stopped"
}

// step logs a failed write of a step: the run goes on, its rows are the record.
func (s *Service) step(ctx context.Context, what string, err error) {
	if err != nil && !errors.Is(err, run.ErrNotLive) {
		s.cfg.Log.WarnContext(ctx, "scan: could not record the progress of a run", "step", what, "error", err)
	}
}

// closeRunProbes closes the probe rows a run left open.
func (s *Service) closeRunProbes(ctx context.Context, runID, result string) {
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = ? WHERE run_id = ? AND result IS NULL`, result, runID)
		return err
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: closing the probe log failed", "run", runID, "error", err)
	}
}

// identifies says a run identifies its devices before checking them: Scan now only. A schedule and a KEV rescan check
// what is known; discovery identifies devices in its own window.
func identifies(sp runSpec) bool { return sp.trigger == "manual" }

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (s *Service) devicesByID(ctx context.Context) (map[string]Device, error) {
	all, err := s.cfg.Inventory.Devices(ctx)
	out := make(map[string]Device, len(all))
	for _, d := range all {
		out[d.ID] = d
	}
	return out, err
}

// scanTarget scans one device. end is "" to go on, "stopped" after Stop now, or the stop reason of an
// unresponsive device when stop_on_unresponsive is set. ident is the device's identification row in a Scan now run, nil
// in other runs.
func (s *Service) scanTarget(ctx context.Context, runID, id string, sp runSpec) (rows []RunRow, ident *IdentRow, end string) {
	explicit := slices.Contains(sp.picked, id) // M1: the pick is per device
	skipped := func(d Device, why string) *IdentRow {
		if !identifies(sp) {
			return nil
		}
		r := skippedRow(d, why)
		return &r
	}
	failed := func(err error) ([]RunRow, *IdentRow, string) {
		r := s.failed(ctx, id, err)
		return r, skipped(Device{ID: id}, "not_scanned"), ""
	}
	st, err := s.settings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return failed(err)
	}
	devs, err := s.devicesByID(ctx)
	if err != nil {
		return failed(err)
	}
	d, ok := devs[id]
	if !ok {
		return []RunRow{{TargetID: id, Label: "—", IP: "—", Result: "skipped", Note: skipNote["gone"]}}, skipped(Device{ID: id}, ReasonGone), ""
	}
	s.setCurrent(runID, d)
	// #830: the device's own progress. The worker's reports of its nmap and nuclei jobs reach this Tracker through ctx (the Dispatcher
	// finds the Sink there); the scan names the phase itself where no tool reports yet.
	tr := progress.NewTracker(s.now)
	s.setProgress(runID, tr)
	ctx = progress.WithSink(ctx, tr)
	if identifies(sp) {
		tr.Report(progress.Phase(progress.PhaseDiscovery, ""))
	} else {
		tr.Report(progress.Phase(progress.PhaseVulns, ""))
	}
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return failed(err)
	}
	if sc.ConfirmedAt == "" {
		return []RunRow{s.skip(d, reasonNoScope)}, skipped(d, reasonNoScope), ""
	}
	why, careful, err := s.consent(ctx, st, d, explicit)
	if err != nil {
		return failed(err)
	}
	if why != "" {
		return []RunRow{s.skip(d, why)}, skipped(d, why), ""
	}
	if identifies(sp) {
		row, how := s.identify(ctx, d, sp.identBusy)
		ident = &row
		switch how {
		case "stopped":
			return []RunRow{{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: noteIdentStopped}}, ident, "stopped"
		case "skip":
			return []RunRow{{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: noteIdentInterrupted}}, ident, ""
		}
		// What the identification recorded changed the device: its open ports (where nuclei goes) and, through the findings
		// module, its findings (what plan reads). The address it was checked for stays the one consent decided on.
		if devs, err := s.devicesByID(ctx); err == nil {
			if now, ok := devs[id]; ok && now.IP == d.IP {
				d = now
			}
		}
	}
	rate := st.Rate
	if careful {
		rate = max(1, st.Rate/4) // Fragile and unclassified devices at a quarter of the speed
	}
	var only []string // nil: every CVE; a device the map does not name gets an empty list and is probed for nothing
	if sp.onlyCVEs != nil {
		only = append([]string{}, sp.onlyCVEs[d.ID]...)
	}
	// This device's part runs under its own context, so DeviceChanged can stop it alone when the device may no
	// longer be scanned (its network scan turned off while it runs); the run goes on with the next device.
	dctx, dcancel := context.WithCancel(ctx)
	dr := &devRun{id: d.ID, explicit: explicit, cancel: dcancel}
	s.mu.Lock()
	s.dev = dr
	s.mu.Unlock()
	rows, end = s.scanDevice(dctx, runID, d, st, rate, only)
	s.mu.Lock()
	s.dev = nil
	s.mu.Unlock()
	dcancel()
	if end == "stopped" && ctx.Err() == nil && len(rows) > 0 { // only this device's part was stopped
		rows[len(rows)-1].Note = noteTurnedOff
		if dr.unread.Load() {
			rows[len(rows)-1].Note = noteRecheckFailed
		}
		end = ""
	}
	return rows, ident, end
}

// devRun is the device whose vulnerability check is running now (Service.dev).
type devRun struct {
	id       string
	explicit bool
	cancel   context.CancelFunc
	unread   atomic.Bool // DeviceChanged could not read the device again and stopped it to be safe (review r2 L3)
}

// DeviceChanged stops the check of assetID when it is the device being checked now and the inventory no longer lets it be scanned
// (its network scan turned off; also never, excluded, moved, gone). The probes on their way are closed as stopped and its row
// says why; the run goes on with the next device. A read that fails stops it too (fail closed).
func (s *Service) DeviceChanged(ctx context.Context, assetID string) error {
	s.mu.Lock()
	r := s.dev
	s.mu.Unlock()
	if r == nil || r.id != assetID {
		return nil
	}
	st, err := s.settings(ctx, s.cfg.DB.Reader())
	if err != nil {
		r.unread.Store(true)
		r.cancel()
		return err
	}
	devs, err := s.devicesByID(ctx)
	if err != nil {
		r.unread.Store(true)
		r.cancel()
		return err
	}
	d, ok := devs[assetID]
	if !ok {
		r.cancel()
		return nil
	}
	why, _, err := s.consent(ctx, st, d, r.explicit)
	if err != nil {
		r.unread.Store(true)
	}
	if err != nil || why != "" {
		r.cancel()
	}
	return err
}

func (s *Service) skip(d Device, why string) RunRow {
	note := skipNote[why]
	if note == "" {
		note = skipNote["out_of_scope"]
	}
	return RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: note}
}

func (s *Service) failed(ctx context.Context, id string, err error) []RunRow {
	s.cfg.Log.ErrorContext(ctx, "scan: a device could not be scanned", "asset", id, "error", err)
	return []RunRow{{TargetID: id, Label: "—", IP: "—", Result: "skipped", Note: noteEngine}}
}

// setProgress makes tr the progress of the live run id; nothing when id is not the live run.
func (s *Service) setProgress(id string, tr *progress.Tracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live != nil && s.live.id == id {
		s.live.prog = tr
	}
}

// progressOf is the progress of run id while this process runs it; nil otherwise.
func (s *Service) progressOf(id string) *progress.View {
	s.mu.Lock()
	tr := (*progress.Tracker)(nil)
	if s.live != nil && s.live.id == id {
		tr = s.live.prog
	}
	s.mu.Unlock()
	if tr == nil {
		return nil
	}
	return tr.View()
}

// setCurrent names the device the live run is on (display only).
func (s *Service) setCurrent(runID string, d Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live != nil && s.live.id == runID {
		s.live.cur = Current{Label: d.Label, IP: d.IP}
	}
}

// currentOf is the device run id is on while this process runs it (or has it queued); nil otherwise.
func (s *Service) currentOf(id string) *Current {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live != nil && s.live.id == id {
		c := s.live.cur
		return &c
	}
	if sp, ok := s.pending[id]; ok {
		c := sp.first
		return &c
	}
	return nil
}

// check is one CVE of a device and the templates that confirm it.
type check struct {
	finding FindingRef
	tpls    []pack.Template
}

// suspectedNote says how a finding without a template was matched, so a product-only match is not read as a version check.
func suspectedNote(basis string) string {
	switch basis {
	case "version":
		return "still suspected: the device's version is in the affected range."
	case "product":
		return "still suspected from the product alone; no version was checked."
	}
	return "still suspected; see the finding for how it was matched."
}

// plan chooses what a device is checked for: each CVE of its findings that has a template in the pack (at most
// nucleiargv.MaxTemplates templates); a CVE without a template is a no_template row and sends nothing (INV-8).
func (s *Service) plan(ctx context.Context, d Device, onlyCVEs []string) (checks []check, rows []RunRow, err error) {
	if s.cfg.Findings == nil {
		return nil, nil, nil
	}
	fs, err := s.cfg.Findings.List(ctx, d.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("scan: reading the findings of %s: %w", d.ID, err)
	}
	n := 0
	seen := map[string]bool{}
	for _, f := range fs {
		if dismissed(f.Status) || (onlyCVEs != nil && !slices.Contains(onlyCVEs, f.CVE)) {
			continue
		}
		if seen[f.CVE] {
			continue
		}
		seen[f.CVE] = true
		tpls := s.templatesOf(f)
		if len(tpls) == 0 {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_template", FindingID: ptr(f.ID), Note: f.CVE + ": no safe scan template yet, " + suspectedNote(f.Basis)})
			continue
		}
		if n+len(tpls) > nucleiargv.MaxTemplates {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", FindingID: ptr(f.ID), Note: f.CVE + ": not checked in this scan (more than 32 templates for one device); scan the device again."})
			continue
		}
		n += len(tpls)
		checks = append(checks, check{finding: f, tpls: tpls})
	}
	return checks, rows, nil
}

// dismissed is a finding a person closed (false positive, not relevant, patched, risk accepted until a day): its
// CVE is not probed again (review L3). Mitigated findings are rescanned: a match shows the mitigation did not hold; no match changes nothing.
func dismissed(status string) bool {
	return status == "false_positive" || status == "not_relevant" || status == "patched" || status == "risk_accepted"
}

// endpoints are where nuclei sends requests on a device: its known web services first, then its other TCP ports
// (network templates), at most nucleiargv.MaxTargets; a device with no known port gets ports 80 and 443. TLS comes from the
// service name: nmap's tunnel="ssl" reaches the inventory as "ssl/http", and a port that any source names TLS is
// only spoken to over https (a plain-HTTP request to it is a wasted probe and a silent miss).
func endpoints(d Device) []nucleiargv.Target {
	isTLS := func(name string) bool { return strings.Contains(name, "https") || strings.HasPrefix(name, "ssl/http") }
	tls := map[int]bool{}
	for _, sv := range d.Services {
		if isTLS(strings.ToLower(sv.Name)) {
			tls[sv.Port] = true
		}
	}
	var web, other []nucleiargv.Target
	for _, sv := range d.Services {
		name := strings.ToLower(sv.Name)
		switch {
		case !isTLS(name) && !strings.HasPrefix(name, "http") && name != "www":
			other = append(other, nucleiargv.Target{Host: d.IP, Port: sv.Port})
		case tls[sv.Port]:
			web = append(web, nucleiargv.Target{Host: d.IP, Port: sv.Port, Scheme: "https"})
		default:
			web = append(web, nucleiargv.Target{Host: d.IP, Port: sv.Port, Scheme: "http"})
		}
	}
	all := append(web, other...)
	if len(all) == 0 {
		all = []nucleiargv.Target{{Host: d.IP, Port: 80, Scheme: "http"}, {Host: d.IP, Port: 443, Scheme: "https"}}
	}
	out := make([]nucleiargv.Target, 0, len(all))
	for _, t := range all {
		if len(out) < nucleiargv.MaxTargets && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// scanDevice sends one job for the device and turns what nuclei printed into result rows and finding updates.
func (s *Service) scanDevice(ctx context.Context, runID string, d Device, st Settings, rate int, onlyCVEs []string) ([]RunRow, string) {
	checks, rows, err := s.plan(ctx, d, onlyCVEs)
	if err != nil {
		return s.failed(ctx, d.ID, err), ""
	}
	if len(checks) == 0 {
		if len(rows) == 0 {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "not_applicable", Note: noteNoApply})
		}
		return rows, ""
	}
	job := nucleiargv.Job{Targets: endpoints(d), Rate: rate, MaxHostErrors: st.UnresponsiveAfter}
	var ids []string
	for _, c := range checks {
		for _, t := range c.tpls {
			job.Templates = append(job.Templates, t.Path) // the file of the verified index, never the whole directory (M2)
			ids = append(ids, t.ID)
		}
	}
	if _, err := nucleiargv.Build(job); err != nil { // the same check the worker makes: never hand over a job it would refuse
		return s.failed(ctx, d.ID, err), ""
	}
	probes, err := s.writeProbes(ctx, runID, d, checks)
	if err != nil {
		return s.failed(ctx, d.ID, err), ""
	}
	progress.Report(ctx, progress.Update{Phase: progress.PhaseVulns, Percent: -1, Total: int64(len(ids) * len(job.Targets)), Unit: progress.UnitChecks})
	out, err := s.runJob(ctx, Job{Job: job, IDs: ids, PackVersion: s.cfg.Pack.Version, PackSHA256: s.cfg.Pack.SHA256})
	res := out.Results
	s.noteSkipped(ctx, runID, d, probes, out.Skipped)
	if ctx.Err() != nil { // Stop now while this device was being scanned
		s.closeProbes(ctx, probes, func(string) string { return "stopped" })
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: noteStoppedMid}), "stopped"
	}
	if errors.Is(err, ErrEngineDown) { // the scanner cannot run any job now: stop with its own words, not device by device
		s.cfg.Log.ErrorContext(ctx, "scan: the scanner cannot run jobs", "asset", d.ID, "run", runID, "error", err)
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: noteEngine})
		return rows, "The vulnerability scanner stopped accepting jobs: " + clip(err.Error(), 400)
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		s.cfg.Log.ErrorContext(ctx, "scan: the scanner failed on a device", "asset", d.ID, "run", runID, "error", err)
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		for _, c := range checks {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Template: ptr(c.tpls[0].Path), Result: "no_response", FindingID: ptr(c.finding.ID), Note: noteEngine})
		}
		return rows, ""
	}
	if errors.Is(err, context.DeadlineExceeded) { // review L5: the device did not finish in time, which is not "did not respond"
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		mins := int(deviceTimeout.Minutes())
		if st.StopOnUnresponsive {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: fmt.Sprintf("The device did not finish within %d minutes; scanning stopped so the device is not hung.", mins)})
			return rows, fmt.Sprintf("%s (%s) did not finish within %d minutes. Vedette stopped so the device is not hung.", d.Label, d.IP, mins)
		}
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: fmt.Sprintf("The device did not finish within %d minutes; skipped.", mins)}), ""
	}
	if unresponsive(res) || allUnreachable(out.HostErrors, job.Targets) || allGaveUp(nucleiout.GaveUp(res, out.Skipped), job.Targets) {
		// A device nuclei gave up on mid-run may already have matched: those matches are recorded as usual, a
		// no_response never drops them. Every other template of the device closes as no_response.
		for _, c := range checks {
			if checkMatched(c, res) {
				rows = append(rows, s.conclude(ctx, d, c, res, job.Targets))
			}
		}
		s.closeProbes(ctx, probes, func(tpl string) string {
			if templateResult(tpl, res) == "matched" {
				return "matched"
			}
			return "no_response"
		})
		if st.StopOnUnresponsive {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: noteNoResp})
			return rows, fmt.Sprintf("%s (%s) stopped responding after %d failed requests. Vedette stopped so the device is not hung.", d.Label, d.IP, st.UnresponsiveAfter)
		}
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: noteNoRespGoOn}), ""
	}
	byTemplate := map[string]string{}
	inconclusive := func(id string) bool { return slices.Contains(out.Skipped.MatchedTemplates, id) }
	for _, c := range checks {
		row := s.conclude(ctx, d, c, res, job.Targets)
		// review r2 M3: a line that said matched but could not be tied to the device's targets (an unreadable target, a match
		// with an error, another address) never reads "no match reported": no finding, and a note to check by hand, on the device
		// (every target of the job is the device's)
		if row.Result != "matched" && slices.ContainsFunc(c.tpls, func(t pack.Template) bool { return inconclusive(t.ID) }) {
			row.Result, row.Note = "no_response", c.finding.CVE+": "+nucleiout.InconclusiveNote+"."
		}
		rows = append(rows, row)
		for _, t := range c.tpls {
			byTemplate[t.ID] = templateResult(t.ID, res)
			if byTemplate[t.ID] != "matched" && inconclusive(t.ID) {
				byTemplate[t.ID] = "no_response"
			}
		}
	}
	s.closeProbes(ctx, probes, func(tpl string) string { return byTemplate[tpl] })
	return rows, ""
}

// hostPorts are the job's targets as nucleiout matches them (L2).
func hostPorts(ts []nucleiargv.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Host + ":" + strconv.Itoa(t.Port)
	}
	return out
}

// recheckInput is the -u of the "check it yourself" line: the job's own target that matched, never a field of the
// output (L7).
func recheckInput(ts []nucleiargv.Target, hostPort string) string {
	for _, t := range ts {
		if t.Host+":"+strconv.Itoa(t.Port) == hostPort {
			return t.Input()
		}
	}
	return ts[0].Input() // unreachable: nucleiout returns only the job's targets
}

// runJob runs the job on the engine, bounded by the device timeout; after Stop now it waits at most stopGrace.
func (s *Service) runJob(ctx context.Context, job Job) (nucleiout.Outcome, error) {
	jctx, cancel := context.WithTimeout(ctx, deviceTimeout)
	defer cancel()
	type result struct {
		out nucleiout.Outcome
		err error
	}
	ch := make(chan result, 1)
	s.busy.Add(1)
	go func() {
		var r result
		func() {
			defer s.busy.Add(-1) // before the send: once the run has its result, the engine is no longer busy (a start right after the run ended saw already_running)
			r.out, r.err = s.cfg.Engine.Run(jctx, job)
		}()
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-ctx.Done():
		select {
		case r := <-ch:
			return r.out, r.err
		case <-time.After(stopGrace):
			return nucleiout.Outcome{}, ctx.Err()
		}
	}
}

// checkMatched says one of the check's templates has a matched line.
func checkMatched(c check, res []nucleiout.Result) bool {
	return slices.ContainsFunc(res, func(r nucleiout.Result) bool {
		return r.Matched && slices.ContainsFunc(c.tpls, func(t pack.Template) bool { return t.ID == r.Template })
	})
}

// allUnreachable says every target of the job stopped answering: the worker counted at least max-host-errors timeouts on each
// of them, from nuclei's error log. That is a run total, not nuclei's own -mhe count (consecutive errors, reset by a success,
// and applied to http targets only), so a very flaky but alive device can count here too: the safe side for the device. It holds even when the
// device answered some templates before it died: the device is lost for this run (INV-6). One target that did not
// reach the limit means the device still answers on it, so it is not this case.
func allUnreachable(he []nucleiout.HostError, targets []nucleiargv.Target) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		hp := t.Host + ":" + strconv.Itoa(t.Port)
		if !slices.ContainsFunc(he, func(h nucleiout.HostError) bool { return h.Target == hp && h.Unreachable }) {
			return false
		}
	}
	return true
}

// allGaveUp says nuclei gave up every target of the job as unresponsive (nucleiout.GaveUp): its own -mhe count, which a refused or
// reset connection feeds too, while the worker's host errors count only timeouts. The device is lost for this run, as in
// allUnreachable.
func allGaveUp(gave []string, targets []nucleiargv.Target) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !slices.Contains(gave, t.Host+":"+strconv.Itoa(t.Port)) {
			return false
		}
	}
	return true
}

// unresponsive says the device answered nothing: it printed lines and every one is an error (INV-6). With -ms (matcher
// status) nuclei prints a line, with its error, for every template and target that did not match, so a device dead from the
// start prints only errors. An empty output is not that (no line, no verdict). A device that dies mid-run is caught by
// allUnreachable, from the worker's host errors. nuclei itself stops sending after max_host_errors errors in a row (-mhe),
// so the device is not pushed further either way.
func unresponsive(res []nucleiout.Result) bool {
	return len(res) > 0 && !slices.ContainsFunc(res, func(r nucleiout.Result) bool { return r.Error == "" })
}

// templateResult is the probe-log result of one template: matched; no_response when it has lines and every one is an
// error; otherwise not_matched, which means only "no match reported".
func templateResult(id string, res []nucleiout.Result) string {
	seen, answered := false, false
	for _, r := range res {
		if r.Template != id {
			continue
		}
		if r.Matched {
			return "matched"
		}
		seen, answered = true, answered || r.Error == ""
	}
	if seen && !answered {
		return "no_response"
	}
	return "not_matched"
}

// conclude turns the lines of one CVE into its result row and tells the findings module (INV-8, S-SCAN-3).
// One matched line is enough for a template on a device (L3): a template that needs an out-of-band answer is refused by
// the pack (oast), so a "not matched" never stands for a check nuclei could not make with -ni.
func (s *Service) conclude(ctx context.Context, d Device, c check, res []nucleiout.Result, targets []nucleiargv.Target) RunRow {
	cve := c.finding.CVE
	row := RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Template: ptr(c.tpls[0].Path), FindingID: ptr(c.finding.ID)}
	var hit *nucleiout.Result
	seen, answered := false, false
	for i, r := range res {
		if !slices.ContainsFunc(c.tpls, func(t pack.Template) bool { return t.ID == r.Template }) {
			continue
		}
		if r.Matched {
			hit = &res[i]
			break
		}
		seen, answered = true, answered || r.Error == ""
	}
	switch {
	case hit != nil:
		tpl := c.tpls[slices.IndexFunc(c.tpls, func(t pack.Template) bool { return t.ID == hit.Template })]
		row.Template = ptr(tpl.Path)
		row.Result, row.Note = "matched", cve+": the scan template matches, the flaw is still there."
		input := recheckInput(targets, hit.Target)
		ev := Evidence{
			// Review M3: only validated parts: the pack path, the address that passed the argv grammar and the job's input.
			// The device name comes from the network (DHCP, mDNS) and could plant a fake command; it is never in here.
			Summary:  fmt.Sprintf("Safe scan template %s matched on %s. To check it yourself, run: nuclei -t %s -u %s", tpl.Path, d.IP, tpl.Path, input),
			Template: tpl.Path, Request: hit.Request, Response: hit.Response, CheckedAt: s.now().UTC(),
		}
		if id, err := s.cfg.Findings.ConfirmFromScan(ctx, d.ID, cve, ev); err != nil {
			s.cfg.Log.ErrorContext(ctx, "scan: recording a confirmed finding failed", "asset", d.ID, "cve", cve, "error", err)
		} else {
			row.FindingID = ptr(id)
		}
		s.publish(ctx, EventFindingConfirmed, FindingConfirmedEvent{AssetID: d.ID, CVE: cve, Template: tpl.Path, Evidence: ev.Summary})
	case seen && !answered:
		row.Result, row.Note = "no_response", cve+": no answer for this check."
	default:
		// A not-matched line is "no match reported", never "not vulnerable". It never
		// resolves, downgrades or marks the finding: nothing is sent to the findings module.
		row.Result, row.Note = "not_matched", cve+": no match reported by the scan template."
	}
	return row
}

// ---- probe log ----

type probeRow struct{ id, template string }

// writeProbes writes one probe row per template before the job leaves core (INV-7).
func (s *Service) writeProbes(ctx context.Context, runID string, d Device, checks []check) ([]probeRow, error) {
	now := store.FormatTS(s.now())
	var out []probeRow
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		out = out[:0]
		for _, c := range checks {
			for _, t := range c.tpls {
				id := store.NewID("pr")
				if _, err := tx.ExecContext(ctx, `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					id, now, runID, d.IP, clip(d.Label, 300), t.Path, t.Request); err != nil {
					return fmt.Errorf("scan: writing the probe log: %w", err)
				}
				out = append(out, probeRow{id: id, template: t.ID})
			}
		}
		return nil
	})
	return out, err
}

// noteSkipped writes what nucleiout skipped (lines that cannot be a result of the job: the run is kept) to the core log
// and after the request text of the probe rows of the templates those lines were of (cut to the row, never the request: review
// r1 L7), so the probe log says it.
func (s *Service) noteSkipped(ctx context.Context, runID string, d Device, rows []probeRow, sk nucleiout.Skipped) {
	if sk.Lines == 0 {
		return
	}
	s.cfg.Log.WarnContext(ctx, "scan: nuclei printed lines that cannot be a result of the job; skipped, the run is kept", "asset", d.ID, "run", runID,
		"lines", sk.Lines, "matched", sk.Matched, "template", sk.Template, "host", sk.Host, "port", sk.Port)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			if !slices.Contains(sk.Templates, r.template) {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE scan_probe SET request = request || substr(?, 1, max(0, 300 - length(request))) WHERE id = ?`, sk.Note(), r.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: noting skipped lines in the probe log failed", "error", err)
	}
}

// closeProbes fills in the results; it runs even when the run was stopped (INV-7).
func (s *Service) closeProbes(ctx context.Context, rows []probeRow, result func(template string) string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			res := result(r.template)
			if res == "" {
				res = "no_response"
			}
			if _, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = ? WHERE id = ? AND result IS NULL`, res, r.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: closing the probe log failed", "error", err)
	}
}

func (s *Service) publish(ctx context.Context, name string, data any) {
	if s.cfg.Publisher == nil {
		return
	}
	if err := s.cfg.Publisher.Publish(ctx, events.Event{Name: name, Data: data}); err != nil {
		s.cfg.Log.WarnContext(ctx, "scan: publishing an event failed", "event", name, "error", err)
	}
}
