package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/store"
)

// Scan run states and phases (contract.ts ScanRun, INV-18).
const (
	RunRunning = "running"
	RunDone    = "done"
	RunFailed  = "failed"
	RunStopped = "stopped"

	PhaseQueued  = "queued"  // accepted, the goroutine has not started the scan yet
	PhaseProbing = "probing" // the scan module's runner is scanning the target
	PhaseSaving  = "saving"  // the result is being limited and stored
	// PhaseGreenbone: the snapshot of the other steps is stored and Greenbone scans the IP (up to 90 minutes, INV-25); the box's one
	// scan slot stays busy until it ends.
	PhaseGreenbone = "greenbone"
	PhaseDone      = "done" // the snapshot exists
)

// saveTimeout bounds the write of a finished scan, which must not depend on the request that started it.
const saveTimeout = 30 * time.Second

// ScanRun is one scan as the page sees it (contract.ts ScanRun). It lives in memory only (INV-18): after a restart there is no run.
type ScanRun struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	TargetValue string    `json:"target_value"`
	By          string    `json:"by"`
	StartedAt   string    `json:"started_at"`
	FinishedAt  *string   `json:"finished_at"`
	Status      string    `json:"status"`
	Phase       string    `json:"phase"`
	SnapshotID  *string   `json:"snapshot_id"`
	Error       *RunError `json:"error"`
	// StopReason says why a stopped run was stopped when it was not a person's Stop; nil otherwise.
	StopReason *string `json:"stop_reason,omitempty"`
	// OpenVASOnly: the run is OpenVAS again for the newest scan of the target (POST …/openvas), not a scan.
	OpenVASOnly bool `json:"openvas_only,omitempty"`
	// Progress is how far the step that runs now is (#830): the nmap and nuclei jobs of the scan module as the scan worker reports
	// them, OpenVAS's own percent in the greenbone phase. Only while the run is running; null otherwise. In memory, like the run.
	Progress *progress.View `json:"progress"`
	// Scheduled: the run is a scheduled scan of the target (INV-36), started by the box.
	Scheduled bool `json:"scheduled,omitempty"`
	// Queue is the scans that wait after this one, in order (INV-36); left out when none waits.
	Queue []QueuedScan `json:"queue,omitempty"`
}

// RunError is why a run failed: the code and text of the API error the synchronous scan used to answer.
type RunError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// scanRun is the Service's record of a run. view is guarded by Service.runMu; snap and err are written before done is closed.
type scanRun struct {
	view   ScanRun
	cancel context.CancelCauseFunc
	done   chan struct{}
	snap   Snapshot
	err    error

	prevLast    time.Time // the target's lastScan before this run, put back when the runner found the module off (nothing was asked)
	hadPrevLast bool
	mode        ScanMode          // what this run may do: set when it starts; withdrawing or lowering the terms stops a run above them
	gbSnap      string            // the snapshot whose OpenVAS step runs now (set under runMu): its "running" is real
	prog        *progress.Tracker // #830: the progress of the run; its context carries it to the jobs that report
	steps       *stepLog          // #861 (INV-30): what nuclei, ZAP and OpenVAS did in this run; its context carries it to the steps
	queued      *queuedScan       // INV-36: the queued scan this run is (nil for a scan that started at once); a scheduled one compares
}

// stoppedBy is the cause of a run's context when someone stopped it, the module was switched off, the box shut down or the
// testing terms were withdrawn.
type stoppedBy struct {
	by     string // who or what stopped it, for the audit row
	why    string // why the box stopped it, for the page (the testing terms were withdrawn, Vedette shut down); "" for a Stop
	reason string // GreenboneStop.Reason: StopPerson, StopShutdown, StopModule or StopTerms
	person string // the e-mail of the person behind it (a Stop, a change of the terms); "" for the box
}

func (e *stoppedBy) Error() string { return "stopped by " + e.by }

// stop is the GreenboneStop of this cause.
func (e *stoppedBy) stop() *GreenboneStop {
	st := &GreenboneStop{Reason: e.reason}
	if !slices.Contains(stopReasons, st.Reason) {
		st.Reason = StopPerson
	}
	if e.person != "" {
		p := e.person
		st.By = &p
	}
	return st
}

// stopOf is why a run that ended with err was stopped; nil when it was not stopped.
func stopOf(err error) *GreenboneStop {
	var sb *stoppedBy
	if errors.As(err, &sb) {
		return sb.stop()
	}
	return nil
}

// stopWhy is the reason of a stop in words, for the lines a scan stores and the engines' last runs ("" for nil): never a time (the
// page shows GreenboneRun.EndedAt in the viewer's time zone).
func stopWhy(st *GreenboneStop) string {
	if st == nil {
		return ""
	}
	by := "someone"
	if st.By != nil && *st.By != "" {
		by = *st.By
	}
	switch st.Reason {
	case StopShutdown:
		return "Vedette shut down: an update, a restart or a stop of the service"
	case StopRestart:
		return "Vedette restarted"
	case StopModule:
		return "the External exposure module was switched off"
	case StopTerms:
		return "the testing terms of this target were withdrawn or lowered by " + by
	}
	return by + " pressed Stop"
}

// begin registers a run and starts it in the background, or refuses (INV-1, INV-18): the gate's reason, no runner (501), another
// run (409 busy), the same target within ScanEvery (429). The run's context comes from the Service, not from the request, so the
// scan goes on after the 202 has been sent; it ends when its last step returns (each step has its own cap: 5 minutes for the runner and the
// templates, 8 minutes for service identification (ServicesTimeout) and a page for ZAP, 90 minutes for the optional Greenbone step;
// 70 minutes for the service step of a deep scan, FullServicesTimeout), or on StopScan. No cap covers the whole run.
//
// With a (POST …/openvas) the run is OpenVAS again on a's snapshot (executeAgain): it needs no runner. With q the run is that queued
// scan (INV-36): it takes q's id and leaves the queue; without q, scans that wait go first (409 busy).
func (s *Service) begin(ctx context.Context, user string, t Target, reason BlockedReason, a *again, q *queuedScan) (*scanRun, error) {
	if reason != "" {
		return nil, s.refusal(t, reason, s.clock())
	}
	r := s.scanRunner()
	if r == nil && a == nil {
		return nil, ErrNotImplemented
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.off || s.closed { // the gate took seconds: the module may have been switched off meanwhile (SYS-5)
		return nil, ErrModuleOff
	}
	if s.run != nil && s.run.view.Status == RunRunning {
		return nil, ErrScanBusy
	}
	if q == nil && len(s.queue) > 0 { // the scans that wait go first
		return nil, ErrScanBusy
	}
	if s.feedSync {
		return nil, s.errScanFeedSync(s.feedSyncAt)
	}
	now := s.clock()
	if err := s.tooSoonLocked(t, now); err != nil {
		return nil, err
	}
	last, had := s.lastScan[t.ID]
	// The run's mode comes from a fresh read of the terms under runMu: a withdrawal committed while the gate ran
	// is seen here, and one that comes later finds this run registered and stops it (stopRunAbove takes runMu too).
	fresh, err := loadTarget(ctx, s.cfg.DB.Reader(), t.ID)
	if err != nil {
		return nil, fmt.Errorf("exposure: reading the testing terms before the scan: %w", err)
	}
	mode := fresh.mode()
	if q != nil && q.scheduled { // INV-36: decided under runMu, so terms withdrawn while the checks ran are seen here
		if why := scheduleWhy(fresh, now); why != "" {
			return nil, &skipError{why: why, stored: true}
		}
		if r := fresh.blocked(now); r != "" { // the ownership check the gate just stored, as the gate would answer it
			return nil, &skipError{why: gateWhy(fresh, r, now)}
		}
		mode.Disruptive = false // a scan the box starts by itself never runs the disruptive checks
	}
	s.lastScan[t.ID] = now
	rctx, cancel := context.WithCancelCause(context.WithoutCancel(ctx)) // the request's values, never its cancellation
	run := &scanRun{
		view:   ScanRun{ID: store.NewID("sr"), TargetID: t.ID, TargetValue: t.Value, By: user, StartedAt: store.FormatTS(now), Status: RunRunning, Phase: PhaseQueued},
		cancel: cancel, done: make(chan struct{}), prevLast: last, hadPrevLast: had, mode: mode, prog: progress.NewTracker(s.clock),
		steps: &stepLog{},
	}
	rctx = withSteps(progress.WithSink(rctx, run.prog), run.steps)
	if q != nil { // the queued scan starts: it keeps the id its place had and leaves the queue
		run.view.ID, run.view.Scheduled, run.queued = q.id, q.scheduled, q
		s.removeLocked(q)
	}
	s.run = run
	if a != nil { // no runner step: the run is the OpenVAS step from the start
		run.view.OpenVASOnly, run.view.Phase = true, PhaseGreenbone
		go s.executeAgain(rctx, run, user, t, *a)
		return run, nil
	}
	go s.execute(rctx, run, r, user, t)
	return run, nil
}

// tooSoonLocked is the 429 of a target scanned less than ScanEvery ago (nil otherwise). The caller holds runMu.
func (s *Service) tooSoonLocked(t Target, now time.Time) error {
	last, had := s.lastScan[t.ID]
	if had && now.Sub(last) < ScanEvery && !last.After(now) {
		next := last.Add(ScanEvery)
		return apiErr(429, "rate_limited", "%s was scanned at %s. Scan it again after %s: at most one scan of a target every %d minutes.",
			t.Value, s.momentText(last), s.momentText(next), int(ScanEvery/time.Minute))
	}
	return nil
}

func (s *Service) setPhase(run *scanRun, phase string) {
	s.runMu.Lock()
	run.view.Phase = phase
	s.runMu.Unlock()
	if phase == PhaseGreenbone { // #830: until OpenVAS gives its first percent
		run.prog.Report(progress.Phase(progress.PhaseOpenVAS, ""))
	}
}

// execute is the background half of a scan: the runner, then one snapshot for the day with its audit row and event (POST-1). Every
// run ends here with exactly one exposure.scan audit row and one final state.
func (s *Service) execute(ctx context.Context, run *scanRun, r Runner, user string, t Target) {
	defer run.cancel(nil)
	defer func() { // the runner parses untrusted data; a panic must end this run, not the box (the request pipeline would have answered 500)
		if p := recover(); p != nil {
			s.cfg.Log.ErrorContext(ctx, "an exposure scan panicked", "target", t.Value, "panic", p, "stack", string(debug.Stack()))
			s.finish(ctx, run, user, t, fmt.Errorf("%w: %v", errScanPanicked, p))
		}
	}()
	s.setPhase(run, PhaseProbing)
	run.prog.Report(progress.Phase(progress.PhasePorts, "")) // #830: the jobs below report their own phases as they run
	st := ScanTarget{ID: t.ID, Kind: t.Kind, Value: t.Value, User: user, Mode: run.mode, Typed: t.Typed}
	if t.proofDomain != "" { // the domain whose token proved the target at the gate, and the name its record sits on when not that domain's own
		st.Proof = &ProofOwner{Domain: t.proofDomain, Token: t.proofToken, ProofAt: t.proofAt}
	}
	if t.Typed && st.Mode.Full { // the deep steps of a typed IP carry its live proof to the executors
		if scope, why := s.typedScope(ctx, t); scope != nil {
			st.Domain = scope
		} else {
			st.Mode, st.TypedWhy = ScanMode{}, why
		}
	} else if t.Typed {
		st.TypedWhy = typedTerms
	}
	content, err := r.Scan(ctx, st)
	content.Hosts = clearDeep(content.Hosts) // The deep state of a run is exposure's own, never the runner's
	deepDomain := st.Kind == KindDomain && st.Mode.Full
	if err == nil {
		content, err = s.identify(ctx, st, content) // INV-19: service identification of the box's own IP, and what was checked
	}
	if err == nil && !deepDomain { // INV-30: no more template calls in this run
		run.steps.close(StepNuclei)
	}
	if err == nil {
		run.prog.Report(progress.Phase(progress.PhaseWeb, ""))
		content, err = s.webPassive(ctx, byName(st), content) // INV-24: passive web scan of its web ports
	}
	if err == nil {
		run.steps.close(StepZAP)
	}
	var deep []deepAddr
	if err == nil && deepDomain { // Each address of the names at the domain's terms depth
		content, deep, err = s.deepDomain(ctx, st, content)
		if err == nil {
			run.steps.close(StepNuclei)
		}
	}
	gb, gbRun := false, GreenboneRun{State: GBRunNotRun}
	var gbIP []int  // the open TCP ports of an IP target OpenVAS checks
	if err == nil { // INV-25: the optional deep scan runs last, after the snapshot of the other steps is stored
		var line string
		gb, line, err = s.greenbonePlan(ctx, st)
		if gb && st.Kind == KindDomain && len(deep) == 0 {
			gb, line = false, notGBNoDeep
		}
		if ip, perr := netip.ParseAddr(st.Value); gb && st.Kind == KindIP && perr == nil {
			gbIP = gbPorts(content.Ports, ip)
			if l := gbPortsLine(gbIP); l != "" { // no open port to check: OpenVAS is not started at all
				gb, line = false, l
			}
		}
		if gb {
			at := store.FormatTS(s.clock())
			line, gbRun = gbPending, GreenboneRun{State: GBRunRunning, StartedAt: &at}
		}
		if err == nil {
			content.NotChecked = append(content.NotChecked, NotCheckedRow{Kind: "greenbone", Text: line})
		}
	}
	if err == nil && ctx.Err() != nil { // stopped just as it finished: nothing is stored
		err = context.Cause(ctx)
	}
	if err == nil {
		id := store.NewID("sn")
		s.runMu.Lock() // Its "running" is live from the moment it is stored, never read as cut off
		run.view.Phase = PhaseSaving
		run.prog.Report(progress.Phase(progress.PhaseSaving, ""))
		if gb {
			run.gbSnap = id
		}
		s.runMu.Unlock()
		run.snap, err = s.saveScan(ctx, user, t, content, id, gbRun, run.view.StartedAt)
	}
	if err == nil { // INV-30: nuclei's and ZAP's last runs are on the cards while OpenVAS still runs
		s.saveSteps(ctx, run, runOn, "")
	}
	if err == nil && gb { // a stop now keeps the snapshot above; Greenbone's outcome (or that it was stopped) is added to it
		err = s.openVASPart(ctx, run, user, t, func() (gbOutcome, error) {
			if st.Kind == KindDomain {
				return s.greenboneDomain(ctx, st, deep, content.Ports)
			}
			return s.greenboneStep(ctx, st, gbIP)
		})
	}
	if err != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) { // the run was cut short; any other error is the real one
		err = context.Cause(ctx)
	}
	s.finish(ctx, run, user, t, err)
}

// openVASPart runs the OpenVAS step of a run whose snapshot is stored (run.snap) and adds its outcome to that snapshot: a stop keeps
// the snapshot, with the line that says why, and is the run's error. The scan's own last step, and the whole of a run of OpenVAS again.
func (s *Service) openVASPart(ctx context.Context, run *scanRun, user string, t Target, step func() (gbOutcome, error)) error {
	s.setPhase(run, PhaseGreenbone)
	o, err := step()
	if err != nil {
		o.stop = stopOf(context.Cause(ctx))
		o.not = append([]NotCheckedRow{{Kind: "greenbone", Text: gbStoppedLine(o.stop, len(o.rows) > 0)}}, o.not...) // a domain keeps the rows of the addresses that finished
		if o.audit == "" {
			o.audit = "stopped"
		}
		if w := stopWhy(o.stop); w != "" {
			o.audit += " (" + w + ")"
		}
		o.state = GBRunStopped
	}
	outcome, text := openVASStep(o.state, len(o.rows), o.stop)
	run.steps.set(StepOpenVAS, outcome, text, s.clock())
	s.addGreenbone(ctx, user, t, &run.snap, o)
	return err
}

// gbStoppedLine is the OpenVAS line of a step that was stopped: why, when it is known, and that the rows of a domain's addresses that
// finished (some) are kept.
func gbStoppedLine(st *GreenboneStop, some bool) string {
	why := stopWhy(st)
	switch {
	case why == "" && some:
		return notGBStoppedSome
	case why == "":
		return notGBStopped
	case some:
		return "OpenVAS was stopped (" + why + ") before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept."
	}
	return "OpenVAS was stopped before it finished (" + why + "), so its results are not shown. The results of the other checks above are kept."
}

// byName is the ScanTarget of a domain's by-name passive web pass (INV-24): always the basic scope, whatever the terms. The deep
// scan by name of each address, with the terms' mode and the domain's scope, is deepDomain's.
func byName(st ScanTarget) ScanTarget {
	if st.Kind == KindDomain {
		st.Mode = ScanMode{}
	}
	return st
}

func (s *Service) saveScan(ctx context.Context, user string, t Target, content Content, id string, gbRun GreenboneRun, started string) (Snapshot, error) {
	at := s.clock()
	// INV-22: the marks of a carried port come only from carryNotSeen below, never from what the runner sent (sanitize keeps them, for
	// the Greenbone re-save of a stored snapshot)
	for i := range content.Ports {
		content.Ports[i].LastSeen, content.Ports[i].Misses, content.Ports[i].Unchecked = "", 0, false
	}
	content = sanitize(content)
	extra := ""
	if t.Kind == KindIP {
		extra = t.Value
	}
	day := at // the scan's day is the day it started (INV-34), like its name on every page
	if st, err := parseTS(started); err == nil {
		day = st
	}
	date := day.In(s.loc()).Format(dayFormat)
	snap := Snapshot{ID: id, Date: date, ScannedAt: store.FormatTS(at), StartedAt: cmp.Or(started, store.FormatTS(at)), GreenboneRun: gbRun,
		Vulns: []VulnRow{}, VersionGaps: []GapRow{}} // computed when read (INV-20); never null in an answer
	if gbRun.State != GBRunRunning { // the scan ends here; one whose OpenVAS step starts now ends when that step does (addGreenbone)
		snap.FinishedAt = &snap.ScannedAt
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	// INV-22: carry what the last observation (a scan today counts) had open and this scan did not report. One scan runs at a time, so
	// reading it before the write is safe; the address gate (ScannableIP) must not run inside the write transaction.
	prev, ok, err := previousSnapshot(wctx, s.cfg.DB.Reader(), t.ID, date)
	if err != nil {
		return Snapshot{}, err
	}
	content = carryHosts(content, prev, ok) // INV-27: names whose lookup failed keep their last rows, so their addresses are not "moved"
	if ok {
		content = carryNotSeen(content, prev, s.coveredBy(wctx, user, t, content, prev))
	}
	content.AdminPanels = applianceAdmins(content.AdminPanels, content.Ports, content.Services) // an appliance's admin page on any port
	snap.Content, snap.Counts = content, countsOf(content, extra, at)
	err = s.write(wctx, func(tx *sql.Tx, emit func(string, any)) error {
		if _, err := loadTarget(wctx, tx, t.ID); err != nil { // deleted while the scan ran
			return err
		}
		if err := upsertSnapshot(wctx, tx, t.ID, snap); err != nil {
			return err
		}
		detail := fmt.Sprintf("%d subdomains, %d ports", snap.Counts.Subdomains, snap.Counts.Ports)
		if n := keptPorts(snap.Ports); n > 0 {
			detail += fmt.Sprintf(" (%d kept from an earlier scan)", n)
		}
		if err := s.audit(wctx, tx, user, "exposure.scan", t.Value, detail); err != nil {
			return err
		}
		emit(EventSnapshotCreated, SnapshotCreatedEvent{TargetID: t.ID, Date: snap.Date, Counts: snap.Counts})
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// finish records the end of a run: the audit row of one that ended without a snapshot, and the final state the page reads.
func (s *Service) finish(ctx context.Context, run *scanRun, user string, t Target, err error) {
	kept := run.snap.ID != ""                                  // stopped during the Greenbone step: the snapshot of the other steps is stored and already audited
	s.saveSteps(ctx, run, runEndOf(err), stopWhy(stopOf(err))) // INV-30: before the run reads as ended, so its steps are on the cards when it does
	if err != nil && !kept {
		s.auditFailedScan(ctx, user, t, err)
	}
	s.runMu.Lock()
	run.err = err
	now := store.FormatTS(s.clock())
	v := &run.view
	v.FinishedAt = &now
	var sb *stoppedBy
	var ae *APIError
	switch {
	case err == nil:
		v.Status, v.Phase, v.SnapshotID = RunDone, PhaseDone, &run.snap.ID
	case errors.As(err, &sb):
		v.Status = RunStopped
		if sb.why != "" {
			why := sb.why
			v.StopReason = &why
		}
		if kept {
			v.SnapshotID = &run.snap.ID
		}
	case errors.As(err, &ae):
		v.Status, v.Error = RunFailed, &RunError{Code: ae.Code, Message: ae.Message}
	default:
		s.cfg.Log.ErrorContext(ctx, "an exposure scan failed", "target", t.Value, "error", err)
		v.Status, v.Error = RunFailed, &RunError{Code: "internal", Message: "The scan stopped because of an error on the box, so nothing was saved. Try again; if it keeps happening, check the box logs."}
	}
	if errors.Is(err, ErrScanOff) { // the runner found the module off: nothing was asked or probed, so it does not count against ScanEvery
		if run.hadPrevLast {
			s.lastScan[t.ID] = run.prevLast
		} else {
			delete(s.lastScan, t.ID)
		}
	}
	s.runMu.Unlock()
	if q := run.queued; q != nil && q.scheduled { // INV-36
		if run.snap.ID != "" { // a snapshot was stored (OpenVAS may have failed or been stopped after it): what is new is alerted
			s.alertChanges(ctx, t, q.prev, run.snap)
		} else if err != nil { // nothing stored: the target says why, and when the schedule tries again
			s.noteRunEnd(ctx, q, t, err)
		}
	}
	s.dispatch() //nolint:contextcheck // the next queued scan runs on the service's own context, not on this run's
	close(run.done)
}

func (s *Service) runView(run *scanRun) ScanRun {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return run.withProgress()
}

// withProgress is the view with the progress of a running run (#830). The caller holds runMu.
func (r *scanRun) withProgress() ScanRun {
	v := r.view
	if v.Status == RunRunning && r.prog != nil {
		v.Progress = r.prog.View()
	}
	return v
}

// CurrentScan is GET /exposure/scan: the run that runs now, or the last one; nil when none has run since the box started (INV-18).
func (s *Service) CurrentScan() *ScanRun {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.run == nil {
		if len(s.queue) == 0 {
			return nil
		}
		v := s.queuedViewLocked(s.queue[0]) // nothing ran since the box started, and scans wait: the first is about to start
		return &v
	}
	v := s.run.withProgress()
	v.Queue = s.queueViewsLocked()
	return &v
}

// cancelRun cancels the run that runs now, if any, and does not wait for it: the Stop of a person, by (for the audit row and the page).
func (s *Service) cancelRun(by string) *scanRun {
	return s.cancelRunWith(&stoppedBy{by: by, reason: StopPerson, person: by})
}

// cancelRunWith cancels the run that runs now, if any, with the cause sb, and does not wait for it.
func (s *Service) cancelRunWith(sb *stoppedBy) *scanRun {
	s.runMu.Lock()
	run := s.run
	if run == nil || run.view.Status != RunRunning {
		s.runMu.Unlock()
		return nil
	}
	s.runMu.Unlock()
	run.cancel(sb)
	return run
}

// stopWait is how long Stop waits for the run to end before it answers with the state it has (a runner that ignores its context).
const stopWait = 10 * time.Second

// StopScan is CancelScan that waits until the run has ended, at most stopWait (POST /exposure/scan/stop). It returns the run's state
// and false when no run was running. The state is stopped; it is still running only when the runner did not end within stopWait.
func (s *Service) StopScan(ctx context.Context, by string) (ScanRun, bool) {
	run := s.cancelRun(by)
	if run == nil {
		return ScanRun{}, false
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopWait)
	defer cancel()
	select {
	case <-run.done:
	case <-wctx.Done():
	}
	return s.runView(run), true
}

// ModuleSwitched is the Registry subscriber of the module's switch (SYS-5): off cancels the run and makes begin refuse until it is
// on again, so a scan whose gate was still running when the switch came cannot start. It does not wait.
func (s *Service) ModuleSwitched(enabled bool) {
	s.runMu.Lock()
	s.off = !enabled
	if !enabled { // the scans that wait do not run; a scheduled one is queued again by the schedule once the module is on
		s.clearQueueLocked()
	}
	s.runMu.Unlock()
	if !enabled {
		s.cancelRunWith(&stoppedBy{by: "the box (the Exposure module was switched off)", why: stopWhy(&GreenboneStop{Reason: StopModule}), reason: StopModule})
		s.gbModuleOff(s.bg) // Greenbone's containers stop with the module
		return
	}
	s.GreenboneAtStart(s.bg) // and start again with it when it is enabled
}

// closeWait bounds Close: a runner that ignores its context must not hold the shutdown until its own 5-minute cap.
const closeWait = 30 * time.Second

// Close ends the shutdown of the box: no new run starts, the run that runs is cancelled and Close waits for it, at most closeWait,
// so its exposure.scan audit row is written before the database closes (LEGAL §3).
func (s *Service) Close() {
	s.runMu.Lock()
	s.closed = true
	s.clearQueueLocked()
	s.runMu.Unlock()
	g := s.gb() // a Greenbone start that is still pulling images, or its feed update, ends with the box
	g.mu.Lock()
	if g.upCancel != nil {
		g.upCancel()
	}
	if g.syncCancel != nil {
		g.syncCancel()
	}
	syncDone := g.syncDone
	g.mu.Unlock()
	s.waitSync(syncDone) // the host must not keep pulling the feed after the box stops
	if run := s.cancelRunWith(&stoppedBy{by: "the box (shutting down)", why: "Vedette shut down", reason: StopShutdown}); run != nil {
		select {
		case <-run.done:
		case <-time.After(closeWait):
			s.cfg.Log.Error("exposure: the running scan did not stop at shutdown; its audit row may be missing")
			s.cutAtShutdown(run) // its OpenVAS step reads "stopped by a shutdown", not "a restart", at the next start
		}
	}
}

// errScanPanicked is the error of a run a panic ended (execute's recover): an error of the box, never a stop.
var errScanPanicked = errors.New("exposure: the scan panicked")

// runEndOf is how a run that ended with err ended, for its steps (INV-30).
func runEndOf(err error) int {
	var sb *stoppedBy
	switch {
	case errors.As(err, &sb):
		return runStopped
	case errors.Is(err, errScanPanicked):
		return runPanicked
	}
	return runEnded
}

// cutAtShutdown stores the OpenVAS step of run, when it still reads "running", as stopped by the shutdown: Close's wait ran out (OpenVAS
// took longer than closeWait to stop its task), and the process ends before the run writes its outcome. Failures are logged.
func (s *Service) cutAtShutdown(run *scanRun) {
	s.runMu.Lock()
	id, target := run.gbSnap, run.view.TargetID
	s.runMu.Unlock()
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(s.bg, saveTimeout)
	defer cancel()
	now := store.FormatTS(s.clock())
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		var date string
		if err := tx.QueryRowContext(ctx, `SELECT date FROM exp_snapshot WHERE id = ?`, id).Scan(&date); err != nil {
			return nil //nolint:nilerr // not stored yet, or replaced: nothing to mark
		}
		snap, ok, err := loadSnapshot(ctx, tx, target, date)
		if err != nil || !ok || snap.ID != id || snap.GreenboneRun.State != GBRunRunning {
			return err
		}
		return storeCut(ctx, tx, target, snap, now, &GreenboneStop{Reason: StopShutdown})
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: marking the OpenVAS step a shutdown cut as stopped failed", "error", err)
	}
}
