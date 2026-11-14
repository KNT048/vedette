package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

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
	// StopReason says why a stopped run was stopped when it was not a person's Stop (D-566 review r1 M1); nil otherwise.
	StopReason *string `json:"stop_reason,omitempty"`
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

	prevLast    time.Time // the target's lastScan before this run, put back when the scan module was off (nothing was asked)
	hadPrevLast bool
	mode        ScanMode // what this run may do (D-566): set when it starts; withdrawing or lowering the terms stops a run above them
}

// stoppedBy is the cause of a run's context when someone stopped it or the module was switched off.
type stoppedBy struct {
	by  string
	why string // why the box stopped it, for the page (D-566 review r1 M1: the testing terms were withdrawn); "" for a Stop
}

func (e *stoppedBy) Error() string { return "stopped by " + e.by }

// begin registers a run and starts it in the background, or refuses (INV-1, INV-18): the gate's reason, no runner (501), another
// run (409 busy), the same target within ScanEvery (429). The run's context comes from the Service, not from the request, so the
// scan goes on after the 202 has been sent; it ends when its last step returns (each step has its own cap: 5 minutes for the runner,
// service identification and the templates, 8 minutes a page for ZAP, 90 minutes for the optional Greenbone step; FULL-4 (Trưởng),
// for Mlee: 70 minutes for the service step of a deep scan, FullServicesTimeout, D-526), or on StopScan. No cap covers the whole run.
func (s *Service) begin(ctx context.Context, user string, t Target, reason BlockedReason) (*scanRun, error) {
	if reason != "" {
		return nil, s.refusal(t, reason, s.clock())
	}
	r := s.scanRunner()
	if r == nil {
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
	if s.feedSync {
		return nil, s.errScanFeedSync(s.feedSyncAt)
	}
	now := s.clock()
	last, had := s.lastScan[t.ID]
	if had && now.Sub(last) < ScanEvery && !last.After(now) {
		next := last.Add(ScanEvery)
		return nil, apiErr(429, "rate_limited", "%s was scanned at %s. Scan it again after %s: at most one scan of a target every %d minutes.",
			t.Value, s.momentText(last), s.momentText(next), int(ScanEvery/time.Minute))
	}
	// The run's mode comes from a fresh read of the terms under runMu (D-566 review r2 M1): a withdrawal committed while the gate ran
	// is seen here, and one that comes later finds this run registered and stops it (stopRunAbove takes runMu too).
	fresh, err := loadTarget(ctx, s.cfg.DB.Reader(), t.ID)
	if err != nil {
		return nil, fmt.Errorf("exposure: reading the testing terms before the scan: %w", err)
	}
	s.lastScan[t.ID] = now
	rctx, cancel := context.WithCancelCause(context.WithoutCancel(ctx)) // the request's values, never its cancellation
	run := &scanRun{
		view:   ScanRun{ID: store.NewID("sr"), TargetID: t.ID, TargetValue: t.Value, By: user, StartedAt: store.FormatTS(now), Status: RunRunning, Phase: PhaseQueued},
		cancel: cancel, done: make(chan struct{}), prevLast: last, hadPrevLast: had, mode: fresh.mode(),
	}
	s.run = run
	go s.execute(rctx, run, r, user, t)
	return run, nil
}

func (s *Service) setPhase(run *scanRun, phase string) {
	s.runMu.Lock()
	run.view.Phase = phase
	s.runMu.Unlock()
}

// execute is the background half of a scan: the runner, then one snapshot for the day with its audit row and event (POST-1). Every
// run ends here with exactly one exposure.scan audit row and one final state.
func (s *Service) execute(ctx context.Context, run *scanRun, r Runner, user string, t Target) {
	defer run.cancel(nil)
	defer func() { // the runner parses untrusted data; a panic must end this run, not the box (the request pipeline would have answered 500)
		if p := recover(); p != nil {
			s.cfg.Log.ErrorContext(ctx, "an exposure scan panicked", "target", t.Value, "panic", p, "stack", string(debug.Stack()))
			s.finish(ctx, run, user, t, fmt.Errorf("exposure: the scan panicked: %v", p))
		}
	}()
	s.setPhase(run, PhaseProbing)
	st := ScanTarget{ID: t.ID, Kind: t.Kind, Value: t.Value, User: user, Mode: run.mode}
	content, err := r.Scan(ctx, st)
	if err == nil {
		content, err = s.identify(ctx, st, content) // INV-19: service identification of the box's own IP, and what was checked
	}
	if err == nil {
		content, err = s.webPassive(ctx, st, content) // INV-24: passive web scan of its web ports
	}
	gb, pending := false, ""
	if err == nil { // INV-25: the optional deep scan runs last, after the snapshot of the other steps is stored
		var line string
		if gb, line, err = s.greenbonePlan(ctx, st); gb {
			pending = gbPending(s.momentText(s.clock()))
			line = pending
		}
		if err == nil {
			content.NotChecked = append(content.NotChecked, NotCheckedRow{Kind: "greenbone", Text: line})
		}
	}
	if err == nil && ctx.Err() != nil { // stopped just as it finished: nothing is stored
		err = context.Cause(ctx)
	}
	if err == nil {
		s.setPhase(run, PhaseSaving)
		run.snap, err = s.saveScan(ctx, user, t, content)
	}
	if err == nil && gb { // a stop now keeps the snapshot above; Greenbone's outcome (or that it was stopped) is added to it
		s.setPhase(run, PhaseGreenbone)
		o, gerr := s.greenboneStep(ctx, st)
		if gerr != nil {
			o.not = append([]NotCheckedRow{{Kind: "greenbone", Text: notGBStopped}}, o.not...)
			if o.audit == "" {
				o.audit = "stopped"
			}
			err = gerr
		}
		s.addGreenbone(ctx, user, t, &run.snap, pending, o)
	}
	if err != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) { // the run was cut short; any other error is the real one
		err = context.Cause(ctx)
	}
	s.finish(ctx, run, user, t, err)
}

func (s *Service) saveScan(ctx context.Context, user string, t Target, content Content) (Snapshot, error) {
	at := s.clock()
	content = sanitize(content)
	extra := ""
	if t.Kind == KindIP {
		extra = t.Value
	}
	date := at.In(s.cfg.Location).Format(dayFormat)
	snap := Snapshot{ID: store.NewID("sn"), Date: date, ScannedAt: store.FormatTS(at),
		Vulns: []VulnRow{}, VersionGaps: []GapRow{}} // computed when read (INV-20); never null in an answer
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	// INV-22: carry what the last observation (a scan today counts) had open and this scan did not report. One scan runs at a time, so
	// reading it before the write is safe; the address gate (ScannableIP) must not run inside the write transaction.
	if prev, ok, err := previousSnapshot(wctx, s.cfg.DB.Reader(), t.ID, date); err != nil {
		return Snapshot{}, err
	} else if ok {
		content = carryNotSeen(content, prev, s.coveredBy(wctx, user, t, content, prev))
	}
	snap.Content, snap.Counts = content, countsOf(content, extra, at)
	err := s.write(wctx, func(tx *sql.Tx, emit func(string, any)) error {
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
	kept := run.snap.ID != "" // stopped during the Greenbone step: the snapshot of the other steps is stored and already audited
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
	if errors.Is(err, ErrScanOff) { // the scan module was off: nothing was asked or probed, so it does not count against ScanEvery
		if run.hadPrevLast {
			s.lastScan[t.ID] = run.prevLast
		} else {
			delete(s.lastScan, t.ID)
		}
	}
	s.runMu.Unlock()
	close(run.done)
}

func (s *Service) runView(run *scanRun) ScanRun {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return run.view
}

// CurrentScan is GET /exposure/scan: the run that runs now, or the last one; nil when none has run since the box started (INV-18).
func (s *Service) CurrentScan() *ScanRun {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.run == nil {
		return nil
	}
	v := s.run.view
	return &v
}

// cancelRun cancels the run that runs now, if any, and does not wait for it. by is who stopped it, for the audit row.
func (s *Service) cancelRun(by string) *scanRun {
	s.runMu.Lock()
	run := s.run
	if run == nil || run.view.Status != RunRunning {
		s.runMu.Unlock()
		return nil
	}
	s.runMu.Unlock()
	run.cancel(&stoppedBy{by: by})
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
	s.runMu.Unlock()
	if !enabled {
		s.cancelRun("the box (the Exposure module was switched off)")
		s.gbModuleOff() // FULL-2 (Trưởng), for Mlee: Greenbone's containers stop with the module (D-529)
		return
	}
	s.GreenboneAtStart(context.Background()) // FULL-2 (Trưởng), for Mlee: and start again with it when it is enabled
}

// closeWait bounds Close: a runner that ignores its context must not hold the shutdown until its own 5-minute cap.
const closeWait = 30 * time.Second

// Close ends the shutdown of the box: no new run starts, the run that runs is cancelled and Close waits for it, at most closeWait,
// so its exposure.scan audit row is written before the database closes (LEGAL §3).
func (s *Service) Close() {
	s.runMu.Lock()
	s.closed = true
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
	s.waitSync(syncDone) // the host must not keep pulling the feed after the box stops (review r1 L2)
	if run := s.cancelRun("the box (shutting down)"); run != nil {
		select {
		case <-run.done:
		case <-time.After(closeWait):
			s.cfg.Log.Error("exposure: the running scan did not stop at shutdown; its audit row may be missing")
		}
	}
}
