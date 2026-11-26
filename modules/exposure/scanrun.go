package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/progress"
	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// A scan of a target is a shared run (core/run) of kind exposure_scan in the exposure lane: the database holds the queue, so a scan
// asked while another runs waits in it and survives a restart, and one scan runs at a time on the box. Its engine steps (nuclei, ZAP,
// OpenVAS) are steps of the run, and the module's own facts about it are its exp_scan row. A restart stops a scan that was running
// ("Vedette restarted"); what it wrote before stays.
const (
	RunKind = "exposure_scan"
	RunLane = "exposure"
)

// The names of the steps of a scan's run. Settings › Scanning's engine cards read the newest ended step of each engine. stepSurface
// is the one step of the runs stored before the scan's steps were split (runsteps.go): a run that wrote its rows has it done.
const (
	stepSurface     = "Ports, names and services"
	stepNameNuclei  = "Templates (nuclei)"
	stepNameZAP     = "Passive web scan (ZAP)"
	stepNameZAPAct  = "Active web scan (ZAP)"
	stepNameOpenVAS = "OpenVAS"
)

// The engine steps of an external scan as Settings › Scanning shows them (INV-30): nuclei (the safe and the deep templates), ZAP
// (the passive web scan) and OpenVAS.
const (
	StepNuclei = "nuclei"
	StepZAP    = "zap"
	// StepZAPActive is ZAP's active scan, after the passive one, only in a scan a person starts (INV-24).
	StepZAPActive = "zap_active"
	StepOpenVAS   = "openvas"
)

// How a step of a run ended, as Settings › Scanning's last_run.outcome names it.
const (
	StepOK      = "ok"
	StepPartial = "partial"
	StepFailed  = "failed"
	StepStopped = "stopped"
)

var stepEngines = []string{StepNuclei, StepZAP, StepZAPActive, StepOpenVAS}

var stepNames = map[string]string{StepNuclei: stepNameNuclei, StepZAP: stepNameZAP, StepZAPActive: stepNameZAPAct, StepOpenVAS: stepNameOpenVAS}

var stepStatus = map[string]corerun.Status{StepOK: corerun.Done, StepPartial: corerun.Partial, StepFailed: corerun.Failed, StepStopped: corerun.Stopped}

// saveTimeout bounds the write of a finished scan, which must not depend on the request that started it.
const saveTimeout = 30 * time.Second

// Scan run states and phases of the old run view (contract.ts ScanRun), read from the shared run.
const (
	RunQueued  = "queued"
	RunRunning = "running"
	RunDone    = "done"
	RunFailed  = "failed"
	RunStopped = "stopped"

	PhaseQueued    = "queued"
	PhaseProbing   = "probing"
	PhaseGreenbone = "greenbone"
	PhaseDone      = "done"
)

// ScanRun is a scan as GET /exposure/scan shows it (contract.ts ScanRun), read from its shared run.
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
	StopReason  *string   `json:"stop_reason,omitempty"`
	// Progress is nil: the progress of a scan is the done and total of its run's steps (/runs/{id}).
	Progress *progress.View `json:"progress"`
}

// RunError is why a run failed.
type RunError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// scanExec is a scan this process executes now: what Stop, the terms and ScanNow need of it.
type scanExec struct {
	targetID string
	mode     ScanMode
	cause    *stoppedBy // why the box stops it, set before the stop is asked; nil for a person's Stop
	content  Content    // what it found, as written, for ScanNow
	vulns    []VulnRow  // the exploited CVEs matched on it
	gaps     []GapRow
	gbRun    GreenboneRun
	written  bool // its rows are written
	first    bool // they were the target's first rows: its baseline, announced to nobody
	started  bool // its work began in this process (a queued scan has not)
	err      error
	done     chan struct{}
}

// stoppedBy is why the box (or a person, through a terms change) stopped a run.
type stoppedBy struct {
	by     string // who or what stopped it, for the audit row
	why    string // why, for the page ("the testing terms of this target were withdrawn"); "" for a Stop
	reason string // GreenboneStop.Reason: StopPerson, StopShutdown, StopModule or StopTerms
	person string // the e-mail of the person behind it; "" for the box
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

// stopWhy is the reason of a stop in words ("" for nil).
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

// registerRuns registers the scan's kind of run. A Manager is required to scan: without one Scan now answers 501.
func (s *Service) registerRuns() error {
	if s.cfg.Runs == nil {
		return nil
	}
	// Each step of a scan counts as one unit: the run reads "3 of 8 steps" (runsteps.go).
	return s.cfg.Runs.Register(corerun.Kind{Module: ModuleID, Name: RunKind, Lane: RunLane, Unit: "steps", Run: s.runScan})
}

// setStopCause records why the box stops run id before it asks the stop.
func (s *Service) setStopCause(id string, sb *stoppedBy) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if x := s.execs[id]; x != nil && x.cause == nil {
		x.cause = sb
	}
}

// cause is why ctx of run id ended: the reason the box recorded, else a person's Stop.
func (s *Service) cause(id string) *stoppedBy {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if x := s.execs[id]; x != nil && x.cause != nil {
		return x.cause
	}
	return &stoppedBy{by: "a person", reason: StopPerson}
}

// ---- starting ----

// Scan scans one target now for a caller that is not a person at the button (the commitment must already exist). See ScanNow.
func (s *Service) Scan(ctx context.Context, user, id string) (ScanResult, error) {
	return s.ScanNow(ctx, Actor{Email: user}, id, "")
}

// ScanResult is what one scan found and wrote, for a caller that waits for it.
type ScanResult struct {
	RunID string
	Content
	Counts      Counts     // what the scan itself found
	Rows        ScanCounts // what the rows say after it
	Vulns       []VulnRow  // the exploited CVEs matched on its services
	VersionGaps []GapRow
	// GreenboneRun is how its OpenVAS step went: its state, when it started and ended, the state of each address of a domain.
	GreenboneRun GreenboneRun
}

// ScanNow queues a scan and waits for it to end: StartScan followed by waiting for its run, for callers that are not a page (tests,
// the command line). The page calls StartScan and reads the run.
func (s *Service) ScanNow(ctx context.Context, who Actor, id, noticeVersion string) (ScanResult, error) {
	runID, x, t, err := s.startScan(ctx, who, id, noticeVersion)
	if err != nil {
		return ScanResult{}, err
	}
	if err := s.waitRun(ctx, runID, x); err != nil {
		return ScanResult{}, err
	}
	if x.err != nil && !x.written {
		return ScanResult{}, fmt.Errorf("exposure: scanning %s: %w", t.Value, x.err)
	}
	r := ScanResult{RunID: runID, Content: x.content, Vulns: nz(x.vulns), VersionGaps: nz(x.gaps), GreenboneRun: x.gbRun}
	nameAppliances(r.Ports, r.AdminPanels, r.Services) // the appliances its ports and admin pages name, tied to the inventory's devices
	s.tieAppliances(ctx, r.Ports, r.AdminPanels)
	var doc string
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT summary FROM exp_scan WHERE run_id = ?`, runID).Scan(&doc); err == nil {
		var sum scanSummary
		if json.Unmarshal([]byte(doc), &sum) == nil && sum.Counts != nil && sum.Found != nil {
			r.Rows, r.Counts = *sum.Counts, *sum.Found
		}
	}
	if x.err != nil { // the rows were written, then a later step (OpenVAS) was stopped or failed
		return r, fmt.Errorf("exposure: scanning %s: %w", t.Value, x.err)
	}
	return r, nil
}

// waitRun waits until run id has ended: its work in this process (x, nil when it is over or ran elsewhere) is done and the run
// manager has recorded how it ended.
func (s *Service) waitRun(ctx context.Context, id string, x *scanExec) error {
	if x != nil {
		select {
		case <-x.done:
		case <-ctx.Done():
			return fmt.Errorf("exposure: waiting for the scan: %w", context.Cause(ctx))
		}
	}
	tick := time.NewTicker(5 * time.Millisecond) // the manager records the end right after the work returns
	defer tick.Stop()
	for {
		var st string
		if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT status FROM core_run WHERE id = ?`, id).Scan(&st); err != nil || corerun.Status(st).Ended() {
			return nil
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return fmt.Errorf("exposure: waiting for the scan: %w", context.Cause(ctx))
		}
	}
}

// waiter is the in-process record of run id that ScanNow waits on (made here when the run has not started yet).
func (s *Service) waiter(id string) *scanExec {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	x := s.execs[id]
	if x == nil {
		x = &scanExec{done: make(chan struct{})}
		s.execs[id] = x
	}
	return x
}

// StartScan is POST …/scan (PRE-1, INV-1, INV-12, INV-17): the gate first, then the scan is queued as a run (one at a time on the box,
// in the order asked), at most one per target every ScanEvery (429) and never twice at once (409 busy). A refusal is audited as
// exposure.scan with its outcome (LEGAL §3). When the only thing missing is the commitment and who.Admin is set, this press is the
// confirmation: it needs two-step sign-in and the notice version the page showed (confirmByScan). For anyone else the answer is
// 400 commitment_required.
func (s *Service) StartScan(ctx context.Context, who Actor, id, noticeVersion string) (ScanRun, error) {
	runID, _, _, err := s.startScan(ctx, who, id, noticeVersion)
	if err != nil {
		return ScanRun{}, err
	}
	v, ok, err := s.runOf(ctx, runID)
	if err != nil || !ok {
		return ScanRun{}, fmt.Errorf("exposure: reading the scan: %w", cmpErr(err, ErrNotFound))
	}
	return v, nil
}

func cmpErr(err, other error) error {
	if err != nil {
		return err
	}
	return other
}

func (s *Service) startScan(ctx context.Context, who Actor, id, noticeVersion string) (string, *scanExec, Target, error) {
	t, reason, err := s.gate(ctx, who.Email, id)
	if err != nil {
		return "", nil, Target{}, fmt.Errorf("exposure: scanning: %w", err)
	}
	if reason == BlockedNoCommitment && who.Admin {
		if err = s.confirmByScan(ctx, who, t, noticeVersion); err == nil {
			t, reason, err = s.gate(ctx, who.Email, id)
		}
		if err != nil {
			s.auditFailedScan(ctx, who.Email, t, err)
			return "", nil, t, fmt.Errorf("exposure: scanning %s: %w", t.Value, err)
		}
	}
	if reason == "" { // INV-31: the shared block is read before anything is sent, for every kind of target
		err = s.checkSafety(ctx, t)
	} else {
		err = s.refusal(t, reason, s.clock())
	}
	var runID string
	var x *scanExec
	if err == nil {
		runID, x, err = s.queueScan(ctx, who.Email, t)
	}
	if err != nil {
		s.auditFailedScan(ctx, who.Email, t, err)
		return "", nil, t, fmt.Errorf("exposure: scanning %s: %w", t.Value, err)
	}
	return runID, x, t, nil
}

// queueScan creates the run of a scan of t with its exp_scan row, or refuses: no runner or no run manager (501), the module off, a scan
// of t queued or running (409 busy), the same target within ScanEvery (429).
func (s *Service) queueScan(ctx context.Context, user string, t Target) (string, *scanExec, error) {
	if s.scanRunner() == nil || s.cfg.Runs == nil {
		return "", nil, ErrNotImplemented
	}
	s.runMu.Lock()
	off, syncing, syncAt := s.off || s.closed, s.feedSync, s.feedSyncAt
	s.runMu.Unlock()
	if off {
		return "", nil, ErrModuleOff
	}
	if syncing { // OpenVAS's feed update holds the box's one scan slot
		return "", nil, s.errScanFeedSync(syncAt)
	}
	now := s.clock()
	var runID string
	var x *scanExec
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		if _, live := s.activeRunTx(ctx, tx, t.ID); live {
			return errScanBusyFor(t.Value)
		}
		if last, ok := s.lastAsked(ctx, tx, t.ID); ok && now.Sub(last) < ScanEvery && !last.After(now) {
			next := last.Add(ScanEvery)
			return apiErr(429, "rate_limited", "%s was scanned at %s. Scan it again after %s: at most one scan of a target every %d minutes.",
				t.Value, s.momentText(last), s.momentText(next), int(ScanEvery/time.Minute))
		}
		fresh, err := loadTarget(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		if runID, err = s.createScanRun(ctx, tx, fresh, corerun.Manual, user, ""); err != nil {
			return err
		}
		x = s.waiter(runID) // before the commit: the run cannot start before it, so a caller that waits never misses its end
		s.runMu.Lock()
		x.targetID = t.ID // known before it starts; a queued scan has no mode yet and reads the terms when it starts
		s.runMu.Unlock()
		return nil
	})
	if err != nil && x != nil {
		s.runMu.Lock()
		delete(s.execs, runID)
		s.runMu.Unlock()
	}
	return runID, x, err
}

func errScanBusyFor(value string) *APIError {
	return apiErr(409, "busy", "A scan of %s is already queued or running. Wait for it to finish, or stop it, then try again.", value)
}

// activeRun is the run of target id that is queued, running or stopping; ok false when none.
func (s *Service) activeRun(ctx context.Context, id string) (string, bool) {
	return s.activeRunTx(ctx, s.cfg.DB.Reader(), id)
}

func (s *Service) activeRunTx(ctx context.Context, q querier, id string) (string, bool) {
	var runID string
	err := q.QueryRowContext(ctx, `SELECT r.id FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		WHERE x.target_id = ? AND r.status IN ('queued', 'waiting', 'running', 'stopping') ORDER BY r.queued_at DESC LIMIT 1`, id).Scan(&runID)
	return runID, err == nil
}

// lastAsked is when the newest scan of target id that was not taken back before it started was asked.
func (s *Service) lastAsked(ctx context.Context, q querier, id string) (time.Time, bool) {
	var at sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT max(r.queued_at) FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		WHERE x.target_id = ? AND r.started_at IS NOT NULL`, id).Scan(&at); err != nil || !at.Valid {
		return time.Time{}, false
	}
	t, err := parseTS(at.String)
	return t, err == nil
}

// ---- running ----

// runScan is the Run of the scan's kind: the target is checked again right before (the proof, the commitment, the safety block: a
// scan may have waited in the queue), then the runner and the engines, then the rows (writeScan), then the optional OpenVAS step and
// its rows. Every scan ends with exactly one exposure.scan audit row.
func (s *Service) runScan(ctx context.Context, x *corerun.Exec) (corerun.Result, error) {
	var targetID, user string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT x.target_id, r.requested_by FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE x.run_id = ?`, x.ID()).
		Scan(&targetID, &user)
	if err != nil {
		return corerun.Result{}, errors.New("the target of this scan was deleted")
	}
	ex := s.waiter(x.ID())
	s.runMu.Lock()
	ex.targetID, ex.started = targetID, true
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		delete(s.execs, x.ID())
		s.runMu.Unlock()
		close(ex.done)
	}()
	res, err := s.execute(ctx, x, ex, user, targetID)
	if err != nil {
		ex.err = err
	}
	if err != nil && ctx.Err() != nil { // a stop: the run says stopped, not failed
		return corerun.Result{Status: corerun.Partial}, nil
	}
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return corerun.Result{}, errors.New(ae.Message)
		}
		s.cfg.Log.ErrorContext(ctx, "an exposure scan failed", "target", targetID, "error", err)
		return corerun.Result{}, errors.New("the scan stopped because of an error on the box, so nothing was saved; try again, and if it keeps happening, check the box logs")
	}
	return res, nil
}

// execute is the work of one scan.
func (s *Service) execute(ctx context.Context, x *corerun.Exec, ex *scanExec, user, id string) (res corerun.Result, err error) {
	steps := &stepLog{}
	rs := s.newRunSteps(x, steps)
	defer func() { // runs after the recover below: every step the run did not end is ended, by how the run ended
		end, why, note := s.endOf(ctx, err), "", ""
		switch {
		case end == runStopped:
			why = stopWhy(s.cause(x.ID()).stop())
		case err != nil:
			note = failNote(err)
		}
		rs.close(ctx, end, why, note)
	}()
	defer func() { // the runner parses untrusted data; a panic must end this run, not the box
		if p := recover(); p != nil {
			s.cfg.Log.ErrorContext(ctx, "an exposure scan panicked", "target", id, "panic", p, "stack", string(debug.Stack()))
			err = errScanPanicked
		}
	}()
	// RunIDOf: the probe log names the run. What the engines report of their progress is the note of the step it belongs to.
	ctx = withSteps(withRunSteps(WithRunID(ctx, x.ID()), rs), steps)
	if progress.SinkFrom(ctx) == nil {
		ctx = progress.WithSink(ctx, rs)
	}
	rs.add(ctx, stepDef{stepKeyCheck, stepNameCheck})
	rs.start(ctx, stepKeyCheck)
	rs.startLive(ctx)
	if err := s.waitFeedSync(ctx); err != nil {
		return corerun.Result{}, err
	}
	// Every scan is checked again right before it starts, however short its wait in the queue: the ownership proof (a domain's TXT
	// record), the box's own IP and the safety block may have changed since it was asked.
	t, reason, err := s.gate(ctx, user, id)
	if err == nil && reason != "" {
		err = s.refusal(t, reason, s.clock())
	}
	if err == nil {
		err = s.checkSafety(ctx, t)
	}
	r := s.scanRunner()
	if err == nil && r == nil {
		err = ErrNotImplemented
	}
	if err != nil {
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	fresh, err := loadTarget(ctx, s.cfg.DB.Reader(), id) // the terms as they are now: withdrawn while it waited, it runs at the lower depth
	if err != nil {
		return corerun.Result{}, fmt.Errorf("exposure: reading the testing terms before the scan: %w", err)
	}
	if user == SystemUser && !fresh.Terms.current() { // a scan the box queued by itself waited while the terms were withdrawn
		err := apiErr(409, "terms_required", "%s was not scanned: its testing terms were withdrawn, or are of an older version, after this scheduled scan was queued. "+
			"The box scans a target on its schedule only while they are accepted.", t.Value)
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	mode := s.runMode(ctx, user, fresh) // never the disruptive checks in a scan the box runs by itself, or behind carrier-grade NAT
	s.runMu.Lock()
	ex.mode = mode
	s.runMu.Unlock()
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE exp_scan SET mode = ? WHERE run_id = ?`, modeWord(ex.mode), x.ID())
		return err
	}); err != nil {
		return corerun.Result{}, fmt.Errorf("recording the mode of the scan: %w", err)
	}
	rs.end(ctx, stepKeyCheck, corerun.Done, modeNote(ex.mode))
	head, tail := scanPlan(t.Kind, ex.mode)
	rs.plan(ctx, head, tail, t.Kind != KindDomain) // a domain's addresses come before the rest
	content, deep, err := s.engines(ctx, t, user, ex.mode, steps)
	if err != nil {
		s.auditFailedScan(ctx, user, t, s.stopErr(ctx, x.ID(), err))
		return corerun.Result{}, s.stopErr(ctx, x.ID(), err)
	}
	gb, gbIP, line, err := s.planOpenVAS(ctx, t, ex.mode, user, content, deep)
	if err != nil {
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	if line != "" {
		content.NotChecked = append(content.NotChecked, NotCheckedRow{Kind: "greenbone", Text: line})
	}
	if err := s.reached(ctx, t, content); err != nil { // nothing answered and the box could not reach the Internet: incomplete
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	if ctx.Err() != nil { // stopped just as it finished: nothing is stored
		err := s.stopErr(ctx, x.ID(), ctx.Err())
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	rs.start(ctx, stepKeySave)
	wr, err := s.save(ctx, x.ID(), user, t, content, steps)
	if err != nil {
		s.auditFailedScan(ctx, user, t, err)
		return corerun.Result{}, err
	}
	ex.content, ex.vulns, ex.gaps, ex.written, ex.first = wr.final.Content, wr.final.Vulns, wr.final.VersionGaps, true, wr.first
	s.alertNews(ctx, t, x.ID(), "", wr.first, wr.openedAt, wr.newAt)
	rs.end(ctx, stepKeySave, corerun.Done, fmt.Sprintf("%s (%d new, %d closed), %s (%d new).",
		plural(wr.counts.Services, "open service"), wr.counts.NewServices, wr.counts.ClosedServices, plural(wr.counts.Issues, "open issue"), wr.counts.NewIssues))
	rs.record(ctx, "", runOn, "")
	s.recordCoverage(ctx, x, wr.checked, wr.topPorts)
	s.recordNames(ctx, x, wr.probed)
	for _, h := range content.Hosts { // what the deep scan did with each address: the rotation of the next scans reads it
		for _, a := range h.IPs {
			if a.Deep != "" {
				_ = x.AddItem(ctx, corerun.Item{SubjectKind: "address", SubjectID: a.IP, Label: h.Name + " " + a.IP, Outcome: "deep_" + a.Deep})
			}
		}
	}
	ex.gbRun = GreenboneRun{State: GBRunNotRun}
	if !gb {
		rs.skip(ctx, stepKeyOpenVAS, cmp.Or(line, "OpenVAS does not run in this scan."))
		return corerun.Result{}, nil
	}
	return s.openVASStep(ctx, x, ex, user, t, content, deep, gbIP)
}

// engines runs the runner and the engine steps of a scan and returns what they found.
func (s *Service) engines(ctx context.Context, t Target, user string, mode ScanMode, steps *stepLog) (Content, []deepAddr, error) {
	st := s.scanTarget(ctx, t, user, mode)
	rs := runStepsOf(ctx)
	rs.start(ctx, stepKeySurface)
	content, err := s.scanRunner().Scan(ctx, st)
	content.Hosts = clearDeep(content.Hosts) // The deep state of a run is exposure's own, never the runner's
	if err == nil {
		rs.end(ctx, stepKeySurface, corerun.Done, surfaceNote(st.Kind, content))
	}
	deepDomain := st.Kind == KindDomain && st.Mode.Full
	if err == nil {
		content, err = s.identify(ctx, st, content) // INV-19: service identification of the box's own IP, and what was checked
	}
	if err == nil && !deepDomain { // INV-30: no more template calls in this run
		steps.close(StepNuclei)
	}
	var deep []deepAddr
	if err == nil && deepDomain { // Each address of the names at the domain's terms depth: its ports are web candidates too
		content, deep, err = s.deepDomain(ctx, st, content)
		if err == nil {
			steps.close(StepNuclei)
		}
	}
	if err == nil {
		rs.addTail(ctx)
		if deepDomain { // a domain's templates ran in the steps of its addresses: this step says what they did
			rs.start(ctx, stepKeyNuclei)
		}
		rs.settle(ctx, stepKeyNuclei, content, "templates")
		rs.start(ctx, stepKeyZAP)
		content, err = s.webPassive(ctx, byName(st), content) // INV-24: passive web scan of the services that answered HTTP
	}
	if err == nil {
		steps.close(StepZAP)
		rs.settle(ctx, stepKeyZAP, content, "web")
		rs.start(ctx, stepKeyZAPActive)
		content, err = s.webActive(ctx, st, content) // INV-24: the active scan of those pages, in a person's scan of an accepted target (the terms' mode, not the by-name scope)
	}
	if err == nil {
		steps.close(StepZAPActive)
		rs.settle(ctx, stepKeyZAPActive, content, "web_active")
	}
	return content, deep, err
}

// scanTarget is what the runner and the engines are told about t.
func (s *Service) scanTarget(ctx context.Context, t Target, user string, mode ScanMode) ScanTarget {
	st := ScanTarget{ID: t.ID, Kind: t.Kind, Value: t.Value, User: user, Mode: mode, Typed: t.Typed}
	if at, err := s.executorProof(ctx, t); err != nil { // fail closed: the executors check the address themselves
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the proof the executors get failed", "target", t.Value, "error", err)
	} else {
		st.ProvenAt = at
	}
	if t.Kind == KindDomain {
		plan, err := namePlan(ctx, s.cfg.DB.Reader(), t)
		if err != nil { // fail closed: the target's own name only
			s.cfg.Log.ErrorContext(ctx, "exposure: reading the names a domain's children scan failed; this scan reaches its own name only", "target", t.Value, "error", err)
			plan = &NamePlan{id: t.ID, nodes: []scopeNode{{id: t.ID, value: t.Value, mode: ScopeSelf, enabled: true}}}
		}
		st.Names = plan
	}
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
	return st
}

// planOpenVAS decides whether the optional OpenVAS step runs (INV-25) and on which ports of an IP; line is the "Not checked" line
// that says why not, or that it is pending.
func (s *Service) planOpenVAS(ctx context.Context, t Target, mode ScanMode, user string, c Content, deep []deepAddr) (bool, []int, string, error) {
	st := s.scanTarget(ctx, t, user, mode)
	gb, line, err := s.greenbonePlan(ctx, st)
	if err != nil {
		return false, nil, "", err
	}
	if gb && st.Kind == KindDomain && len(deep) == 0 {
		gb, line = false, notGBNoDeep
	}
	var ports []int
	if ip, perr := netip.ParseAddr(st.Value); gb && st.Kind == KindIP && perr == nil {
		ports = gbPorts(c.Ports, ip)
		if l := gbPortsLine(ports); l != "" { // no open port to check: OpenVAS is not started at all
			gb, line = false, l
		}
	}
	if gb {
		line = gbPending
	}
	return gb, ports, line, nil
}

// save writes the rows of a scan (writeScan) and publishes what changed.
func (s *Service) save(ctx context.Context, runID, user string, t Target, c Content, steps *stepLog) (written, error) {
	at := s.clock()
	c = unresolvedLine(sanitize(c))
	c.AdminPanels = applianceAdmins(c.AdminPanels, c.Ports, c.Services) // an appliance's admin page on any port
	m := vulnSet{Content: c, ID: runID}
	ranMatch := s.withVulns(ctx, &m)
	c = m.Content // with the comparison's lines, and without the web alerts Vedette's rule list treats as noise
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	prevOpen, err := servicesOf(wctx, s.cfg.DB.Reader(), t.ID, true)
	if err != nil {
		return written{}, err
	}
	prevHosts, err := storedHosts(wctx, s.cfg.DB.Reader(), t.ID)
	if err != nil {
		return written{}, err
	}
	prevPorts := make([]PortRow, 0, len(prevOpen))
	for _, x := range prevOpen {
		prevPorts = append(prevPorts, PortRow{IP: x.IP, Port: x.Port})
	}
	checked, gone := s.coverage(wctx, user, t, c, prevPorts, prevHosts)
	w := scanWrite{target: t, runID: runID, user: user, at: at, c: c, vulns: m.Vulns, first: s.baseline(wctx, t.ID, runID),
		checked: checked, gone: gone, ran: engineSet{EngineNuclei: steps.ran(StepNuclei), EngineZAP: steps.ran(StepZAP) || steps.ran(StepZAPActive), EngineMatch: ranMatch}}
	var out written
	err = s.write(wctx, func(tx *sql.Tx, emit func(string, any)) error {
		var err error
		if out, err = s.writeScan(wctx, tx, w); err != nil {
			return err
		}
		out.final, out.checked, out.first = m, checked, w.first
		emit(EventScanWritten, ScanWrittenEvent{TargetID: t.ID, RunID: runID, At: store.FormatTS(at), First: w.first, Counts: out.counts, Opened: nz(out.openedAt), NewIssues: nz(out.newAt)})
		return nil
	})
	return out, err
}

// baseline says this scan (run runID) is the first of target id: no earlier scan of it wrote its results, and it holds no rows (a child
// target holds rows its parent scanned before it). Only then is everything it finds the baseline, announced to nobody. An earlier scan
// that found nothing open still counts: what opens after it is news.
func (s *Service) baseline(ctx context.Context, id, runID string) bool {
	var n int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM exp_scan WHERE target_id = ? AND run_id <> ? AND json_extract(summary, '$.counts') IS NOT NULL)`,
		id, runID).Scan(&n)
	if err != nil || n == 1 {
		return false // when in doubt, news: an alert too many beats a port never announced
	}
	return !s.hasRows(ctx, id)
}

// hasRows says target id holds rows: a name, a service or an issue.
func (s *Service) hasRows(ctx context.Context, id string) bool {
	var n int
	_ = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM exp_service WHERE target_id = ?1) OR EXISTS (SELECT 1 FROM exp_host WHERE target_id = ?1)
		OR EXISTS (SELECT 1 FROM exp_issue WHERE target_id = ?1)`, id).Scan(&n)
	return n == 1
}

// openVASStep runs the OpenVAS step of a scan whose rows are written, as a step of its run, and writes its issues.
func (s *Service) openVASStep(ctx context.Context, x *corerun.Exec, ex *scanExec, user string, t Target, c Content, deep []deepAddr, ports []int) (corerun.Result, error) {
	mode := ex.mode
	started := s.clock().Format("2006-01-02T15:04:05.000Z")
	ex.gbRun = GreenboneRun{State: GBRunRunning, StartedAt: &started}
	rs := runStepsOf(ctx)
	rs.start(ctx, stepKeyOpenVAS)
	st := s.scanTarget(ctx, t, user, mode)
	var o gbOutcome
	var err error
	if st.Kind == KindDomain {
		o, err = s.greenboneDomain(ctx, st, deep, c.Ports)
	} else {
		o, err = s.greenboneStep(ctx, st, ports)
	}
	if err != nil {
		o.stop = stopOf(s.stopErr(ctx, x.ID(), err))
		o.not = append([]NotCheckedRow{{Kind: "greenbone", Text: gbStoppedLine(o.stop, len(o.rows) > 0)}}, o.not...)
		if o.audit == "" {
			o.audit = "stopped"
		}
		if w := stopWhy(o.stop); w != "" {
			o.audit += " (" + w + ")"
		}
		o.state = GBRunStopped
	}
	if !slices.Contains(gbRunStates, o.state) || o.state == GBRunRunning {
		o.state = GBRunFailed // never reached: every outcome names its state
	}
	outcome, text := openVASStep(o.state, len(o.rows), o.stop)
	ended := s.clock().Format("2006-01-02T15:04:05.000Z")
	ex.gbRun.State, ex.gbRun.Addresses, ex.gbRun.EndedAt = o.state, o.addrs, &ended
	if o.state == GBRunStopped {
		ex.gbRun.Stop = o.stop
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	o.rows = sanitizeGreenbone(o.rows)
	ex.content.Greenbone = append(ex.content.Greenbone, o.rows...)
	ex.content.Checks = append(ex.content.Checks, o.checks...)
	ex.content.NotChecked = append(slices.DeleteFunc(ex.content.NotChecked, func(n NotCheckedRow) bool { return n.Kind == "greenbone" && n.Text == gbPending }), o.not...)
	var fresh []NewIssue
	werr := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		var err error
		if fresh, err = s.writeOpenVAS(wctx, tx, t, x.ID(), s.clock(), o, openVASCoverage(t, o, c.Ports)); err != nil {
			return err
		}
		return s.audit(wctx, tx, user, "exposure.greenbone_scan", t.Value, clipText(o.audit, 500))
	})
	if werr != nil { // its results are not stored: the step and the run say so, never done
		s.cfg.Log.ErrorContext(wctx, "exposure: storing OpenVAS's results failed", "target", t.Value, "error", werr)
		rs.end(wctx, stepKeyOpenVAS, corerun.Failed, "OpenVAS's results could not be stored.")
		return corerun.Result{Status: corerun.Partial, Error: "OpenVAS's results could not be stored"}, nil
	}
	s.alertNews(wctx, t, x.ID(), stepOpenVAS, ex.first, nil, fresh)
	st2 := corerun.Done
	if s, ok := stepStatus[outcome]; ok {
		st2 = s
	}
	rs.end(wctx, stepKeyOpenVAS, st2, text)
	if err != nil || ctx.Err() != nil {
		ex.err = s.stopErr(ctx, x.ID(), err)
		return corerun.Result{Status: corerun.Partial, Error: "OpenVAS did not finish"}, nil
	}
	return corerun.Result{}, nil
}

// openVASCoverage is where OpenVAS finished in one step: each address it scanned to the end (done; a scan its cap or OpenVAS itself
// cut short did not look everywhere), on the ports it was given (the open ports this scan found there) and the address as a whole;
// nil when it finished nowhere.
func openVASCoverage(t Target, o gbOutcome, ports []PortRow) coverFunc {
	done := func(st string) bool { return st == GBRunDone }
	addrs := map[string]bool{}
	if t.Kind == KindIP && done(o.state) {
		addrs[ipKey(t.Value)] = true
	}
	for _, a := range o.addrs {
		if done(a.State) {
			addrs[ipKey(a.IP)] = true
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	open := map[string]bool{}
	for _, p := range ports {
		open[portKey(p.IP, p.Port)] = true
	}
	return func(x issueWhere) bool {
		return addrs[ipKey(x.ip)] && (x.port == 0 || open[portKey(x.ip, x.port)])
	}
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

// stopErr is err, or why the run was stopped when its context ended.
func (s *Service) stopErr(ctx context.Context, id string, err error) error {
	if ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return s.cause(id)
	}
	return err
}

// endOf is how a run that ended with err ended, for its steps.
func (s *Service) endOf(ctx context.Context, err error) int {
	switch {
	case ctx.Err() != nil:
		return runStopped
	case errors.Is(err, errScanPanicked):
		return runPanicked
	}
	return runEnded
}

// failNote is the note of the step a run's error ended: the reason a person can read, never the box's own error text.
func failNote(err error) string {
	var ae *APIError
	switch {
	case errors.As(err, &ae):
		return ae.Message
	case errors.Is(err, errScanPanicked):
		return "The scan stopped because of an error on the box."
	}
	return "The scan stopped because of an error on the box, so nothing was saved."
}

// surfaceNote is what the surface step found: an IP's open common ports, a domain's names.
func surfaceNote(k Kind, c Content) string {
	if k == KindDomain {
		addrs := map[string]bool{}
		for _, h := range c.Hosts {
			for _, a := range h.IPs {
				addrs[a.IP] = true
			}
		}
		return fmt.Sprintf("%s found, on %s.", plural(len(c.Hosts), "name"), nouns(len(addrs), "address", "addresses"))
	}
	return fmt.Sprintf("%s open of the commonly exposed ones.", plural(len(c.Ports), "port"))
}

// errScanPanicked is the error of a run a panic ended: an error of the box, never a stop.
var errScanPanicked = errors.New("exposure: the scan panicked")

// scanning says a scan of this process runs now (it has started its work). The caller holds runMu.
func (s *Service) scanning() bool {
	for _, x := range s.execs {
		if x.started {
			return true
		}
	}
	return false
}

// waitFeedSync holds a scan that starts while OpenVAS's feed update runs until it ends: the update holds the box's one scan slot.
func (s *Service) waitFeedSync(ctx context.Context) error {
	s.runMu.Lock()
	ch := s.syncDone
	busy := s.feedSync
	s.runMu.Unlock()
	if !busy || ch == nil {
		return nil
	}
	runStepsOf(ctx).say(stepKeyCheck, "Waiting for OpenVAS's feed update to finish: it holds the box's one scan slot.")
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---- the old run view ----

// runOf reads run id as the old run view.
func (s *Service) runOf(ctx context.Context, id string) (ScanRun, bool, error) {
	var v ScanRun
	var queued string
	var started, ended, stop, errText sql.NullString
	var status string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id, x.target_id, coalesce(r.subject_label, ''), r.requested_by, r.queued_at, r.started_at, r.ended_at,
		r.status, r.stop_reason, r.error FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE r.id = ?`, id).
		Scan(&v.ID, &v.TargetID, &v.TargetValue, &v.By, &queued, &started, &ended, &status, &stop, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanRun{}, false, nil
	}
	if err != nil {
		return ScanRun{}, false, err
	}
	v.StartedAt = queued
	if started.Valid {
		v.StartedAt = started.String
	}
	v.FinishedAt, v.StopReason = optText(ended), optText(stop)
	switch corerun.Status(status) {
	case corerun.Queued, corerun.Waiting:
		v.Status, v.Phase = RunQueued, PhaseQueued
	case corerun.Running, corerun.Stopping:
		v.Status, v.Phase = RunRunning, PhaseProbing
		var n int
		_ = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run_step WHERE run_id = ? AND name = ? AND status = 'running'`, id, stepNameOpenVAS).Scan(&n)
		if n > 0 {
			v.Phase = PhaseGreenbone
		}
	case corerun.Done, corerun.Partial:
		v.Status, v.Phase = RunDone, PhaseDone
	case corerun.Failed:
		v.Status, v.Phase = RunFailed, PhaseProbing
		v.Error = &RunError{Code: "scan_failed", Message: errText.String}
	default:
		v.Status, v.Phase = RunStopped, PhaseProbing
	}
	return v, true, nil
}

// scanView reads one scan as the tree shows it.
func (s *Service) scanView(ctx context.Context, runID string) (ScanView, error) {
	return scanScanView(s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id, x.target_id, r.status, r.trigger, r.requested_by, x.mode, r.queued_at, r.started_at,
		r.ended_at, r.waiting_for, r.stop_reason, r.error, x.summary FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE x.run_id = ?`, runID))
}

// CurrentScan is GET /exposure/scan: the scan that runs now, else the first that waits, else the newest one; nil when there is none.
func (s *Service) CurrentScan(ctx context.Context) *ScanRun {
	var id string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		ORDER BY CASE WHEN r.status IN ('running', 'stopping') THEN 0 WHEN r.status IN ('queued', 'waiting') THEN 1 ELSE 2 END,
		CASE WHEN r.status IN ('queued', 'waiting') THEN r.queued_at END ASC, coalesce(r.started_at, r.queued_at) DESC LIMIT 1`).Scan(&id)
	if err != nil {
		return nil
	}
	v, ok, err := s.runOf(ctx, id)
	if err != nil || !ok {
		return nil
	}
	return &v
}

// StopScan stops the scan that runs now (POST /exposure/scan/stop), as by; false when none runs.
func (s *Service) StopScan(ctx context.Context, by string) (ScanRun, bool) {
	var id string
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE r.status IN ('running', 'stopping') LIMIT 1`).Scan(&id); err != nil || s.cfg.Runs == nil {
		return ScanRun{}, false
	}
	s.setStopCause(id, &stoppedBy{by: by, reason: StopPerson, person: by})
	if err := s.cfg.Runs.Stop(ctx, id, by, ""); err != nil && !errors.Is(err, corerun.ErrEnded) {
		s.cfg.Log.WarnContext(ctx, "exposure: stopping the scan", "run", id, "error", err)
	}
	v, ok, err := s.runOf(ctx, id)
	return v, ok && err == nil
}

// Unqueue takes the queued scan of target id out of the queue (DELETE /exposure/targets/{id}/queue): 409 not_queued when none waits.
func (s *Service) Unqueue(ctx context.Context, by, id string) error {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return fmt.Errorf("exposure: unqueueing: %w", err)
	}
	var runID string
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE x.target_id = ? AND r.status = 'queued' LIMIT 1`, id).Scan(&runID)
	if err != nil || s.cfg.Runs == nil {
		return apiErr(409, "not_queued", "No scan of %s waits in the queue.", t.Value)
	}
	if err := s.cfg.Runs.Stop(ctx, runID, by, "taken out of the queue"); err != nil {
		return fmt.Errorf("exposure: unqueueing: %w", err)
	}
	s.auditScanRow(ctx, by, t.Value, "taken out of the queue before it started")
	return nil
}

// ModuleSwitched is the Registry subscriber of the module's switch (SYS-5): off makes new scans refused until it is on again (the run
// manager stops the scans of the module); OpenVAS's containers stop and start with the module.
func (s *Service) ModuleSwitched(enabled bool) {
	s.runMu.Lock()
	s.off = !enabled
	if !enabled {
		for _, x := range s.execs {
			if x.cause == nil {
				x.cause = &stoppedBy{by: "the box (the Exposure module was switched off)", why: stopWhy(&GreenboneStop{Reason: StopModule}), reason: StopModule}
			}
		}
	}
	s.runMu.Unlock()
	if !enabled {
		s.gbModuleOff(s.bg)
		return
	}
	s.GreenboneAtStart(s.bg)
}

// Close ends the shutdown of the box: no new scan is queued, and OpenVAS's start and feed update end. The run manager ends the scan
// that runs (closed before this service); the next start records it as stopped by the restart.
func (s *Service) Close() {
	s.runMu.Lock()
	s.closed = true
	for _, x := range s.execs {
		if x.cause == nil {
			x.cause = &stoppedBy{by: "the box (shutting down)", why: "Vedette shut down", reason: StopShutdown}
		}
	}
	s.runMu.Unlock()
	g := s.gb()
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
}

// ---- engine steps ----

// EngineRun is the newest scan in which an engine step actually ran (INV-30): Settings › Scanning's nuclei, zap and openvas cards
// read their last run here. At is when the step ended (RFC 3339 UTC).
type EngineRun struct {
	Engine  string
	RunID   string
	Target  string
	At      string
	Outcome string
	Text    string
}

// EngineRuns reads the newest ended step of each engine of the scans; an engine that never ran is not in the map.
func (s *Service) EngineRuns(ctx context.Context) (map[string]EngineRun, error) {
	out := map[string]EngineRun{}
	for _, engine := range stepEngines {
		var r EngineRun
		var status string
		var note sql.NullString
		err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT r.id, coalesce(r.subject_label, ''), st.ended_at, st.status, st.note FROM core_run_step st
			JOIN core_run r ON r.id = st.run_id JOIN exp_scan x ON x.run_id = r.id WHERE r.module = ? AND r.kind = ? AND st.name = ? AND st.ended_at IS NOT NULL
			AND st.status <> 'skipped' ORDER BY st.ended_at DESC LIMIT 1`, ModuleID, RunKind, stepNames[engine]).Scan(&r.RunID, &r.Target, &r.At, &status, &note)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("exposure: reading the engines' last runs: %w", err)
		}
		r.Engine, r.Text = engine, note.String
		if !strings.HasPrefix(r.Text, "External scan of ") { // the step's own note, as the run page shows it
			r.Text = clipText("External scan of "+r.Target+": "+r.Text, maxLineText)
		}
		for o, st := range stepStatus {
			if string(st) == status {
				r.Outcome = o
			}
		}
		if r.Outcome == "" {
			continue
		}
		out[engine] = r
	}
	return out, nil
}

// recordNames writes, as items of the run, the names the scan probed (kind name, the id of the name's row, outcome probed): the count of
// names scanned by two targets reads them.
func (s *Service) recordNames(ctx context.Context, x *corerun.Exec, probed map[string]string) {
	names := slices.Sorted(maps.Keys(probed))
	items := make([]corerun.Item, 0, len(names))
	for _, n := range names {
		items = append(items, corerun.Item{SubjectKind: itemName, SubjectID: probed[n], Label: n, Outcome: "probed"})
	}
	if len(items) == 0 {
		return
	}
	if err := x.AddItems(ctx, items...); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the names a scan probed", "run", x.ID(), "error", err)
	}
}

// itemName is the kind of a run item that names a name the scan probed.
const itemName = "name"

// recordCoverage writes, as items of the run, which ports the scan probed on each address it reached, and each open service outside
// the fixed list its service step probed (topPorts, kind itemPort): the next scan closes a service only when this one, which probed
// it, missed it too (INV-22). A failure is logged: the next scan then waits one scan more.
func (s *Service) recordCoverage(ctx context.Context, x *corerun.Exec, checked map[string]string, topPorts []string) {
	ips := make([]string, 0, len(checked))
	for ip := range checked {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	for _, ip := range ips {
		if err := x.AddItem(ctx, corerun.Item{SubjectKind: "address", SubjectID: ip, Label: ip, Outcome: checked[ip]}); err != nil {
			s.cfg.Log.WarnContext(ctx, "exposure: recording what a scan checked", "run", x.ID(), "address", ip, "error", err)
		}
	}
	items := make([]corerun.Item, 0, len(topPorts))
	for _, k := range topPorts {
		items = append(items, corerun.Item{SubjectKind: itemPort, SubjectID: k, Label: k, Outcome: coverTop})
	}
	if len(items) == 0 {
		return
	}
	if err := x.AddItems(ctx, items...); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: recording the ports a scan's service step checked", "run", x.ID(), "error", err)
	}
}

// deepHistory is when each address of target id was last deep-scanned and last taken in turn by a scan (the run items of the
// deep scan), for the rotation of the addresses past the cap.
func (s *Service) deepHistory(ctx context.Context, id string) (last, tried map[string]string, err error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT i.subject_id, i.outcome, r.started_at FROM core_run_item i JOIN core_run r ON r.id = i.run_id
		WHERE r.module = ? AND r.kind = ? AND r.subject_kind = 'target' AND r.subject_id = ? AND i.subject_kind = 'address' AND r.started_at IS NOT NULL`,
		ModuleID, RunKind, id)
	if err != nil {
		return nil, nil, fmt.Errorf("the deep scans of %s: %w", id, err)
	}
	defer func() { _ = rows.Close() }()
	last, tried = map[string]string{}, map[string]string{}
	for rows.Next() {
		var ip, outcome, at string
		if err := rows.Scan(&ip, &outcome, &at); err != nil {
			return nil, nil, fmt.Errorf("the deep scans of %s: %w", id, err)
		}
		switch outcome {
		case "deep_" + DeepScanned:
			last[ip], tried[ip] = max(last[ip], at), max(tried[ip], at)
		case "deep_" + DeepRefused, "deep_" + DeepIncomplete:
			tried[ip] = max(tried[ip], at)
		}
	}
	return last, tried, rows.Err()
}

// auditFailedScan writes the exposure.scan row of an attempt that ended without rows: refused, busy, too soon, the module off, failed
// or stopped. The write outlives a caller that hung up; a failure to write is logged.
func (s *Service) auditFailedScan(ctx context.Context, user string, t Target, cause error) {
	s.auditScanRow(ctx, user, t.Value, failedDetail(cause))
}

func (s *Service) auditScanRow(ctx context.Context, user, target, detail string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	err := s.write(actx, func(tx *sql.Tx, _ func(string, any)) error {
		return s.audit(actx, tx, user, "exposure.scan", target, detail)
	})
	if err != nil {
		s.cfg.Log.ErrorContext(actx, "auditing an exposure scan failed", "target", target, "error", err)
	}
}

// failedDetail is the detail of the audit row of a scan that did not write its rows.
func failedDetail(err error) string {
	var ae *APIError
	var sb *stoppedBy
	switch {
	case errors.As(err, &sb):
		return "stopped by " + sb.by
	case errors.As(err, &ae):
		return "not done: " + ae.Code + ": " + clipText(ae.Message, 300)
	case err == nil:
		return "not done"
	}
	return "failed: the scan stopped (" + clipText(err.Error(), 200) + ")"
}
