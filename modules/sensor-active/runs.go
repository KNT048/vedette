package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
)

// Every piece of work of the module is a run of core/run (DB-DESIGN core_run): the run is its record (the Runs tab, the run page,
// every "Open the run"), its queue (the queued and waiting rows survive a restart) and its lane (one live run per lane, held by the
// database). The nmap work shares the lane nmap, so a person's check that meets a sweep is a queued run that says what it waits for;
// the SNMP reads have their own lane.
const (
	// ModuleID is the module's id: the module of its runs.
	ModuleID = "sensor-active"

	RunSweep    = "lan_sweep"    // one pass over the confirmed ranges, across windows: a step per range, its done count the cursor
	RunCheck    = "device_check" // the nmap check of one device: the window's queue, a person's check, Scan now's identification
	RunSNMP     = "snmp_read"    // the window's SNMP round, or the read of one device a person asked for
	RunAllPorts = "all_ports"    // the weekly scan of every port of one device
	RunService  = "service_scan" // the nmap -sV of one public address for an exposure scan

	laneNmap = "nmap"
	laneSNMP = "snmp"
)

// Words of the runs' units, for the line each run reads as (run.Kind.Unit).
const (
	unitAddresses = "addresses"
	unitDevices   = "devices"
)

// noteLost ends a queued run a restart left that only the process that made it could run (it waits for a result in memory).
const noteLost = "Vedette restarted before this began, so it did not run"

// workFunc is the work of a run made with submit: it runs once the lane is free, with the values of the caller's context and the
// cancellation of the run's.
type workFunc func(ctx context.Context, x *run.Exec) (run.Result, error)

type pending struct {
	values context.Context // the caller's context, for its values only (a progress sink, the deadline marks)
	work   workFunc
}

// outcome is how a run's work ended, for the caller that waits for it (await).
type outcome struct {
	res run.Result
	err error
}

type execKey struct{}

// execOf is the run whose work ctx carries; nil outside a run.
func execOf(ctx context.Context) *run.Exec {
	x, _ := ctx.Value(execKey{}).(*run.Exec)
	return x
}

// registerKinds adds the module's kinds of run to the manager; New calls it, so the restart recovery knows them.
func (s *Service) registerKinds() error {
	kinds := []run.Kind{
		{Module: ModuleID, Name: RunSweep, Lane: laneNmap, Resumable: true, AdminResume: true, Unit: unitAddresses, Estimate: s.sweepEstimate,
			Hold: s.sweepHold, Run: s.runOf(s.runSweep)},
		{Module: ModuleID, Name: RunCheck, Lane: laneNmap, Resumable: true, AdminResume: true, Unit: unitDevices, Estimate: s.checkEstimate,
			Hold: s.checkHold, Run: s.runOf(s.runCheck)},
		{Module: ModuleID, Name: RunAllPorts, Lane: laneNmap, Unit: unitDevices, Estimate: s.allPortsEstimate, Hold: s.allPortsHold,
			GiveWay: s.allPortsGiveWay, Run: s.runOf(s.runAllPorts)},
		{Module: ModuleID, Name: RunSNMP, Lane: laneSNMP, Unit: unitDevices, Run: s.runOf(s.runSNMP)},
		{Module: ModuleID, Name: RunService, Lane: laneNmap, Run: s.runOf(nil)},
	}
	for _, k := range kinds {
		if err := s.runs.Register(k); err != nil {
			return err
		}
	}
	return nil
}

// runOf is the Run of a kind: the work a caller handed with submit when there is one, else the kind's own work from what the run
// stored (self; nil: the run cannot go on without its caller, so it ends with noteLost). The waiting caller hears how it ended.
func (s *Service) runOf(self workFunc) func(ctx context.Context, x *run.Exec) (run.Result, error) {
	return func(ctx context.Context, x *run.Exec) (res run.Result, err error) {
		defer func() { s.tell(x.ID(), outcome{res, err}) }()
		defer s.resumeYielded(context.WithoutCancel(ctx), x.ID()) // a pass that gave way to this run goes on after it
		s.mu.Lock()
		p := s.pend[x.ID()]
		delete(s.pend, x.ID())
		s.mu.Unlock()
		work, values := self, context.Context(nil)
		if p != nil {
			work, values = p.work, p.values
		}
		if work == nil {
			return run.Result{Status: run.Failed, Error: noteLost}, nil
		}
		if s.off.Load() { // the module was turned off: nothing is sent, and the run ends stopped
			s.stopForModuleOff(ctx, x.ID())
			return run.Result{Status: run.Partial, Error: run.ModuleOffReason}, nil
		}
		if values != nil { // the caller's values, cancelled with the run
			wctx, cancel := context.WithCancelCause(values)
			stop := context.AfterFunc(ctx, func() { cancel(context.Cause(ctx)) })
			defer stop()
			defer cancel(nil)
			ctx = wctx //nolint:contextcheck // the caller's values, cancelled with the run's context by the AfterFunc above
		}
		if progress.SinkFrom(ctx) == nil { // what the worker reports of its nmap goes to the run's estimate (workerEstimate)
			ctx = progress.WithSink(ctx, s.runSink(x.ID()))
			defer s.dropProgress(x.ID())
		}
		res, err = work(context.WithValue(ctx, execKey{}, x), x)
		if ctx.Err() != nil && err == nil && (res.Status == "" || res.Status == run.Done) {
			// stopped while it worked: what it read cannot be told from a run cut short, so it ends stopped, never done
			res = run.Result{Status: run.Partial, Error: "stopped"}
		}
		// The module turned off under the work (Stop) ends it stopped, whichever comes first: core/run's own stop of the module's runs
		// (it runs on its own goroutine) or the work noticing its cancelled context. Work that had finished stays done.
		if s.off.Load() && (err != nil || (res.Status != "" && res.Status != run.Done)) {
			s.stopForModuleOff(ctx, x.ID())
		}
		return res, err
	}
}

// stopForModuleOff records the stop of run id by its module turned off, before its work returns: core/run then ends it stopped.
func (s *Service) stopForModuleOff(ctx context.Context, id string) {
	if err := s.runs.Stop(context.WithoutCancel(ctx), id, run.System, run.ModuleOffReason); err != nil && !errors.Is(err, run.ErrEnded) {
		s.log.WarnContext(ctx, "sensoractive: recording the stop of a run of a module turned off failed", "run", id, "error", err)
	}
}

// resumeYielded queues again the pass that gave way to other work in the nmap lane (sweepMayGoOn), once the run that ends now was the
// last one waiting for the lane and the pass may go on now: in the window, or within the hour of a person's sweep or of a new box's
// first pass. Outside them the pass keeps waiting for the window (the window's driver resumes it then).
func (s *Service) resumeYielded(ctx context.Context, ending string) {
	sw, err := s.liveRun(ctx, RunSweep)
	if err != nil || sw == nil || sw.Status != run.Waiting || sw.ID == ending || !s.isYielded(sw.ID) {
		return
	}
	if other, _, err := s.laneBusy(ctx, ending); err != nil || other != "" {
		return // more work waits for the lane: the last of it resumes the pass
	}
	if s.sweepWait(withManualUntil(ctx, s.sweepUntil(ctx, *sw))).Status == run.Waiting {
		return
	}
	s.setYielded(sw.ID, false)
	if err := s.resumeWaiting(ctx, sw.ID); err != nil && !errors.Is(err, run.ErrNotResumable) {
		s.log.WarnContext(ctx, "sensoractive: resuming the pass after the work it gave way to failed", "run", sw.ID, "error", err)
	}
}

// tell hands how a run's work ended to the caller that waits for it, if one does.
func (s *Service) tell(id string, o outcome) {
	s.mu.Lock()
	ch := s.waits[id]
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- o:
		default:
		}
	}
}

// submit queues a run (or creates it waiting, spec.WaitingFor) with its work, in one transaction with inTx (nil: none). work nil:
// the kind's own work runs it.
func (s *Service) submit(ctx context.Context, spec run.Spec, work workFunc, inTx func(tx *sql.Tx, id string) error) (string, error) {
	var id string
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.submitTx(ctx, tx, spec, work, inTx)
		return err
	})
	if err != nil {
		if id != "" {
			s.mu.Lock()
			delete(s.pend, id)
			delete(s.waits, id)
			s.mu.Unlock()
		}
		return "", fmt.Errorf("sensoractive: queue the run: %w", err)
	}
	return id, nil
}

// submitTx is submit inside the caller's transaction: the schedule of the sweep queues its run in its own.
func (s *Service) submitTx(ctx context.Context, tx *sql.Tx, spec run.Spec, work workFunc, inTx func(tx *sql.Tx, id string) error) (string, error) {
	spec.Module = ModuleID
	if spec.RequestedBy == "" {
		spec.RequestedBy = run.System
	}
	if spec.Trigger == "" {
		spec.Trigger = run.Event
	}
	if spec.ParentID == "" {
		spec.ParentID = run.IDFrom(ctx) // the work of another module's run (a vulnerability check, an exposure scan) is its step
	}
	id, err := s.runs.CreateTx(ctx, tx, spec)
	if err != nil {
		return "", err
	}
	if inTx != nil {
		if err := inTx(tx, id); err != nil {
			return id, err
		}
	}
	if work != nil { // before the commit: the dispatcher cannot start the run before it, and then finds its work and its caller
		s.mu.Lock()
		s.pend[id] = &pending{values: context.WithoutCancel(ctx), work: work}
		s.mu.Unlock()
		s.expect(id)
	}
	return id, nil
}

// errNotStarted says a run a caller waited for did not start within its time: it was stopped while still queued.
var errNotStarted = errors.New("sensoractive: the run did not start in time")

// await waits until run id has ended or waits for something (or ctx ends) and returns it as stored then, with how its work
// ended when this process ran it. startWithin > 0 stops it, with the reason busyReason, when it is still queued after that long
// (errNotStarted). stopOnCancel stops it when ctx ends first (a caller that gives up); the window's driver leaves it to run.
func (s *Service) await(ctx context.Context, id string, startWithin time.Duration, busyReason string, stopOnCancel bool) (r run.Run, got *outcome, err error) {
	ch := s.expect(id)
	defer func() {
		s.mu.Lock()
		delete(s.waits, id)
		if !r.Status.Live() && r.Status != run.Queued { // it ran, or never will in this wait: work it never took is not kept
			delete(s.pend, id)
		}
		s.mu.Unlock()
	}()
	var give <-chan time.Time
	if startWithin > 0 {
		t := time.NewTimer(startWithin)
		defer t.Stop()
		give = t.C
	}
	poll := time.NewTicker(250 * time.Millisecond) // a run stopped while queued never runs: only its row says so
	defer poll.Stop()
	bg := context.WithoutCancel(ctx)
	for {
		r, err = s.runs.Read(bg, id)
		if err != nil {
			return r, got, err
		}
		if r.Status.Ended() || r.Status == run.Waiting {
			return r, got, nil
		}
		select {
		case o := <-ch:
			got = &o
			poll.Reset(20 * time.Millisecond) // the manager records the end right after the work returned
		case <-ctx.Done():
			if stopOnCancel {
				if err := s.runs.Stop(bg, id, run.System, "The work that asked for it stopped"); err != nil && !errors.Is(err, run.ErrEnded) {
					s.log.WarnContext(bg, "sensoractive: stopping a run whose caller gave up failed", "run", id, "error", err)
				}
				if now, err := s.runs.Read(bg, id); err == nil {
					r = now // stopped while queued: the work handed to it is dropped (the deferred clean-up)
				}
			}
			return r, got, ctx.Err()
		case <-give:
			give = nil
			if r.Status == run.Queued {
				if err := s.runs.Stop(bg, id, run.System, busyReason); err != nil && !errors.Is(err, run.ErrEnded) {
					return r, got, err
				}
				r, _ = s.runs.Read(bg, id)
				if r.Status == run.Stopped {
					return r, got, errNotStarted
				}
			}
		case <-poll.C:
		}
	}
}

// expect registers the caller that is about to wait for run id (await), before the run can start and end: an end it would miss
// otherwise is only seen at the next poll.
func (s *Service) expect(id string) chan outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.waits[id]
	if ch == nil {
		ch = make(chan outcome, 1)
		s.waits[id] = ch
	}
	return ch
}

// doRun submits a run with its work and waits for it, as await does; the work's own error is returned when it ran.
func (s *Service) doRun(ctx context.Context, spec run.Spec, work workFunc, startWithin time.Duration, busyReason string) error {
	id, err := s.submit(ctx, spec, work, nil)
	if err != nil {
		return err
	}
	_, got, err := s.await(ctx, id, startWithin, busyReason, true)
	if err != nil {
		return err
	}
	if got != nil && got.err != nil {
		return got.err
	}
	return nil
}

// doWork runs fn as the work of a run made from spec and waits for it, as doRun does, and returns fn's own error (nil when it did
// not run: errNotStarted, or the run's error). result maps fn's error to how the run ends.
func (s *Service) doWork(ctx context.Context, spec run.Spec, fn func(ctx context.Context) error, result func(ctx context.Context, err error) run.Result,
	startWithin time.Duration, busyReason string) error {
	got := make(chan error, 1)
	err := s.doRun(ctx, spec, func(ctx context.Context, _ *run.Exec) (run.Result, error) {
		err := fn(ctx)
		got <- err
		return result(ctx, err), nil
	}, startWithin, busyReason)
	select {
	case werr := <-got:
		return werr
	default:
		if err == nil {
			err = ErrStopped // stopped before it ran
		}
		return err
	}
}

// liveRun is a run of the module of kind that has not ended (queued, waiting, running or stopping), the newest; nil when none.
func (s *Service) liveRun(ctx context.Context, kind string) (*run.Run, error) {
	var id string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM core_run WHERE module = ? AND kind = ? AND status IN ('queued', 'waiting', 'running', 'stopping')
		ORDER BY queued_at DESC, rowid DESC LIMIT 1`, ModuleID, kind).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // none
	}
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read the runs: %w", err)
	}
	r, err := s.runs.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// laneBusy says another run than except is queued, running or stopping in the nmap lane: a sweep gives way to it between batches,
// and the window's driver does not resume work while it waits.
func (s *Service) laneBusy(ctx context.Context, except string) (string, string, error) {
	var id, title string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id, title FROM core_run WHERE lane = ? AND id <> ? AND status IN ('queued', 'running', 'stopping')
		ORDER BY CASE status WHEN 'queued' THEN 1 ELSE 0 END, queued_at, rowid LIMIT 1`, laneNmap, except).Scan(&id, &title)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("sensoractive: read the runs: %w", err)
	}
	return id, title, nil
}

// windowWait is what a run of the window waits for while it is closed: "the scan window (opens 23 Nov 2026, 23:00)", in the
// organization's zone.
func (s *Service) windowWait(st Settings) string {
	at := st.nextOpening(s.local())
	if at == nil {
		return "the scan window (no window is set)"
	}
	return "the scan window (opens " + orgtime.Stamp(*at, s.zone()) + ")"
}

// label is how a run names a device: its name and address, its address, or its id.
func label(a Asset) string {
	switch {
	case a.Name != "" && a.IP.IsValid():
		return a.Name + " (" + a.IP.String() + ")"
	case a.Name != "":
		return a.Name
	case a.IP.IsValid():
		return a.IP.String()
	}
	return a.ID
}

// deviceLabel is label of device id, or its id when the inventory does not answer.
func (s *Service) deviceLabel(ctx context.Context, id string) string {
	a, err := s.inv.Asset(ctx, id)
	if err != nil {
		return id
	}
	return label(a)
}

// hostItem is the item of an address a sweep found: the device when the inventory has one there.
func hostItem(addr netip.Addr, assetID, outcome string) run.Item {
	if assetID != "" {
		return run.Item{SubjectKind: "device", SubjectID: assetID, Label: addr.String(), Outcome: outcome}
	}
	return run.Item{SubjectKind: "host", Label: addr.String(), Outcome: outcome}
}
