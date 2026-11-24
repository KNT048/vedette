package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/run"
)

// ---- the window's driver: Tick, the queue of device checks, the sweep of the window ----

// reasonWords are the words a device check of the window says it was queued for (core_run.trigger_note).
var reasonWords = map[string]string{
	"discovered":    "a new device appeared",
	"first_check":   "no check reached the device yet",
	"scan_on":       "its network scan was turned on",
	"normal_owed":   "it is owed a full scan after its gentle look",
	"gentle_titles": "it waits for its gentle look",
	"check_now":     "a person asked to check it",
	"queued":        "it was queued",
}

// Enqueue queues a device for its check inside the window (a device another sensor saw first, a device whose scan was turned on):
// a device_check run waiting for its turn, which survives a restart. A device that already has a check queued or waiting keeps that
// one. A device found by a person's sweep is checked right after it, as a step of it.
func (s *Service) Enqueue(ctx context.Context, assetID, reason string) error {
	if s.off.Load() {
		return nil // the module is off: nothing is queued
	}
	if l := len(assetID); l < 1 || l > 96 {
		return errors.New("sensoractive: bad device id")
	}
	words, ok := reasonWords[reason]
	if !ok {
		words = reasonWords["queued"]
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return err
	}
	wait := s.queueWait(ctx, st)
	lbl := s.deviceLabel(ctx, assetID)
	parent := ""
	if sw, err := s.liveRun(ctx, RunSweep); err == nil && sw != nil && sw.Status == run.Running && s.clock().Before(s.sweepUntil(*sw)) {
		parent = sw.ID // a person's pass: the devices it finds are checked right after it, within its hour
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE module = ? AND kind = ? AND subject_kind = 'device' AND subject_id = ?
			AND status IN ('queued', 'waiting')`, ModuleID, RunCheck, assetID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		_, err := s.runs.CreateTx(ctx, tx, run.Spec{Module: ModuleID, Kind: RunCheck, Title: "Check of " + lbl, Trigger: run.Event, TriggerNote: words,
			RequestedBy: run.System, Subject: &run.Subject{Kind: "device", ID: assetID, Label: lbl}, ParentID: parent,
			Steps: []run.StepPlan{{Name: lbl, Total: 1}}, WaitingFor: wait})
		return err
	})
}

// What a check of the window that waits for its turn really waits for, besides the window itself (windowWait).
const (
	waitTurn   = "its turn in the scan window"
	waitWorker = "the scan worker to be available"
)

// queueWait is what a check of the window waits for now: the next window while it is closed; inside it, the scan worker while it
// is not ready (after a restart, until it reports), else its turn.
func (s *Service) queueWait(ctx context.Context, st Settings) string {
	if _, ok := s.windowNow(ctx, st); !ok {
		return s.windowWait(st)
	}
	if s.available(ctx) != nil {
		return waitWorker
	}
	return waitTurn
}

// refreshWaits makes the window's waiting checks say what they wait for now (queueWait): the reason changes while they wait (the
// window opened while the scan worker was not ready, the window closed before their turn came). Only the reasons of the window's
// own queue are touched: a check that waits for the settings (scanning off, the scope) keeps its reason.
func (s *Service) refreshWaits(ctx context.Context, st Settings) {
	want := s.queueWait(ctx, st)
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, waiting_for FROM core_run WHERE module = ? AND kind = ? AND status = 'waiting'
		AND trigger <> 'manual' AND waiting_for <> ?`, ModuleID, RunCheck, want)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id, w string
		if rows.Scan(&id, &w) == nil && (w == waitTurn || w == waitWorker || w == waitWorkerBack || strings.HasPrefix(w, "the scan window")) {
			ids = append(ids, id)
		}
	}
	if rows.Close() != nil || len(ids) == 0 {
		return
	}
	if err := s.runs.Rewait(ctx, want, ids...); err != nil {
		s.log.WarnContext(ctx, "sensoractive: saying what the waiting checks wait for failed", "error", err)
	}
}

// personWaitMax is how long a person's check waits for the scan worker to report before it gives up.
const personWaitMax = 30 * time.Minute

// Why a person's check that waited for the scan worker gives up.
const (
	gaveUpNoWorker = "The scan worker did not report for 30 minutes, so the device was not checked. Check that the scan container runs, then check the device again"
	gaveUpNoNmap   = "The scan worker reports that nmap is not installed in the scan container, so the device was not checked"
)

// workerReported is the scan worker's heartbeat (workerReporter.OnReport): the person's checks that wait for it start now, on a goroutine
// of their own (the heartbeat must not wait), one pass at a time.
func (s *Service) workerReported() {
	if !s.waking.CompareAndSwap(false, true) {
		return
	}
	if s.beforeBackground != nil {
		s.beforeBackground()
	}
	// closed is read and the pass counted under bgMu, as Close sets it: Close either refuses the pass or waits for it.
	s.bgMu.Lock()
	if s.closed {
		s.bgMu.Unlock()
		s.waking.Store(false)
		return
	}
	s.bg.Add(1)
	s.bgMu.Unlock()
	go func() {
		defer s.bg.Done()
		defer s.waking.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), workerReportedFor)
		defer cancel()
		if st, err := s.inv.Settings(ctx); err != nil || st.allowed() != nil {
			return // scanning off or the scope not confirmed: the check is refused when it runs; the tick looks again
		}
		s.resumePersonsChecks(ctx)
		s.resumePersonsPass(ctx)
	}()
}

// resumePersonsPass queues again a person's pass that waits for the scan worker within its hour (sweepUntil: a person's sweep, or a
// pass a person asked to go on now) once the worker is available: after a restart the pass meets a worker that has not reported yet,
// and nothing else wakes it outside the window (the window's driver follows the window's own pass). The person's checks go first: with
// other work in the nmap lane the pass is marked as one that gave way, and the end of that work resumes it (resumeYielded). It runs
// when the worker reports and at every tick.
func (s *Service) resumePersonsPass(ctx context.Context) {
	sw, err := s.liveRun(ctx, RunSweep)
	if err != nil || sw == nil || sw.Status != run.Waiting || sw.WaitingFor == nil || *sw.WaitingFor != waitWorker {
		return
	}
	until := s.sweepUntil(*sw)
	if !s.clock().Before(until) || s.available(ctx) != nil {
		return
	}
	if s.sweepWait(withManualUntil(ctx, until)).Status == run.Waiting {
		return // the settings no longer allow it: it waits for them
	}
	if other, _, err := s.laneBusy(ctx, sw.ID); err != nil {
		return
	} else if other != "" {
		s.setYielded(sw.ID, true)
		return
	}
	s.setYielded(sw.ID, false)
	if err := s.resumeWaiting(ctx, sw.ID); err != nil && !errors.Is(err, run.ErrNotResumable) {
		s.log.WarnContext(ctx, "sensoractive: resuming a person's pass once the scan worker reported failed", "run", sw.ID, "error", err)
	}
}

// later is the later of a and b.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// resumeWaiting queues again run id that the box read as waiting, only while it still waits (run.ResumeWaiting): a person's Stop that
// came after the read holds. Every resume the box makes on its own goes through it; a person's Resume and Scan now do not.
func (s *Service) resumeWaiting(ctx context.Context, id string) error {
	if s.beforeBoxResume != nil {
		s.beforeBoxResume(id)
	}
	return s.runs.ResumeWaiting(ctx, id)
}

// workerReportedFor bounds one workerReported pass.
const workerReportedFor = 30 * time.Second

// resumePersonsChecks queues the person's checks that wait for the scan worker (asked while it had not reported, StartManual) once it
// is available: they run whatever the window, oldest first, behind whatever holds the nmap lane. It runs when the worker reports
// (workerReported) and at every tick. A check gives up with a plain failure when the worker reports that it has no nmap, or after
// personWaitMax without the worker.
func (s *Service) resumePersonsChecks(ctx context.Context) {
	// updated_at is when it began to wait (the row does not change while it waits): a check queued again after a restart or after the
	// worker stopped under it counts its wait from then, not from when the person asked.
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, updated_at FROM core_run WHERE module = ? AND kind = ? AND trigger = 'manual' AND parent_id IS NULL
		AND status = 'waiting' AND waiting_for = ? ORDER BY queued_at, rowid`, ModuleID, RunCheck, waitWorker)
	if err != nil {
		return
	}
	type waiting struct {
		id    string
		since time.Time
	}
	var ws []waiting
	for rows.Next() {
		var w waiting
		var at string
		if rows.Scan(&w.id, &at) == nil {
			w.since, _ = time.Parse(time.RFC3339Nano, at)
			ws = append(ws, w)
		}
	}
	if rows.Close() != nil || len(ws) == 0 {
		return
	}
	ready := s.available(ctx) == nil
	noNmap := false
	if r, ok := s.prober.(workerReporter); ok && !ready {
		noNmap = r.NmapMissing()
	}
	for _, w := range ws {
		var err error
		switch {
		case ready:
			err = s.resumeWaiting(ctx, w.id)
		case noNmap:
			err = s.runs.GiveUp(ctx, w.id, gaveUpNoNmap)
		case !w.since.IsZero() && s.clock().Sub(later(w.since, s.since)) >= personWaitMax: // Vedette off meanwhile: counted from its start
			err = s.runs.GiveUp(ctx, w.id, gaveUpNoWorker)
		}
		if err != nil && !errors.Is(err, run.ErrNotResumable) && !errors.Is(err, run.ErrNotFound) && !errors.Is(err, run.ErrNotLive) {
			s.log.WarnContext(ctx, "sensoractive: settling a person's check that waits for the scan worker failed", "run", w.id, "error", err)
		}
	}
}

// QueueLen is the number of device checks waiting for their turn in the window.
func (s *Service) QueueLen(ctx context.Context) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE module = ? AND kind = ? AND status = 'waiting' AND trigger <> 'manual'`, ModuleID, RunCheck).Scan(&n)
	return n, err
}

// dropWaiting stops the window's waiting check of a device (it may no longer be checked, or a person's check replaces it).
func (s *Service) dropWaiting(ctx context.Context, assetID, reason string) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM core_run WHERE module = ? AND kind = ? AND subject_kind = 'device' AND subject_id = ?
		AND trigger <> 'manual' AND status = 'waiting'`, ModuleID, RunCheck, assetID)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if err := s.runs.Stop(ctx, id, run.System, reason); err != nil && !errors.Is(err, run.ErrEnded) {
			s.log.WarnContext(ctx, "sensoractive: dropping a waiting device check failed", "run", id, "error", err)
		}
	}
}

// queuePendingOnce queues, once per process, every device the inventory says still waits for its one gentle scan (PendingGentle).
func (s *Service) queuePendingOnce(ctx context.Context) error {
	p, ok := s.inv.(PendingGentle)
	if !ok || s.pendingQueued.Load() {
		return nil
	}
	ids, err := p.PendingGentleScans(ctx)
	if err != nil {
		return fmt.Errorf("sensoractive: read the devices waiting for their gentle scan: %w", err)
	}
	for _, id := range ids {
		if err := s.Enqueue(ctx, id, "gentle_titles"); err != nil {
			return err
		}
	}
	s.pendingQueued.Store(true)
	return nil
}

// Tick is the window job, run every minute. While a window is open it checks first the devices no check has reached yet (at most
// firstBeforeSweep of them, within a share of the window), then goes on with the pass of the ranges (resuming the one that waits, or
// following the pass the schedule started), then checks the rest of the waiting devices, reads SNMP and runs the weekly scans of every port. Every
// piece is a run: Tick queues or resumes it and waits for it. Outside a window it runs the first pass of a new box, else nothing.
func (s *Service) Tick(ctx context.Context) error {
	if err := s.queuePendingOnce(ctx); err != nil {
		return err
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return err
	}
	if st.allowed() != nil {
		return nil
	}
	s.refreshWaits(ctx, st)
	s.resumePersonsChecks(ctx)
	s.resumePersonsPass(ctx)
	start, _, ok := st.window(s.local())
	if !ok {
		s.resumeYielded(ctx, "") // a person's pass that gave way goes on within its hour (after a restart too)
		due, err := s.firstPassDue(ctx)
		if err != nil || !due {
			return err
		}
		return s.firstPass(ctx)
	}
	if err := s.available(ctx); err != nil {
		return err
	}
	// The devices a person turned the network scan on for, that a new range now covers, or that no check ever reached are checked
	// first, before the sweep: a sweep of wide ranges takes the whole window and the queue behind it would wait for the next one (INV-27).
	if err := s.queueOwedNormal(ctx, start); err != nil {
		s.log.WarnContext(ctx, "sensoractive: queueing the devices that owe a scan failed; tried again in the next window", "error", err)
	}
	firstFor := min(st.windowLength()/firstShare, firstMax)
	if err := s.drainQueue(ctx, true, firstBeforeSweep, s.clock().Add(firstFor)); err != nil {
		return err
	}
	// The window's round of SNMP reads has a lane of its own: it runs before the pass, which may take the whole window.
	if err := s.snmpRound(ctx, start); err != nil {
		return err
	}
	// The pass of the ranges; the devices that wait for their check take turns with it between its batches.
	if err := s.windowSweep(ctx); err != nil {
		return err
	}
	if err := s.drain(ctx); err != nil {
		return err
	}
	// Then the weekly scans of every port, one device at a time while the window has room for one. A pass that needs several windows
	// ends within a week (a scope that cannot is refused), and the window it ends in runs them; one such scan takes up to two hours, so
	// it does not take turns between the batches of a pass.
	return s.allPortsRound(ctx)
}

// firstBeforeSweep is the most never-checked devices one tick checks before the window's sweep; the rest follow the sweep.
const firstBeforeSweep = 25

// firstShare and firstMax bound the time the first checks take before the sweep: a quarter of the window, at most 30 minutes, so the
// sweep (discovery of new devices) always runs in the window.
const (
	firstShare = 4
	firstMax   = 30 * time.Minute
)

// drain checks the waiting devices in order while the window is open.
func (s *Service) drain(ctx context.Context) error { return s.drainQueue(ctx, false, 0, time.Time{}) }

// drainQueue resumes the window's waiting device checks one at a time, oldest first, and waits for each: only the devices no check
// reached yet when first is set, at most limit of them (all when 0), starting none after until (no end when zero). It stops at the
// first check that waits again (the window closed, scanning was turned off).
func (s *Service) drainQueue(ctx context.Context, first bool, limit int, until time.Time) error {
	q := `SELECT r.id FROM core_run r WHERE r.module = ? AND r.kind = ? AND r.status = 'waiting' AND r.trigger <> 'manual'`
	if first {
		q += ` AND NOT EXISTS (SELECT 1 FROM core_run c WHERE c.module = r.module AND c.kind = r.kind AND c.subject_id = r.subject_id
			AND EXISTS (SELECT 1 FROM sa_probe p WHERE p.run_id = c.id))`
	}
	rows, err := s.db.Reader().QueryContext(ctx, q+` ORDER BY r.queued_at, r.rowid LIMIT 500`, ModuleID, RunCheck)
	if err != nil {
		if ctx.Err() != nil {
			return nil // the tick ended
		}
		return fmt.Errorf("sensoractive: read the queue: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for i, id := range ids {
		if ctx.Err() != nil || (limit > 0 && i >= limit) || (!until.IsZero() && !s.clock().Before(until)) {
			return nil
		}
		s.expect(id)
		if err := s.resumeWaiting(ctx, id); err != nil {
			if errors.Is(err, run.ErrNotResumable) || errors.Is(err, run.ErrNotFound) {
				continue // a person stopped it meanwhile
			}
			return err
		}
		r, _, err := s.await(ctx, id, 0, "", false)
		if err != nil {
			return nil //nolint:nilerr // the tick ends with its context; the run goes on
		}
		if r.Status == run.Waiting {
			return nil // the rest waits too
		}
	}
	return nil
}

// sweepTurn is how often the driver looks, while a pass runs, for devices that wait for their check: one makes the pass give way
// after its batch.
var sweepTurn = time.Minute

// windowSweep goes on with the pass of the ranges inside the window: the pass that waits is resumed and one that is queued or
// running is followed. A new pass is not started here: it starts when the sweep's schedule (inventory.sweep) comes due. The devices
// that wait for their check take turns with the pass between its batches.
func (s *Service) windowSweep(ctx context.Context) error {
	sw, err := s.liveRun(ctx, RunSweep)
	if err != nil || sw == nil {
		return err
	}
	_, err = s.followPass(ctx, sw.ID, true, true)
	return err
}

// followPass follows pass id until it ends, or waits for something other than the nmap lane (the window closed, scanning off), or ctx
// ends: when it gave way to other work it is resumed once that work is done. turns: the window's devices that wait for their check
// are resumed one at a time between its batches (the window's driver). resumeOnce: a pass that waits for anything else (the worker,
// the settings) is resumed once, as the window's driver does at each tick.
func (s *Service) followPass(ctx context.Context, id string, turns, resumeOnce bool) (run.Run, error) {
	var r run.Run
	resumed := !resumeOnce     // a pass that waits for something else than the lane is resumed at most once per call (the worker came back)
	tried := map[string]bool{} // the checks given a turn in this call: one that waits again (the worker gone) is not tried again
	for range 10000 {
		if ctx.Err() != nil {
			return r, nil
		}
		var err error
		if r, err = s.runs.Read(ctx, id); err != nil {
			return r, err
		}
		switch {
		case r.Status.Ended():
			return r, nil
		case r.Status == run.Waiting:
			if s.sweepWait(withManualUntil(ctx, s.sweepUntil(r))).Status == run.Waiting {
				return r, nil // the window closed, or the settings do not allow it now
			}
			if other, _, err := s.laneBusy(ctx, id); err != nil {
				return r, err
			} else if other != "" { // the work it gave way to goes first
				s.awaitTurn(ctx, other)
				continue
			}
			// the pass goes on first: a waiting device takes its turn only after one of its batches (the running case below)
			if !s.isYielded(id) {
				if resumed || s.available(ctx) != nil {
					return r, nil // it waits for the worker or the settings: the next tick tries again
				}
				resumed = true
			}
			s.setYielded(id, false)
			s.expect(id)
			if err := s.resumeWaiting(ctx, id); err != nil && !errors.Is(err, run.ErrNotResumable) {
				return r, err
			}
			continue
		}
		if turns && s.available(ctx) == nil { // a device waiting for its check makes the pass give way after its batch
			if next, err := s.nextWaitingCheck(ctx); err == nil && next != "" && !tried[next] {
				tried[next] = true
				if err := s.resumeWaiting(ctx, next); err != nil && !errors.Is(err, run.ErrNotResumable) {
					return r, err
				}
			}
		}
		s.awaitTurn(ctx, id)
	}
	return r, nil
}

// awaitTurn waits for run id for at most sweepTurn (it goes on running after): until it ends, waits, or the turn is over.
func (s *Service) awaitTurn(ctx context.Context, id string) {
	tctx, cancel := context.WithTimeout(ctx, sweepTurn)
	defer cancel()
	_, _, _ = s.await(tctx, id, 0, "", false)
}

// nextWaitingCheck is the oldest device check of the window that waits for its turn, "" when none.
func (s *Service) nextWaitingCheck(ctx context.Context) (string, error) {
	var id string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM core_run WHERE module = ? AND kind = ? AND status = 'waiting' AND trigger <> 'manual'
		AND parent_id IS NULL ORDER BY queued_at, rowid LIMIT 1`, ModuleID, RunCheck).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("sensoractive: read the queue: %w", err)
	}
	return id, nil
}

// firstPassDue says no pass was ever made on this box.
func (s *Service) firstPassDue(ctx context.Context) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run WHERE module = ? AND kind = ?`, ModuleID, RunSweep).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sensoractive: read the first pass: %w", err)
	}
	return n == 0, nil
}

// firstPass is the one discovery pass of a box that has never swept, run at once instead of at the next window (otherwise a box set
// up at 11:00 identified nothing until 23:00): a pass and then the checks of the devices it found, with the window counted open for at
// most firstPassFor. Every other rule holds. It runs once: its run is the box's first pass; what it did not finish goes on in the
// next window from its cursor.
func (s *Service) firstPass(ctx context.Context) error {
	if err := s.available(ctx); err != nil {
		return err // not started: the next Tick tries again
	}
	s.mu.Lock()
	s.firstUntil = s.clock().Add(firstPassFor)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.firstUntil = time.Time{}
		s.mu.Unlock()
	}()
	s.log.InfoContext(ctx, "sensoractive: first pass of a new box, outside the window", "for", firstPassFor.String())
	if _, err := s.discover(ctx, run.Spec{Trigger: run.Event, TriggerNote: "the first look of a new box", RequestedBy: run.System}); err != nil &&
		!errors.Is(err, ErrStopped) && !errors.Is(err, ErrOutsideWindow) {
		s.log.WarnContext(ctx, "sensoractive: the first sweep did not run", "error", err)
	}
	return s.drain(ctx)
}

// DiscoverRanges goes on with the pass of the confirmed ranges now (PRE-1): the pass that waits is resumed, else a new one is
// queued, and it is waited for. It returns how far the pass got; ErrStopped when it stopped or waits with work left.
func (s *Service) DiscoverRanges(ctx context.Context) (Result, error) {
	return s.discover(ctx, run.Spec{Trigger: run.Schedule, RequestedBy: run.System})
}

func (s *Service) discover(ctx context.Context, base run.Spec) (Result, error) {
	st, err := s.permit(ctx)
	if err != nil {
		return Result{}, err
	}
	sw, err := s.liveRun(ctx, RunSweep)
	if err != nil {
		return Result{}, err
	}
	var id string
	switch {
	case sw == nil:
		if id, err = s.newSweep(ctx, st, base, nil); err != nil {
			return Result{}, err
		}
	case sw.Status == run.Waiting:
		id = sw.ID
		s.expect(id)
		if err := s.resumeWaiting(ctx, id); errors.Is(err, run.ErrNotResumable) {
			return Result{JobID: id}, ErrStopped // a person stopped the pass after it was read as waiting
		} else if err != nil {
			return Result{}, err
		}
	default:
		id = sw.ID
	}
	r, err := s.followPass(ctx, id, false, false) // it was just queued or resumed
	if err != nil || ctx.Err() != nil {
		return Result{JobID: id}, errors.Join(err, ctx.Err())
	}
	res := Result{JobID: id, Targets: r.Done, Status: jobStatus(r.Status)}
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_run_item WHERE run_id = ? AND outcome = 'new'`, id).Scan(&res.NewDevices); err != nil {
		return res, err
	}
	switch r.Status {
	case run.Done:
		return res, nil
	case run.Failed: // it went through its ranges; batches failed (the run says how many)
		res.Status = StatusFailed
		return res, nil
	}
	res.Status = StatusStopped
	return res, ErrStopped
}

// ---- the runs of one device ----

// runCheck is the work of a device_check run from what it stored: a person's check (trigger manual) identifies the device at once,
// whatever the window, as Scan now does; the window's check scans it when the window is open and waits for the window otherwise.
func (s *Service) runCheck(ctx context.Context, x *run.Exec) (run.Result, error) {
	d, err := x.Run(ctx)
	if err != nil {
		return run.Result{}, err
	}
	if d.Subject == nil || d.Subject.Kind != "device" {
		return run.Result{Status: run.Failed, Error: "the run names no device"}, nil
	}
	id := d.Subject.ID
	if len(d.Steps) > 0 {
		s.stepStart(ctx, x, d.Steps[0].Seq)
	}
	if d.Trigger == run.Manual {
		if d.ParentID != nil { // a Scan now identification: its caller's run handed the work in memory, and a restart ended that caller
			return run.Result{Status: run.Failed, Error: noteLost}, nil
		}
		got, err := s.identifyIn(ctx, id)
		if s.waitsForWorker(got, err) {
			return run.Result{Status: run.Waiting, WaitingFor: waitWorker}, nil
		}
		return s.checkEnd(ctx, x, d, identResult(got, err))
	}
	if d.ParentID != nil { // a device a person's sweep found: checked within that sweep's hour
		if p, err := s.runs.Read(ctx, *d.ParentID); err == nil {
			ctx = withManualUntil(ctx, s.sweepUntil(p))
		}
	}
	err = s.ScanDevice(ctx, id, "")
	return s.checkEnd(ctx, x, d, s.scanResult(ctx, err))
}

// waitsForWorker says a person's check that could not run because of the scan worker waits for it instead of failing: the worker has
// not reported since core or the scan container started (a check queued again after a restart meets it so), or it stopped under the
// check and has not reported since (an update restarts the scan container). Both come back by themselves; resumePersonsChecks starts
// the check when the worker reports and gives up after personWaitMax. A worker that reports (it says nmap is missing, or it is there
// and the job failed) does not come back by waiting: that fails with words.
func (s *Service) waitsForWorker(got Identification, err error) bool {
	gone := got.Why == WhyUnavailable || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrWorkerLost)
	return gone && s.workerAbsent()
}

// checkEnd counts the device of a check that ran to its end.
func (s *Service) checkEnd(ctx context.Context, x *run.Exec, d run.Detail, r run.Result) (run.Result, error) {
	if r.Status == "" || r.Status == run.Done {
		if len(d.Steps) > 0 {
			s.stepProgress(ctx, x, d.Steps[0].Seq, 1, 1)
		}
	}
	return r, nil
}

// scanResult is how a window's check ended, from ScanDevice's error.
func (s *Service) scanResult(ctx context.Context, err error) run.Result {
	switch {
	case err == nil:
		return run.Result{}
	case errors.Is(err, ErrNotFound):
		return run.Result{Status: run.Failed, Error: "The device is no longer in the inventory"}
	case errors.Is(err, ErrBlocked):
		return run.Result{Status: run.Failed, Error: "Not checked: the device's safety rules or the scope do not allow it"}
	case errors.Is(err, ErrScanningOff):
		return run.Result{Status: run.Waiting, WaitingFor: "active scanning to be turned on"}
	case errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
		return run.Result{Status: run.Waiting, WaitingFor: "the scan scope to be confirmed"}
	case errors.Is(err, ErrUnavailable):
		return run.Result{Status: run.Waiting, WaitingFor: waitWorker}
	case errors.Is(err, ErrWorkerLost): // the worker restarted under it (an update of Vedette does): the window tries it again
		return run.Result{Status: run.Waiting, WaitingFor: waitWorkerBack}
	case errors.Is(err, ErrOutsideWindow), errors.Is(err, errDeadline):
		if st, serr := s.inv.Settings(context.WithoutCancel(ctx)); serr == nil {
			return run.Result{Status: run.Waiting, WaitingFor: s.windowWait(st)}
		}
		return run.Result{Status: run.Waiting, WaitingFor: "the scan window"}
	case errors.Is(err, ErrStopped):
		if ctx.Err() != nil {
			return run.Result{Status: run.Partial, Error: "stopped"}
		}
		if w := s.sweepWait(context.WithoutCancel(ctx)); w.Status == run.Waiting { // scanning turned off, the window closed
			return w
		}
		return run.Result{Status: run.Partial, Error: "Stopped: the device or the settings changed while it was checked"}
	}
	return run.Result{Status: run.Failed, Error: failWords(err)}
}

// waitWorkerBack is what a check of the window waits for after the scan worker stopped under it.
const waitWorkerBack = "the scan worker, which stopped during the check (it restarts when Vedette is updated or restarted)"

// failWords is why a device run failed, in words for the run page: the scan worker's failures say what happened; any other error
// loses the package prefixes of its Go text.
func failWords(err error) string {
	switch {
	case errors.Is(err, ErrWorkerLost):
		return "The scan worker stopped during the check (it restarts when Vedette is updated or restarted). Check the device again"
	case errors.Is(err, ErrWorkerRefused):
		return "The scan worker refused the job"
	case errors.Is(err, ErrResultRejected):
		return "The scan worker's result could not be read (too large or malformed)"
	case errors.Is(err, ErrUnavailable):
		return "The scan worker is not available"
	}
	t := err.Error()
	for strings.HasPrefix(t, "sensoractive: ") {
		t = strings.TrimPrefix(t, "sensoractive: ")
	}
	return t
}

// identResult is how a person's check ended, from the identification.
func identResult(got Identification, err error) run.Result {
	switch {
	case errors.Is(err, ErrStopped) && errors.As(err, new(*stopCause)): // stopped under it for a reason of its own: the reason, exactly
		return run.Result{Status: run.Failed, Error: "The check stopped because " + stopWords(err)}
	case errors.Is(err, ErrStopped):
		return run.Result{Status: run.Partial, Error: "stopped"}
	case err != nil:
		return run.Result{Status: run.Failed, Error: failWords(err)}
	case got.Why == WhyUnavailable:
		return run.Result{Status: run.Failed, Error: "The scan worker is not available"}
	case got.Why == WhyHostDown:
		return run.Result{Status: run.Done}
	case got.Why != "":
		return run.Result{Status: run.Failed, Error: "Not checked: " + got.Why}
	}
	return run.Result{}
}

// IdentifyDevice identifies one device for the vulnerability check a person started with Scan now: a device check run (a step of
// the vulnerability check's run), queued in the nmap lane, with the scan shape of pickedPlan and at once (the window does not
// apply, as for Scan now itself). Every other rule of a device scan holds: scanning on, scope confirmed, the device's address in
// scope right before the command line is built (INV-1), the probe log (INV-9), one nmap at a time, the stop on a change of settings
// or of the device. A sweep gives way to it between two batches; when the lane does not come free within busyWait the check is
// stopped and the result says busy. The result says what was recorded, or why nothing was; err is ErrStopped when the run was
// stopped, or a failure of nmap, the worker or storage.
func (s *Service) IdentifyDevice(ctx context.Context, assetID string) (Identification, error) {
	if s.off.Load() {
		return Identification{}, ErrStopped
	}
	by := run.System
	if p := run.IDFrom(ctx); p != "" {
		if r, err := s.runs.Read(ctx, p); err == nil {
			by = r.RequestedBy
		}
	}
	lbl := s.deviceLabel(ctx, assetID)
	got := make(chan Identification, 1)
	work := func(ctx context.Context, x *run.Exec) (run.Result, error) {
		s.stepStart(ctx, x, 1)
		ident, err := s.identifyIn(ctx, assetID)
		got <- ident
		if err != nil && !errors.Is(err, ErrStopped) {
			return run.Result{}, err
		}
		r := identResult(ident, err)
		if r.Status == "" || r.Status == run.Done {
			s.stepProgress(ctx, x, 1, 1, 1)
		}
		return r, nil
	}
	err := s.doRun(ctx, run.Spec{Kind: RunCheck, Title: "Check of " + lbl, Trigger: run.Manual, RequestedBy: by,
		Subject: &run.Subject{Kind: "device", ID: assetID, Label: lbl}, Steps: []run.StepPlan{{Name: lbl, Total: 1}}},
		work, busyWait, "The scanner stayed busy, so this check did not start; the device is checked in the scan window")
	switch {
	case errors.Is(err, errNotStarted):
		return Identification{Why: WhyBusy}, nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return Identification{}, ErrStopped
	}
	select {
	case ident := <-got:
		return ident, err
	default:
		if err == nil {
			err = ErrStopped // stopped before it ran
		}
		return Identification{}, err
	}
}

// runAllPorts is the work of an all_ports run from what it stored: the weekly scan of every port of its device.
func (s *Service) runAllPorts(ctx context.Context, x *run.Exec) (run.Result, error) {
	d, err := x.Run(ctx)
	if err != nil {
		return run.Result{}, err
	}
	if d.Subject == nil {
		return run.Result{Status: run.Failed, Error: "the run names no device"}, nil
	}
	return s.allPortsResult(ctx, d.Subject.ID, s.scanDevice(ctx, d.Subject.ID, "all_ports", true)), nil
}
