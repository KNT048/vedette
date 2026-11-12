package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The host's side of host.self_update after the park (spec 6.14 "Goroutine kết thúc", D-316 (6), plan slice
// 2b). One settle goroutine follows the journal: its first round, in the host that parked the run, starts the
// applier (park first, dispatch after); every round reads the journal and asks whether the transient unit
// still runs; it starts a dead applier once more when that second run can end by the deadline; and it ends
// the run with SettleParked when the applier's phase ends. The same loop runs in the next host, re-armed by
// Resume and AfterReady, and without a run for an orphan journal (the run file was lost), behind a write gate.

const (
	// suPoll is how often the settle loop looks (Deps.Sleep counts it).
	suPoll = 2 * time.Second
	// suSafetyMargin is how long past the journal's deadline a run may stay parked before the host gives it up
	// whatever the unit does (the merge gate of the parked-run deferred file): no applier can run past the
	// deadline (RuntimeMaxSec, and a second dispatch only when it fits), so this only ever catches a stuck host.
	suSafetyMargin = 15 * time.Minute
)

// parkSettler is what the settle loop needs from the server: (*server.Server).SettleParked.
type parkSettler interface {
	SettleParked(runID string, status api.Status, result any, rerr *api.RunError) error
}

// resumeSelfUpdate is the host.self_update part of Options.Resume: keep the parked run when the journal is
// valid, names it, and the run is not past its deadline plus the safety margin (a stuck loop must not hold
// the lock forever across restarts). It only reads.
func (o *Ops) resumeSelfUpdate(run api.Run) bool {
	j, st := o.loadSUJournal()
	if st != jOK || j.RunID != run.RunID || run.ParkedDeadline == nil || o.d.Now().After(run.ParkedDeadline.Add(suSafetyMargin)) {
		return false
	}
	o.suMu.Lock()
	o.suResumed = run.RunID
	o.suMu.Unlock()
	return true
}

// startSelfUpdate runs in Start, before the server listens: it decides what the settle loop does after READY.
// A journal of the run Resume kept is followed with the run. An orphan journal (its run is not running any
// more) still at attempt 0 is cleaned up (nothing was dispatched); one at attempt 1 or 2 raises the write gate
// (409 transition_pending) and is followed without a run. A journal that does not read is left alone and
// refuses the next self-update (transition_pending), for a person and the RUNBOOK.
func (o *Ops) startSelfUpdate() {
	o.suMu.Lock()
	resumed := o.suResumed
	o.suResumed = ""
	o.suMu.Unlock()
	j, st := o.loadSUJournal()
	switch {
	case st == jAbsent:
	case st != jOK:
		// An applier may still be running dpkg (review M5): refuse every write until a person looks (RUNBOOK 5.6).
		o.suGate.Store(true)
		o.log.Error("the self-update journal does not read; it is kept for a person and write commands are refused (RUNBOOK)")
	case j.RunID == resumed:
		o.suFollow = &suFollow{runID: j.RunID, phase: j.Phase}
	case j.Attempt == 0:
		o.cleanSelfUpdate()
		o.note(api.CmdHostSelfUpdate, "self_update_abandoned", map[string]any{"run_id": j.RunID, "phase": j.Phase})
	default:
		o.suGate.Store(true)
		o.suFollow = &suFollow{phase: j.Phase}
		o.log.Warn("an orphan self-update journal is followed without a run; write commands are refused until it ends", "run_id", j.RunID)
	}
}

// suFollow is what AfterReady starts the loop with: the run to settle ("" for an orphan journal).
type suFollow struct {
	runID string
	phase string
}

// afterReadySelfUpdate runs first in AfterReady, after READY: write started.json (the witness the applier
// waits for), then start the settle loop Start decided on. Nothing here waits for the applier before READY.
func (o *Ops) afterReadySelfUpdate(ctx context.Context) {
	if err := o.writeStarted(); err != nil {
		o.log.ErrorContext(ctx, "could not write started.json", "error", err.Error())
	}
	f := o.suFollow
	o.suFollow = nil
	if f == nil {
		return
	}
	if f.runID != "" {
		o.note(api.CmdHostSelfUpdate, "self_update_resumed", map[string]any{"run_id": f.runID, "phase": f.phase})
	}
	o.startSettle(f.runID)
}

// writeStarted writes started.json: this host's version, pid, boot id and time.
func (o *Ops) writeStarted() error {
	return o.saveSU(suStartedName, suStarted{Version: o.cfg.Version, PID: o.d.PID(), BootID: o.bootID(), At: o.d.Now().UTC()})
}

// startSettle starts the settle loop on the process's own context (never a run's).
func (o *Ops) startSettle(runID string) {
	o.mu.Lock()
	ctx := o.loopCtx
	o.mu.Unlock()
	if ctx == nil {
		o.log.Error("the settle loop has no context: Start did not run")
		return
	}
	go o.settleLoop(ctx, runID)
}

// settleLoop follows the journal until the self-update ends, and ends runID with SettleParked ("" for an
// orphan journal: then it lowers the write gate instead). A panic ends the run failed and keeps the gate up
// (merge gate of the parked run, review r1 L1): the applier may still be running, and the journal stays.
func (o *Ops) settleLoop(ctx context.Context, runID string) {
	defer func() {
		if p := recover(); p != nil {
			o.log.ErrorContext(ctx, "the self-update settle loop panicked; the run ends failed and writes are refused until the next start", "panic", fmt.Sprint(p))
			o.suGate.Store(true)
			o.settle(runID, api.StatusFailed, nil, &api.RunError{Code: api.CodeSelfUpdateInterrupted, Message: "The host lost track of the update of the system helper. See the RUNBOOK: vedette-host self-update stopped half way."})
		}
	}()
	// last is the last journal read well, seeded here: the safety net and its audit line work even when the
	// journal never reads again after this (review r2 L1, L3).
	var last suJournal
	j, st := o.loadSUJournal()
	if st == jOK {
		last = j
	}
	if runID != "" && st == jOK && j.RunID == runID && j.Attempt == 0 {
		// The first dispatch also needs a whole applier run before the deadline (review M2): a host that died
		// between the park and the dispatch and comes back late must not start an applier that outlives core's wait.
		if o.d.Now().Add(applierRuntimeMax).After(j.Deadline) {
			o.settle(runID, api.StatusFailed, nil, &api.RunError{Code: api.CodeApplierFailed, Message: "The update of the system helper could not start in time. Nothing was changed."})
			o.cleanSelfUpdate()
			return
		}
		if !o.dispatch(ctx, j, 1) {
			return
		}
		last.Attempt, last.Phase = 1, phDispatched
	}
	for ctx.Err() == nil {
		if o.settleRound(ctx, runID, &last) {
			return
		}
		if !o.d.Sleep(ctx, suPoll) {
			return
		}
	}
}

// pastNet says whether the safety net applies: the deadline is known and now is past it plus the margin.
func (o *Ops) pastNet(deadline time.Time) bool {
	return !deadline.IsZero() && o.d.Now().After(deadline.Add(suSafetyMargin))
}

// settleRound is one look; true when the loop is done. last keeps the last journal that read well.
func (o *Ops) settleRound(ctx context.Context, runID string, last *suJournal) bool {
	j, st := o.loadSUJournal()
	switch {
	case st == jUnreadable:
		if o.pastNet(last.Deadline) { // a journal that never reads again must not hold the lock past the net (review M4)
			o.suGate.Store(true)
			o.note(api.CmdHostSelfUpdate, "self_update_interrupted", map[string]any{"attempt": last.Attempt})
			return o.settle(runID, api.StatusFailed, nil, interruptedErr())
		}
		return false // an I/O error: look again
	case st != jOK || (runID != "" && j.RunID != runID):
		o.log.ErrorContext(ctx, "the self-update journal is gone or not this run's")
		o.suGate.Store(true)
		return o.settle(runID, api.StatusFailed, nil, interruptedErr())
	}
	*last = j
	if ended(j) {
		return o.finish(ctx, runID, j)
	}
	if o.pastNet(j.Deadline) { // the safety net: whatever the unit does
		return o.interrupt(runID, j)
	}
	if o.applierAlive(ctx) {
		return false
	}
	// The unit is not running: look again once (the applier may just have written its last phase and exited).
	if !o.d.Sleep(ctx, suPoll) {
		return true
	}
	j2, st2 := o.loadSUJournal()
	if st2 == jOK && j2.RunID == j.RunID {
		if ended(j2) {
			return o.finish(ctx, runID, j2)
		}
		j = j2 // the attempt is written from what the journal holds now
	}
	if o.applierAlive(ctx) {
		return false
	}
	if j.Attempt == 1 && !o.d.Now().Add(applierRuntimeMax).After(j.Deadline) && o.applierIntact(j) {
		return !o.dispatch(ctx, j, 2)
	}
	return o.interrupt(runID, j)
}

func ended(j suJournal) bool {
	return j.Phase == phInstalled || j.Phase == phRolledBack || j.Phase == phRollbackFail || j.Phase == phNotStarted
}

func interruptedErr() *api.RunError {
	return &api.RunError{Code: api.CodeSelfUpdateInterrupted, Message: "The update of the system helper was cut short twice, or could not finish in time. See the RUNBOOK: vedette-host self-update stopped half way."}
}

// applierIntact says whether selfupdate/applier is still the copy the journal names: a regular file of the
// host's owner, mode 0700, with the recorded SHA-256 (spec 6.14: checked again before a second dispatch).
func (o *Ops) applierIntact(j suJournal) bool {
	f, st, err := openRegularNoFollow(applierPath(o.cfg.StateDir))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != o.cfg.OwnerUID || st.Mode().Perm() != 0o700 {
		return false
	}
	sum, err := sha256Reader(f)
	return err == nil && sum == j.ApplierSHA256
}

// dispatch records attempt (and, for the first, the phase dispatched) in the journal, then starts the applier
// copy in its own transient unit (spec 6.14 Run 7). It reports whether the loop goes on. A failed first
// dispatch ends the run applier_failed and cleans up (nothing changed); a failed second one is interrupted.
func (o *Ops) dispatch(ctx context.Context, j suJournal, attempt int) bool {
	runID := j.RunID
	j.Attempt = attempt
	if attempt == 1 {
		j.Phase = phDispatched
	}
	err := o.saveSU(suJournalName, j)
	if err == nil {
		err = o.startUnit(ctx, systemdRunArgv(o.cfg.StateDir, runID))
	}
	if err != nil {
		o.log.ErrorContext(ctx, "could not start the applier", "attempt", attempt, "error", err.Error())
		// Review M3: the host is stopping (or systemd-run was cut short): settle nothing and leave the journal at this
		// attempt for the next host, which finds the unit running or dead. A start job that systemd may still have
		// queued counts too: when the unit is not known to be gone, keep following it.
		if ctx.Err() != nil {
			return false
		}
		if o.applierAlive(ctx) {
			o.note(api.CmdHostSelfUpdate, "self_update_dispatched", map[string]any{"unit": upgradeUnit, "attempt": attempt})
			return true
		}
		if attempt == 1 {
			o.settle(runID, api.StatusFailed, nil, &api.RunError{Code: api.CodeApplierFailed, Message: "The host could not start the transient unit that installs the update. Nothing was changed."})
			o.cleanSelfUpdate()
			return false
		}
		return !o.interrupt(runID, j)
	}
	o.note(api.CmdHostSelfUpdate, "self_update_dispatched", map[string]any{"unit": upgradeUnit, "attempt": attempt})
	return true
}

// startUnit runs systemd-run with argv (validated by the runner; Deps.StartUnit in tests, after the same validator).
func (o *Ops) startUnit(ctx context.Context, argv []string) error {
	if o.d.StartUnit != nil {
		if err := validateSystemdRun(o.cfg.StateDir)(argv); err != nil {
			return err
		}
		return o.d.StartUnit(argv)
	}
	dctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	_, code, err := o.exec(dctx, binSystemdRun, argv...)
	if err == nil && code != 0 {
		err = fmt.Errorf("systemd-run exited %d", code)
	}
	return err
}

// finish ends the self-update by the applier's last phase (spec 6.14): files first, then the run, then the
// journal and the applier copy (kept after rollback_failed). True when the loop is done.
func (o *Ops) finish(ctx context.Context, runID string, j suJournal) bool {
	res := api.HostSelfUpdateResult{From: j.From.Version, To: j.To.Version, Changed: true, SHA256: j.To.SHA256}
	detail := map[string]any{"from": j.From.Version, "to": j.To.Version}
	var status api.Status
	var rerr *api.RunError
	keep := false
	switch j.Phase {
	case phInstalled:
		if err := o.commitInstalled(j); err != nil {
			o.log.ErrorContext(ctx, "could not record the installed package; trying again", "error", err.Error())
			if !o.pastNet(j.Deadline) {
				return false
			}
			// Past the net (review M4): the new version runs; the run ends succeeded, but the journal stays and the
			// gate is up until a person records the package (RUNBOOK 5.6).
			keep = true
		}
		o.note(api.CmdHostSelfUpdate, "self_update_installed", detail)
		status = api.StatusSucceeded
	case phRolledBack:
		o.clearStaged()
		detail["reason"] = derefReason(j.Reason)
		o.note(api.CmdHostSelfUpdate, "self_update_rolled_back", detail)
		status, res.RolledBackTo = api.StatusReverted, j.From.Version
		rerr = &api.RunError{Code: derefReason(j.Reason), Message: "The new system helper did not work; the previous version " + j.From.Version + " runs again."}
	case phRollbackFail:
		o.note(api.CmdHostSelfUpdate, "self_update_rollback_failed", detail)
		status, keep = api.StatusFailed, true
		rerr = &api.RunError{Code: api.CodeRollbackFailed, Message: "The new system helper did not work and the previous version could not be put back. See the RUNBOOK: vedette-host self-update stopped half way."}
	default: // not_started
		status = api.StatusFailed
		rerr = &api.RunError{Code: derefReason(j.Reason), Message: "The update of the system helper did not start. Nothing was changed."}
	}
	if keep {
		o.suGate.Store(true)
		o.settle(runID, status, res, rerr)
		return true
	}
	o.clearStaged() // nothing needs staged/ or the applier copy any more; the journal goes only once the run is settled
	_ = removeIfThere(applierPath(o.cfg.StateDir))
	if !o.settle(runID, status, res, rerr) {
		return true // shutting down: the next host settles it from the journal
	}
	o.suGate.Store(false) // before the journal goes: whoever sees it gone finds the writes open
	o.cleanSelfUpdate()
	return true
}

func derefReason(r *string) string {
	if r == nil {
		return api.CodeSelfUpdateInterrupted
	}
	return *r
}

// commitInstalled records a successful update: the staged copy becomes packages/<to>, versions.json gets
// current = to and previous = from, and packages/ keeps those two (spec 6.14). Every step is idempotent.
func (o *Ops) commitInstalled(j suJournal) error {
	name := hostPkgName(j.To.Version, o.arch())
	if sha, _, err := o.keptFile(name); err != nil || sha != j.To.SHA256 {
		if err := copyFileAtomic(stagedPath(o.cfg.StateDir, j.To.SHA256), filepath.Join(keptDir(o.cfg.StateDir), name)); err != nil {
			return err
		}
	}
	fromSHA, fromSize, err := o.keptFile(hostPkgName(j.From.Version, o.arch()))
	v := suVersions{Current: suPkg{Version: j.To.Version, SHA256: j.To.SHA256, Size: j.To.Size}}
	if err == nil && fromSHA == j.From.SHA256 {
		v.Previous = &suPkg{Version: j.From.Version, SHA256: fromSHA, Size: fromSize}
	}
	if err := o.saveSU(suVersionsName, v); err != nil {
		return err
	}
	o.retainKept(v)
	return nil
}

// copyFileAtomic copies the host's own file src to dst (0600) through a temp file in dst's folder, fsync and
// rename, streaming (a package is up to 256 MiB).
func copyFileAtomic(src, dst string) error {
	in, _, err := openRegularNoFollow(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := io.Copy(tmp, io.LimitReader(in, maxHostPackage)); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	ok = true
	syncDir(filepath.Dir(dst))
	return nil
}

// interrupt ends the run self_update_interrupted and keeps the journal (RUNBOOK). True: the loop is done.
func (o *Ops) interrupt(runID string, j suJournal) bool {
	o.note(api.CmdHostSelfUpdate, "self_update_interrupted", map[string]any{"attempt": j.Attempt})
	o.suGate.Store(true)
	o.settle(runID, api.StatusFailed, nil, interruptedErr())
	return true
}

// settle ends runID through the server ("" for an orphan journal: nothing to settle). False only when the
// server is shutting down: the run stays parked on disk and the next host settles it.
func (o *Ops) settle(runID string, status api.Status, result any, rerr *api.RunError) bool {
	if runID == "" {
		return true
	}
	o.mu.Lock()
	s, ok := o.notifier.(parkSettler)
	o.mu.Unlock()
	if !ok {
		o.log.Error("the server cannot settle a parked run")
		return true
	}
	err := s.SettleParked(runID, status, result, rerr)
	switch {
	case errors.Is(err, server.ErrShuttingDown):
		return false
	case err != nil && !errors.Is(err, server.ErrNotParked):
		o.log.Error("could not settle the self-update run", "run_id", runID, "error", err.Error())
	}
	return true
}

// selfUpdateGate is the part of WriteGate for an orphan journal or a self-update that ended in a state a person
// must look at: 409 transition_pending for every write command.
func (o *Ops) selfUpdateGate() *server.Refusal {
	if !o.suGate.Load() {
		return nil
	}
	return refuse409(api.CodeTransitionPending, "An update of the system helper has not ended cleanly; write commands are refused until it does (see the RUNBOOK if it does not end by itself).")
}
