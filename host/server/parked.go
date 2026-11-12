package server

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Runs parked across the host's own restart (D-316, docs/specs/host-api.md section 6.14, plan
// docs/plans/2026-11-12-host-self-update.md slice 1).
//
// A command declared Spec.Parks returns Parked from Run: the run stays running with
// parked_deadline and keeps the write lock, but its goroutine ends, so Spec.Timeout no longer
// applies and Shutdown leaves the run on disk as it is. The command's own code (a goroutine it
// starts in rc.OnParked, then after a restart the one its Options.Resume answer re-arms) ends the
// run with SettleParked; the first call wins, later ones get ErrNotParked and change nothing.

// ErrNotParked is returned by SettleParked when no run with that id is parked: it was already
// settled (the loser of a race), never parked, or has not finished parking yet.
var ErrNotParked = errors.New("host: that run is not parked")

// resultParked is the audit result of the line written when a run parks.
const resultParked = "parked"

// maxParkWindow is the longest a run may stay parked, from the start of the run: host.self_update
// needs at most 10 min before it parks plus its journal deadline of 130 min (D-316 (6)), and the
// rest is slack. A Deadline further away is invalid. ponytail: one ceiling for the one command
// that parks; raise it with the command that needs more.
const maxParkWindow = 3 * time.Hour

// Parked is what Run returns (as its result, with a nil error) to park the run instead of finishing
// it: the run is stored running with parked_deadline, an audit line parked and a log event are
// written, and the run KEEPS the global write lock until (*Server).SettleParked ends it, in this
// process or in the next one (Options.Resume). Result is stored as the run's result until then.
// Deadline must be in the future and at most maxParkWindow after the run started; the server does
// not end the run at Deadline by itself, the command's settle goroutine does.
type Parked struct {
	Deadline time.Time
	Result   any
}

// asParked recognises a Parked returned by value or by pointer.
func asParked(res any) (Parked, bool) {
	switch v := res.(type) {
	case Parked:
		return v, true
	case *Parked:
		if v != nil {
			return *v, true
		}
	}
	return Parked{}, false
}

// SettleParked ends the parked run exactly once as status (succeeded, failed or reverted; failed
// and reverted need rerr) with result (nil keeps the Parked.Result stored when it parked). As for
// an awaiting run it writes the final audit line, then the run file together with the release of
// the write lock, then the final event (seq goes on from the stored events), then runs the
// AfterFinish callbacks of the command. A bad status is an error and the run stays parked;
// ErrNotParked when no run with that id is parked (a second call included); ErrShuttingDown once
// Shutdown has begun, and the run stays parked on disk for the next start.
func (s *Server) SettleParked(runID string, status api.Status, result any, rerr *api.RunError) error {
	if err := checkFinal(status, rerr); err != nil {
		return err
	}
	var res json.RawMessage
	if result != nil {
		res = s.storeResult(s.baseCtx, result)
	}
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		return ErrShuttingDown
	}
	lr := s.parked
	if lr == nil || lr.sr.Run.RunID != runID {
		s.mu.Unlock()
		return ErrNotParked
	}
	s.parked = nil
	s.wg.Add(1) // under s.mu, after the draining check: Shutdown waits for a settle that got this far
	s.mu.Unlock()
	defer s.wg.Done()
	if result == nil {
		res = lr.sr.Run.Result
	}
	lr.finish(s, status, res, rerr, false)
	s.runAfter(lr.sub.command, lr.after, status)
	return nil
}

// errParkDraining is enterParked's answer once Shutdown has begun: outcome maps it to
// host_shutting_down even in the short window before the server context is cancelled.
var errParkDraining = errors.New("host: shutdown began before the run parked")

// enterParked parks lr after its command returned pk and reports nil. It reports an error (the
// caller then finishes the run as failed, command_failed) for a Parked that is not valid: the
// command is not declared Parks, is not a write run holding the lock, a run already waits or is
// parked, or Deadline is not in the future or is further than maxParkWindow from the start of the
// run; also when the parked run cannot be stored, since a park that is not on disk would not survive
// the restart it exists for (INV-3). It reports errParkDraining once Shutdown has begun: the run
// then ends as any run the shutdown cut short. In every error case nothing was started for the run
// (OnParked does not run) and the run is not parked.
func (s *Server) enterParked(lr *liveRun, cmd Command, pk Parked, rc *RunContext) error {
	run := &lr.sr.Run
	deadline := pk.Deadline.UTC()
	now := s.now()
	// Measured like the bound of enterAwaiting: elapsed on the monotonic clock plus what is left.
	if !cmd.parks || !lr.sr.Write || deadline.IsZero() || !deadline.After(now) || now.Sub(lr.started)+deadline.Sub(now) > maxParkWindow {
		s.log.Error("a command returned an invalid Parked", "command", lr.sub.command)
		return errors.New("invalid Parked")
	}
	// s.mu is held while the state is written, as in enterAwaiting: a SettleParked that finds the
	// run parked waits for the write to finish, so its final record never gets overwritten by this one.
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		s.log.Warn("shutdown began before the run parked; it ends failed", "run_id", run.RunID)
		return errParkDraining
	}
	if s.active != run.RunID || s.waiting != nil || s.parked != nil {
		s.mu.Unlock()
		s.log.Error("a command returned Parked without holding the write lock, or while a run waits", "command", lr.sub.command)
		return errors.New("invalid Parked")
	}
	// The run file first: whatever follows (the parked line, OnParked, the command's dispatch) may
	// rely on a restart finding the run parked on disk (Options.Resume). A failed write undoes the park.
	prevResult := run.Result
	run.ParkedDeadline, run.Result = &deadline, s.storeResult(s.baseCtx, pk.Result)
	if err := s.runs.put(lr.sr); err != nil {
		run.ParkedDeadline, run.Result = nil, prevResult
		s.mu.Unlock()
		s.log.Error("could not save a parked run; it ends failed", "run_id", run.RunID)
		return errors.New("parked run not stored")
	}
	lr.after = rc.after
	s.parked = lr
	id, err := newID("au_")
	if err == nil {
		err = s.audit.append(auditEntry{
			ID: id, RequestID: run.RequestID, Actor: run.Actor, Peer: lr.sub.p, Command: run.Command,
			ArgsDigest: lr.sub.digest, ArgsRedacted: lr.sub.redacted, Result: resultParked, RunID: run.RunID,
		})
	}
	if err != nil {
		// As for awaiting_confirm: the run is parked anyway, and a broken chain refuses every later write.
		s.log.Error("could not audit parked", "run_id", run.RunID)
	}
	lr.ev.add(api.Event{Kind: api.KindLog, Line: "The run is parked until " + deadline.Format(time.RFC3339) + "; it goes on outside the host process."})
	s.persistEvents(lr)
	s.mu.Unlock()
	for _, fn := range rc.parked {
		s.callParked(lr.sub.command, fn)
	}
	return nil
}

// resumeParked keeps sr as the parked run when it is one of a command declared Parks (a damaged
// file must not make any other run hold the lock with nothing to settle it), no other run holds the
// lock, and Options.Resume says so. A stored parked_deadline beyond maxParkWindow from the start of
// the run is clamped, never trusted. The caller re-arms its settle goroutine after New returns.
func (s *Server) resumeParked(sr storedRun) bool {
	if sr.Run.Status != api.StatusRunning || sr.Run.ParkedDeadline == nil || s.o.Resume == nil || s.active != "" {
		return false
	}
	if cmd, ok := s.reg.Lookup(sr.Run.Command); !ok || !cmd.parks || !s.askResume(sr.Run) {
		return false
	}
	if limit := sr.Run.StartedAt.Add(maxParkWindow); sr.Run.ParkedDeadline.After(limit) {
		s.log.Warn("the stored parked_deadline is beyond the park window; clamped", "run_id", sr.Run.RunID)
		clamped := limit.UTC()
		sr.Run.ParkedDeadline = &clamped
	}
	lr := s.resumedRun(sr)
	s.mu.Lock()
	s.active, s.parked = sr.Run.RunID, lr
	s.live[sr.Run.RunID] = lr.ev
	s.mu.Unlock()
	if err := s.runs.put(lr.sr); err != nil {
		s.log.Error("could not save a resumed run", "run_id", sr.Run.RunID)
	}
	s.log.Info("a parked run survived the restart", "run_id", sr.Run.RunID, "command", sr.Run.Command)
	return true
}
