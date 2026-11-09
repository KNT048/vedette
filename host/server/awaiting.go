package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Runs that wait for confirmation (D-100, docs/specs/host-api.md sections 4 and 6.5).
//
// A command returns Awaiting from Run: the run is parked in awaiting_confirm and keeps the write
// lock. Exactly one party ends it with Settle (a confirm command, a revert command, or the
// command's own timer); the first caller wins, later ones get ErrNotAwaiting and change nothing.

var (
	// ErrNotAwaiting is returned by Settle when no run with that id is awaiting confirmation:
	// it was already settled (the other side of a confirm-against-timer race won), never waited,
	// or has not finished entering the awaiting state yet.
	ErrNotAwaiting = errors.New("host: that run is not awaiting confirmation")
	// ErrShuttingDown is returned by Settle once Shutdown has begun. The run stays awaiting on
	// disk; the next start asks Options.Resume.
	ErrShuttingDown = errors.New("host: shutting down")
)

// resultAwaiting is the audit result of the line written when a run starts waiting.
const resultAwaiting = "awaiting_confirm"

// Settle ends the run runID, which must be awaiting confirmation, as status (succeeded, failed or
// reverted; failed and reverted need rerr). It writes the final audit line and the run, releases
// the write lock and sends the final event, in that order, and then runs the AfterFinish callbacks
// the awaiting command registered. It works exactly once per run (compare-and-set on the stored
// state): a second call, or a call for any other run, returns ErrNotAwaiting and changes nothing.
// The stored result of the awaiting run (Awaiting.Result) is kept.
func (s *Server) Settle(runID string, status api.Status, rerr *api.RunError) error {
	switch {
	case status == api.StatusSucceeded:
	case (status == api.StatusFailed || status == api.StatusReverted) && rerr != nil:
	default:
		return fmt.Errorf("host: Settle: %q with that error is not a final state of an awaiting run", status)
	}
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		return ErrShuttingDown
	}
	lr := s.waiting
	if lr == nil || lr.sr.Run.RunID != runID {
		s.mu.Unlock()
		return ErrNotAwaiting
	}
	s.waiting = nil // the compare-and-set: from here no other Settle and no WhileAwaiting command can see the run
	s.wg.Add(1)     // under s.mu, after the draining check: Shutdown waits for a Settle that got this far
	s.mu.Unlock()
	defer s.wg.Done()
	lr.finish(s, status, lr.sr.Run.Result, rerr, false)
	s.runAfter(lr.sub.command, lr.after, status)
	return nil
}

// enterAwaiting parks lr in awaiting_confirm after its command returned aw. It reports false (the
// caller then finishes the run as failed) only for an Awaiting that is not valid.
func (s *Server) enterAwaiting(lr *liveRun, aw Awaiting, after []func(context.Context, api.Status)) bool {
	if aw.RevertAt.IsZero() {
		s.log.Error("a command returned Awaiting without RevertAt", "command", lr.sub.command)
		return false
	}
	revertAt := aw.RevertAt.UTC()
	run := &lr.sr.Run
	run.Status, run.RevertAt, run.Result = api.StatusAwaitingConfirm, &revertAt, s.storeResult(s.baseCtx, aw.Result)
	lr.after = after
	// s.mu is held while the state is written, as submit does for a new run: the run is visible
	// as waiting only together with its stored state, and a Settle that finds it waits for the
	// write to finish, so its final record can never be overwritten by this one.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waiting = lr
	id, err := newID("au_")
	if err == nil {
		err = s.audit.append(auditEntry{
			ID: id, RequestID: run.RequestID, Actor: run.Actor, Peer: lr.sub.p, Command: run.Command,
			ArgsDigest: lr.sub.digest, ArgsRedacted: lr.sub.redacted, Result: resultAwaiting, RunID: run.RunID,
		})
	}
	if err != nil {
		// The command has already changed the system: leaving the window is worse than a missing
		// line, so the run still waits. A broken chain refuses every later write anyway.
		s.log.Error("could not audit awaiting_confirm", "run_id", run.RunID)
	}
	lr.ev.add(api.Event{Kind: api.KindState, Status: api.StatusAwaitingConfirm})
	if err := s.runs.put(lr.sr); err != nil {
		s.log.Error("could not save an awaiting run", "run_id", run.RunID)
	}
	if err := writeJSONAtomic(s.runs.eventsPath(run.RunID), lr.ev.snapshot()); err != nil {
		s.log.Error("could not save events of an awaiting run", "run_id", run.RunID)
	}
	return true
}

// resumeAwaiting keeps sr as the awaiting run when it is one and Options.Resume says so.
func (s *Server) resumeAwaiting(sr storedRun) bool {
	if sr.Run.Status != api.StatusAwaitingConfirm || sr.Run.RevertAt == nil || s.o.Resume == nil || s.waiting != nil || !s.askResume(sr.Run) {
		return false
	}
	lr := &liveRun{
		sr: sr,
		sub: submission{
			actor: sr.Run.Actor, requestID: sr.Run.RequestID, command: sr.Run.Command, digest: sr.ArgsDigest, write: true,
			redacted: map[string]any{"accepted_audit_id": sr.AcceptedAuditID},
		},
		ev: resumeEventLog(s.runs, sr.Run, s.now),
	}
	s.mu.Lock()
	s.active, s.waiting = sr.Run.RunID, lr
	s.live[sr.Run.RunID] = lr.ev
	s.mu.Unlock()
	s.log.Info("a run awaiting confirmation survived the restart", "run_id", sr.Run.RunID, "command", sr.Run.Command)
	return true
}

// askResume calls Options.Resume; a panic counts as no.
func (s *Server) askResume(run api.Run) (keep bool) {
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("Resume panicked", "run_id", run.RunID, "panic", fmt.Sprint(rec))
			keep = false
		}
	}()
	return s.o.Resume(run)
}

// resumeEventLog reloads the saved events of an awaiting run as a stream that is not finished.
func resumeEventLog(st *runStore, run api.Run, now func() time.Time) *eventLog {
	l := newEventLog(now)
	var ef eventsFile
	if err := readJSONFile(st.eventsPath(run.RunID), &ef); err == nil && ef.Next > 0 {
		l.events, l.next, l.dropped = ef.Events, ef.Next, ef.Dropped
		for _, ev := range l.events {
			l.bytes += 64 + len(ev.Line)
		}
		return l
	}
	l.add(api.Event{Kind: api.KindState, Status: api.StatusAwaitingConfirm})
	return l
}

// runAfter runs the AfterFinish callbacks of a finished run, each on its own goroutine.
func (s *Server) runAfter(command string, fns []func(context.Context, api.Status), status api.Status) {
	for _, fn := range fns {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					s.log.Error("after-finish callback panicked", "command", command, "panic", fmt.Sprint(rec))
				}
			}()
			fn(context.WithoutCancel(s.baseCtx), status)
		}()
	}
}

// gateWhileAwaiting decides a write command's fate against the awaiting run. Call with s.mu held.
// It returns nil to go on (a plain write, no run waiting), or the refusal to answer with. For a
// WhileAwaiting command that may run it records it in s.inflight and returns lockless=true.
func (s *Server) gateWhileAwaiting(cmd Command, args any, runID string) (lockless bool, ref *api.ErrorInfo, status int) {
	w := s.waiting
	if cmd.whileAwaiting {
		switch {
		case w == nil || cmd.runIDOf(args) != w.sr.Run.RunID:
			return false, &api.ErrorInfo{Code: api.CodeNotAwaitingConfirm, Message: "No run is waiting for confirmation with that run id (it may have finished or expired)."}, http.StatusPreconditionFailed
		case s.inflight != "":
			return false, &api.ErrorInfo{Code: api.CodeBusy, Message: "Another write command is already running.", RunID: s.inflight}, http.StatusConflict
		}
		s.inflight = runID
		return true, nil, 0
	}
	if w != nil {
		return false, &api.ErrorInfo{Code: api.CodePendingConfirm, Message: "A network change is waiting for confirmation; confirm or cancel it first.", RunID: w.sr.Run.RunID}, http.StatusConflict
	}
	return false, nil, 0
}
