package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
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

// maxRevertWindow is the longest an awaiting run may wait: the 600 s of the confirm window plus
// 60 s of slack (D-100 (7)). A longer RevertAt is invalid, and on resume a stored one is clamped.
const maxRevertWindow = 660 * time.Second

// Claimed is the right to end one awaiting run, taken by Claim. Finish ends it exactly once.
type Claimed struct {
	s  *Server
	lr *liveRun
	mu sync.Mutex
	// done is set by the first successful Finish.
	done bool
}

// Claim is the compare-and-set of an awaiting run: it takes the run out of the waiting state, so
// every other Claim, Settle and WhileAwaiting command for it gets ErrNotAwaiting / 412 from now
// on, but it KEEPS the write lock until Finish. Confirm and revert must Claim first, do their
// effects, then Finish: the race between a confirm and the timer is then decided before either
// touches the system, and nothing else can write while the winner works. A Claimed must always be
// finished (use defer): until then the lock is held and Shutdown waits for it (bounded by its ctx).
// ErrNotAwaiting: no such run is waiting (already claimed or settled, never waited); ErrShuttingDown
// after Shutdown began (the run stays awaiting on disk).
func (s *Server) Claim(runID string) (*Claimed, error) {
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		return nil, ErrShuttingDown
	}
	lr := s.waiting
	if lr == nil || lr.sr.Run.RunID != runID {
		s.mu.Unlock()
		return nil, ErrNotAwaiting
	}
	s.waiting = nil
	s.wg.Add(1) // under s.mu, after the draining check: Shutdown waits for a Claim that got this far
	s.mu.Unlock()
	return &Claimed{s: s, lr: lr}, nil
}

// Finish ends the claimed run as status (succeeded, failed or reverted; failed and reverted need
// rerr): it writes the final audit line and the run, releases the write lock (or hands it to the
// WhileAwaiting command still running) and sends the final event, in that order, then runs the
// AfterFinish callbacks the awaiting command registered. The stored Awaiting.Result is kept.
// A bad status is an error and the claim stays open; a second successful Finish is ErrNotAwaiting.
func (c *Claimed) Finish(status api.Status, rerr *api.RunError) error {
	if err := checkFinal(status, rerr); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return ErrNotAwaiting
	}
	c.done = true
	defer c.s.wg.Done()
	c.lr.finish(c.s, status, c.lr.sr.Run.Result, rerr, false)
	c.s.runAfter(c.lr.sub.command, c.lr.after, status)
	return nil
}

func checkFinal(status api.Status, rerr *api.RunError) error {
	switch {
	case status == api.StatusSucceeded:
	case (status == api.StatusFailed || status == api.StatusReverted) && rerr != nil:
	default:
		return fmt.Errorf("host: %q with that error is not a final state of an awaiting run", status)
	}
	return nil
}

// Settle is Claim and Finish in one call, for an ending that has no effects of its own to run
// between the two (see Claim). It works exactly once per run (the loser of a race gets
// ErrNotAwaiting and changes nothing).
func (s *Server) Settle(runID string, status api.Status, rerr *api.RunError) error {
	if err := checkFinal(status, rerr); err != nil {
		return err
	}
	c, err := s.Claim(runID)
	if err != nil {
		return err
	}
	return c.Finish(status, rerr)
}

// enterAwaiting parks lr in awaiting_confirm after its command returned aw. It reports false (the
// caller then finishes the run as failed) for an Awaiting that is not valid: the command is not
// declared Awaits, is not a write run holding the lock, a run already waits, or RevertAt is not in
// the future or is further than maxRevertWindow from the start of the run.
func (s *Server) enterAwaiting(lr *liveRun, cmd Command, aw Awaiting, rc *RunContext) bool {
	run := &lr.sr.Run
	revertAt := aw.RevertAt.UTC()
	now := s.now()
	// The bound is elapsed + (RevertAt - now) <= 660 s with the elapsed time on the monotonic clock
	// (Sub uses it when both times have it), so a step of the wall clock during the run neither
	// refuses a good park nor lets a window of more than 660 s through.
	if !cmd.awaits || cmd.whileAwaiting || !lr.sr.Write || revertAt.IsZero() || !revertAt.After(now) || now.Sub(lr.started)+revertAt.Sub(now) > maxRevertWindow {
		s.log.Error("a command returned an invalid Awaiting", "command", lr.sub.command)
		return false
	}
	// s.mu is held while the state is written, as submit does for a new run: the run is visible
	// as waiting only together with its stored state, and a Claim that finds it waits for the
	// write to finish, so its final record can never be overwritten by this one.
	s.mu.Lock()
	if s.active != run.RunID || s.waiting != nil {
		s.mu.Unlock()
		s.log.Error("a command returned Awaiting without holding the write lock, or while a run waits", "command", lr.sub.command)
		return false
	}
	run.Status, run.RevertAt, run.Result = api.StatusAwaitingConfirm, &revertAt, s.storeResult(s.baseCtx, aw.Result)
	lr.after = rc.after
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
	s.persistEvents(lr)
	s.mu.Unlock()
	for _, fn := range rc.parked {
		s.callParked(lr.sub.command, fn)
	}
	return true
}

// persistEvents saves the events of a waiting run now and after every later event, so a restart
// resumes from the true last seq (the timer's own log lines count).
func (s *Server) persistEvents(lr *liveRun) {
	path := s.runs.eventsPath(lr.sr.Run.RunID)
	lr.ev.setPersist(path, func(error) { s.log.Error("could not save events of an awaiting run", "run_id", lr.sr.Run.RunID) })
	if err := lr.ev.save(path); err != nil {
		s.log.Error("could not save events of an awaiting run", "run_id", lr.sr.Run.RunID)
	}
}

func (s *Server) callParked(command string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("OnParked callback panicked", "command", command, "panic", fmt.Sprint(rec))
		}
	}()
	fn()
}

// resumeAwaiting keeps sr as the awaiting run when it is one and Options.Resume says so.
func (s *Server) resumeAwaiting(sr storedRun) bool {
	if sr.Run.Status != api.StatusAwaitingConfirm || sr.Run.RevertAt == nil || s.o.Resume == nil || s.waiting != nil || !s.askResume(sr.Run) {
		return false
	}
	sr.Write = true // a run that holds the lock always releases it (a damaged file must not wedge it)
	if limit := sr.Run.StartedAt.Add(maxRevertWindow); sr.Run.RevertAt.After(limit) {
		s.log.Warn("the stored revert_at is beyond the confirm window; clamped", "run_id", sr.Run.RunID)
		clamped := limit.UTC()
		sr.Run.RevertAt = &clamped
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
	lr.ev.setPersist(s.runs.eventsPath(sr.Run.RunID), func(error) { s.log.Error("could not save events of an awaiting run", "run_id", sr.Run.RunID) })
	if err := s.runs.put(lr.sr); err != nil {
		s.log.Error("could not save a resumed run", "run_id", sr.Run.RunID)
	}
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
