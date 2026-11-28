package findings

import (
	"context"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The research queue (P-12): one background worker (ResearchWorker, the module's "research" job) works through the possible CVEs
// that are due, as soon as they are, with researchParallel CVEs at once, instead of a run after each hourly match. Its queue is the
// database's state (what is due is read again after each pass), so nothing is lost on a restart; a person's check or "Research
// deeper" goes in front (pushed), and a match that leaves new work wakes it.
const (
	researchParallel = 2 // CVEs researched at once (each its own lines in turn); a constant, not a setting
	// researchSettle is how long the worker leaves a check key it has just taken, whatever the result: a key whose state a pass does
	// not change (a record that cannot be read) is so never taken in a loop. A new record makes a new key, which is due at once.
	researchSettle = 15 * time.Minute
	// researchPause is how long the worker rests after a pass that stopped (a budget, the AI unavailable, failed calls in a row),
	// unless a person's request arrives; researchIdle is the longest it waits for work with nothing due.
	researchPause = time.Hour
	researchIdle  = time.Hour
)

// ResearchJob is the name of the research worker's job (Jobs).
const ResearchJob = "research"

// retryBackoff is how long a line whose call failed or timed out waits before it is asked again: 1 h, then 6 h, then a day.
var retryBackoff = []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour}

// researchQueue is the worker's state beside the check's (guarded by checkState.mu).
type researchQueue struct {
	wake     chan struct{}        // a pending wake of the worker (capacity 1)
	pushed   []pushedUnit         // a person's requests, first in first out, ahead of what is due
	inflight map[string]bool      // check keys being checked now
	tried    map[string]time.Time // check keys the worker took, when (researchSettle)
	pause    time.Time            // the worker rests until then (researchPause); a person's request still runs
}

// pushedUnit is a unit a person asked for, with who asked (a person's research is not the automatic one: no daily number, no share).
type pushedUnit struct {
	unit  checkUnit
	actor string
}

// wakeCh is the worker's wake channel, made on first use.
func (s *Service) wakeCh() chan struct{} {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	if s.check.rq.wake == nil {
		s.check.rq.wake = make(chan struct{}, 1)
	}
	return s.check.rq.wake
}

// wakeResearch tells the worker to look for work now (new possible CVEs, a changed record, a person's request); it never blocks.
func (s *Service) wakeResearch() {
	select {
	case s.wakeCh() <- struct{}{}:
	default:
	}
}

// push puts a person's units in front of the queue, leaving out those already queued or being checked (one call per line at a time),
// clears their retry times (a person's request reads them at once) and wakes the worker.
func (s *Service) push(units []checkUnit, actor string) {
	s.check.mu.Lock()
	for _, u := range units {
		if s.check.rq.inflight[u.key] || slices.ContainsFunc(s.check.rq.pushed, func(p pushedUnit) bool { return p.unit.key == u.key }) {
			continue
		}
		delete(s.check.held, u.key)
		delete(s.check.rq.tried, u.key)
		s.check.rq.pushed = append(s.check.rq.pushed, pushedUnit{unit: u, actor: actor})
	}
	s.check.mu.Unlock()
	s.wakeResearch()
}

// ResearchWorker is the research job's run: it works through what is due until ctx ends (the module turned off, the box shutting
// down), then returns. A pass checks every due unit (dueUnits) and the person's requests that arrive meanwhile; the next pass starts at
// once, or once the worker is woken, the next retry time comes, or researchIdle passes.
func (s *Service) ResearchWorker(ctx context.Context) error {
	wake := s.wakeCh()
	for ctx.Err() == nil {
		units := s.dueUnits(ctx)
		if len(units) > 0 || s.hasPushed() {
			s.startRun(units)
			s.runPossibleCheck(ctx, units, SystemUser)
			continue
		}
		t := time.NewTimer(s.nextLook())
		select {
		case <-ctx.Done():
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
	return nil
}

func (s *Service) hasPushed() bool {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	return len(s.check.rq.pushed) > 0
}

// startRun records a new pass as the check's state.
func (s *Service) startRun(units []checkUnit) {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	s.check.run = &CheckRun{Running: true, Total: len(units), By: SystemUser, StartedAt: store.FormatTS(s.now())}
	s.check.run.LinesTotal, s.check.run.LinesDone = s.check.lines.total, s.check.lines.done
}

// dueUnits is what the automatic research takes now: nothing while the AI cannot run, the automatic reading is off or its budget (the
// daily number, the research share of the month) is used up, or the worker rests after a stop; else every due unit (exploited first,
// then CVSS, the longest waiting line first), less those whose pages could not be read in the last day, those waiting for their retry
// time and those just taken (researchSettle).
func (s *Service) dueUnits(ctx context.Context) []checkUnit {
	if s.cfg.Checker == nil || s.cfg.Checker.Ready(ctx) != nil {
		return nil
	}
	if b := s.cfg.Checker.Budget(ctx); !b.Auto || b.Reached || b.ResearchReached {
		return nil
	}
	now := s.now()
	s.check.mu.Lock()
	paused := now.Before(s.check.rq.pause)
	s.check.mu.Unlock()
	if paused {
		return nil
	}
	items, err := s.possibleItems(ctx, "")
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading possible findings for the research failed", "error", err)
		return nil
	}
	all := slices.Clone(items)
	s.check.mu.Lock()
	recent := func(k string) bool { at, ok := s.check.unread[k]; return ok && now.Sub(at) < 24*time.Hour }
	items = slices.DeleteFunc(items, func(it PossibleItem) bool { return recent(it.Question.CheckKey) })
	s.check.mu.Unlock()
	units := s.unitsToCheck(ctx, items)
	s.check.mu.Lock()
	units = slices.DeleteFunc(units, func(u checkUnit) bool { return s.waiting(u.key, now) })
	s.check.mu.Unlock()
	if len(units) > possibleAutoMax {
		units = units[:possibleAutoMax]
	}
	total, done := lineCount(all, units)
	s.check.mu.Lock()
	s.check.lines.total, s.check.lines.done = total, done
	s.check.mu.Unlock()
	return units
}

// waiting says a key is not to be taken now: its retry time has not come, or the worker took it a moment ago. Called with
// checkState.mu held.
func (s *Service) waiting(key string, now time.Time) bool {
	if h, ok := s.check.held[key]; ok && now.Before(h.until) {
		return true
	}
	at, ok := s.check.rq.tried[key]
	return ok && now.Sub(at) < researchSettle
}

// nextLook is how long the worker waits with nothing due: until the first retry time, settle or rest ends, at most researchIdle.
func (s *Service) nextLook() time.Duration {
	now := s.now()
	next := now.Add(researchIdle)
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	soonest := func(t time.Time) {
		if t.After(now) && t.Before(next) {
			next = t
		}
	}
	for _, h := range s.check.held {
		soonest(h.until)
	}
	for _, at := range s.check.rq.tried {
		soonest(at.Add(researchSettle))
	}
	soonest(s.check.rq.pause)
	return max(next.Sub(now), time.Second)
}

// retryWait is how long the keys of a failed call wait: the next step of retryBackoff after the failures they had in a row. Called
// with checkState.mu held.
func (s *Service) retryWait(keys []string) time.Duration {
	tries := 0
	for _, k := range keys {
		tries = max(tries, s.check.held[k].tries)
	}
	return retryBackoff[min(tries, len(retryBackoff)-1)]
}

// groupJob is one CVE's units checked together, with who asked.
type groupJob struct {
	units []checkUnit
	actor string
}

// drain checks the groups take hands out, researchParallel at once, never two of one CVE at a time (so never two calls for one line),
// until take has nothing left and every group has ended. take is called by drain's goroutine alone, with the CVEs being checked.
func drain(take func(busy map[string]bool) (groupJob, bool), check func(groupJob)) {
	busy := map[string]bool{}
	done := make(chan string)
	running := 0
	for {
		var job groupJob
		ok := false
		if running < researchParallel {
			job, ok = take(busy)
		}
		if !ok {
			if running == 0 {
				return
			}
			delete(busy, <-done)
			running--
			continue
		}
		cve := job.units[0].cve
		busy[cve] = true
		running++
		go func() {
			check(job)
			done <- cve
		}()
	}
}
