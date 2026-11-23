package sensoractive

import (
	"context"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
)

// ---- how long a running device run has left (run.Kind.Estimate) ----

// runSink keeps the last progress report of the worker's nmap for one run: the run's summary reads it (workerEstimate). It is
// called under the Dispatcher's lock, so it only takes progMu.
type runSink struct {
	s  *Service
	id string
}

func (k runSink) Report(u progress.Update) {
	k.s.progMu.Lock()
	defer k.s.progMu.Unlock()
	if k.s.prog == nil {
		k.s.prog = map[string]progress.Update{}
	}
	k.s.prog[k.id] = u
}

func (s *Service) runSink(id string) progress.Sink { return runSink{s: s, id: id} }

func (s *Service) dropProgress(id string) {
	s.progMu.Lock()
	defer s.progMu.Unlock()
	delete(s.prog, id)
}

func (s *Service) lastProgress(id string) (progress.Update, bool) {
	s.progMu.Lock()
	defer s.progMu.Unlock()
	u, ok := s.prog[id]
	return u, ok
}

// workerEstimate is what the worker last said of the running nmap of run r: "41% of the ports; about 9 minutes left"; "" before
// its first report (a local nmap reports none) and for a run that is not running.
func (s *Service) workerEstimate(_ context.Context, r run.Run) string {
	if r.Status != run.Running {
		return ""
	}
	u, ok := s.lastProgress(r.ID)
	if !ok {
		return ""
	}
	return progressWords(u)
}

// checkHold is how long a running device check keeps the nmap lane (run.Kind.Hold): the time the worker last said its nmap has left;
// unknown before its first report, for a local nmap and for a queued check.
func (s *Service) checkHold(_ context.Context, r run.Run) (time.Duration, bool) {
	if r.Status != run.Running {
		return 0, false
	}
	u, ok := s.lastProgress(r.ID)
	if !ok || u.Remaining <= 0 {
		return 0, false
	}
	return u.Remaining, true
}

// allPortsHold is how long the weekly scan of every port keeps the nmap lane from a run queued behind it (run.Kind.Hold): no time, it
// gives the lane up at once (allPortsGiveWay; a queued one never starts nmap while other work waits).
func (s *Service) allPortsHold(_ context.Context, r run.Run) (time.Duration, bool) {
	return 0, r.Status == run.Running || r.Status == run.Queued
}

// allPortsGiveWay stops the weekly scan of every port that holds the nmap lane: another run is queued behind it (run.Kind.GiveWay,
// told once that run is committed). It stays due.
func (s *Service) allPortsGiveWay(context.Context, string) { s.stopWeekly() }

// progressWords writes a worker's report: its percent and the time nmap says is left.
func progressWords(u progress.Update) string {
	var parts []string
	if u.Percent >= 0 {
		parts = append(parts, fmt.Sprintf("%d%% of this pass", int(u.Percent)))
	}
	switch {
	case u.Remaining >= time.Minute:
		parts = append(parts, "about "+roundWords(u.Remaining)+" left")
	case u.Remaining > 0:
		parts = append(parts, "less than a minute left")
	}
	return join(parts)
}

// allPortsSends is the most probes the weekly discovery sends: every TCP port, a dropped one twice (--max-retries 1).
const allPortsSends = 2 * 65535

// allPortsEstimate is how long the weekly scan of every port of run r has left: the worker's own report when there is one, else the
// bound of its pace ("at most 18 minutes left at 100 packets/s": every port probed twice at its rate). "" once the discovery is past
// that bound (the follow-up reads the services) and for a run that is not running.
func (s *Service) allPortsEstimate(ctx context.Context, r run.Run) string {
	if w := s.workerEstimate(ctx, r); w != "" {
		return w
	}
	if r.Status != run.Running {
		return ""
	}
	s.mu.Lock()
	var rate int
	var from time.Time
	if c := s.cur; c != nil && c.weekly && c.runID == r.ID {
		rate, from = c.pace, c.paceFrom
	}
	s.mu.Unlock()
	if rate < 1 || from.IsZero() {
		return ""
	}
	left := time.Duration(allPortsSends/rate)*time.Second - s.clock().Sub(from)
	if left < time.Minute {
		return ""
	}
	return fmt.Sprintf("at most %s left at %d packets/s", roundWords(left), rate)
}

// join joins the non-empty parts with "; ".
func join(parts []string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += "; "
		}
		out += p
	}
	return out
}
