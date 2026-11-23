package sensoractive

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// ---- how long a running device run has left (run.Kind.Estimate) ----

// runProg is what the worker last said of the nmap of one device run, kept so the run's line only moves forward: a later pass, a
// later phase of the same pass, or a higher percent of the same phase replaces it; a lower one is dropped (nmap restarts its percent at
// every phase, so the raw reports read 8% → 84% → 28% → 20% over one check).
type runProg struct {
	u      progress.Update
	pass   int // which nmap run of the check the report is about (1, 2, ...)
	passes int // how many nmap runs the check makes; 0 when it is not known
	jobs   int // nmap runs that reported so far (each opens with NewPass): the pass when the caller did not say it
}

// phaseOrder is the order nmap goes through its phases within one run.
var phaseOrder = map[string]int{progress.PhaseDiscovery: 1, progress.PhasePorts: 2, progress.PhaseServices: 3, progress.PhaseScripts: 4, progress.PhaseSaving: 5}

// phaseWords say what nmap is doing in a phase, for the run's line.
var phaseWords = map[string]string{
	progress.PhaseDiscovery: "looking for the device",
	progress.PhasePorts:     "finding open ports",
	progress.PhaseServices:  "reading service versions",
	progress.PhaseScripts:   "running service checks",
	progress.PhaseSaving:    "saving what it found",
}

// runSink keeps the progress of the worker's nmap for one run (runProg): the run's summary reads it. pass and passes, when set
// (withPass), say which nmap run of the check reports now. It is called under the Dispatcher's lock, so it only takes progMu.
type runSink struct {
	s            *Service
	id           string
	pass, passes int
}

func (k runSink) Report(u progress.Update) {
	k.s.progMu.Lock()
	defer k.s.progMu.Unlock()
	if k.s.prog == nil {
		k.s.prog = map[string]runProg{}
	}
	old, had := k.s.prog[k.id]
	next := runProg{u: u, pass: k.pass, passes: k.passes, jobs: old.jobs}
	if u.NewPass || !had {
		next.jobs++
	}
	if next.pass == 0 {
		next.pass = next.jobs
	}
	if had && !forward(old, next) {
		old.jobs = next.jobs
		if old.u.Remaining > 0 && u.Remaining > 0 && old.u.Phase == u.Phase && u.Percent < 0 { // a time left without a percent still counts
			old.u.Remaining = u.Remaining
		}
		k.s.prog[k.id] = old
		return
	}
	k.s.prog[k.id] = next
}

// forward says report next moves the line of a run on from old: a later pass, a later phase of the same pass, or at least the same
// percent of the same phase (a report without a percent moves nothing back).
func forward(old, next runProg) bool {
	switch {
	case next.pass != old.pass:
		return next.pass > old.pass
	case next.u.Phase != old.u.Phase:
		return phaseOrder[next.u.Phase] > phaseOrder[old.u.Phase]
	case next.u.Percent < 0:
		return old.u.Percent < 0
	}
	return next.u.Percent >= old.u.Percent
}

func (s *Service) runSink(id string) progress.Sink { return runSink{s: s, id: id} }

// withPass is ctx with its run's sink told that the reports from now on are about nmap run pass of passes of the check.
func withPass(ctx context.Context, pass, passes int) context.Context {
	k, ok := progress.SinkFrom(ctx).(runSink)
	if !ok {
		return ctx
	}
	k.pass, k.passes = pass, passes
	return progress.WithSink(ctx, k)
}

func (s *Service) dropProgress(id string) {
	s.progMu.Lock()
	defer s.progMu.Unlock()
	delete(s.prog, id)
}

func (s *Service) lastProgress(id string) (runProg, bool) {
	s.progMu.Lock()
	defer s.progMu.Unlock()
	p, ok := s.prog[id]
	return p, ok
}

// workerEstimate is what the worker last said of the running nmap of run r and the time nmap says that phase has left: "finding open
// ports, 41%; about 9 minutes left"; "" before its first report (a local nmap reports none) and for a run that is not running.
func (s *Service) workerEstimate(_ context.Context, r run.Run) string {
	if r.Status != run.Running {
		return ""
	}
	p, ok := s.lastProgress(r.ID)
	if !ok {
		return ""
	}
	return join([]string{progressLine(p), leftWords(p.u.Remaining)})
}

// checkEstimate is the line of a running device check: where its nmap is (progressLine) and the time the check has left as a whole
// (checkHold: the same figure a run queued behind it adds up), "" for a check that is not running.
func (s *Service) checkEstimate(ctx context.Context, r run.Run) string {
	if r.Status != run.Running {
		return ""
	}
	line := ""
	if p, ok := s.lastProgress(r.ID); ok {
		line = progressLine(p)
	}
	left := ""
	if d, ok := s.checkHold(ctx, r); ok {
		left = leftWords(d)
	}
	return join([]string{line, left})
}

// checkHold is how long a device check keeps the nmap lane (run.Kind.Hold): a queued one the time a check takes here (typicalCheck), a
// running one what is left of that time, or the time the worker says its current phase has left when that is longer, at least a
// minute while it runs.
func (s *Service) checkHold(ctx context.Context, r run.Run) (time.Duration, bool) {
	typical := s.typicalCheck(ctx)
	switch r.Status {
	case run.Queued:
		return typical, true
	case run.Running:
	default:
		return 0, false
	}
	left := typical
	if r.StartedAt != nil {
		if at, err := time.Parse(time.RFC3339Nano, *r.StartedAt); err == nil {
			left = typical - s.clock().Sub(at)
		}
	}
	if p, ok := s.lastProgress(r.ID); ok && p.u.Remaining > left {
		left = p.u.Remaining
	}
	return max(left, time.Minute), true
}

// Bounds of typicalCheck.
const (
	typicalSamples  = 20              // the device checks that ended done most recently
	typicalMin      = 3               // fewer than this: the time is worked out from the rate instead
	typicalFor      = time.Minute     // how long a figure is kept before it is read again
	checkAllowance  = 2 * time.Minute // what a check spends past its port probes (versions, scripts, the second pass's waits)
	typicalFallback = 5 * time.Minute // without settings either
	typicalMax      = 2 * time.Hour   // a run's own limit (maxRun)
)

// typicalCheck is how long a device check takes on this box: the middle one of the last typicalSamples checks that ended done; with
// fewer than typicalMin of them, the bound of its probes at the scan rate (the 1,000 common ports and the extra ports, each probed
// twice) plus checkAllowance. Read again at most every typicalFor: it is called while the runs are read.
func (s *Service) typicalCheck(ctx context.Context) time.Duration {
	s.mu.Lock()
	if !s.typicalAt.IsZero() && s.clock().Sub(s.typicalAt) < typicalFor {
		d := s.typical
		s.mu.Unlock()
		return d
	}
	s.mu.Unlock()
	d := s.readTypicalCheck(ctx)
	s.mu.Lock()
	s.typical, s.typicalAt = d, s.clock()
	s.mu.Unlock()
	return d
}

func (s *Service) readTypicalCheck(ctx context.Context) time.Duration {
	var took []time.Duration
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT started_at, ended_at FROM core_run WHERE module = ? AND kind = ? AND status = 'done'
		AND started_at IS NOT NULL AND ended_at IS NOT NULL ORDER BY ended_at DESC LIMIT ?`, ModuleID, RunCheck, typicalSamples)
	if err == nil {
		for rows.Next() {
			var from, to string
			if rows.Scan(&from, &to) != nil {
				continue
			}
			a, e1 := time.Parse(time.RFC3339Nano, from)
			b, e2 := time.Parse(time.RFC3339Nano, to)
			if e1 == nil && e2 == nil && b.After(a) {
				took = append(took, b.Sub(a))
			}
		}
		_ = rows.Close()
	}
	if len(took) >= typicalMin {
		slices.Sort(took)
		return min(took[len(took)/2], typicalMax)
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.Rate < 1 {
		return typicalFallback
	}
	probes := 2 * (1000 + len(nmapargv.ExtraPortNumbers))
	return time.Duration(probes/st.Rate)*time.Second + checkAllowance
}

// progressLine writes where the worker's nmap is: the pass when the check makes several, what nmap does and its percent: "pass 1 of
// 2: reading service versions, 84%".
func progressLine(p runProg) string {
	what := phaseWords[p.u.Phase]
	if what == "" {
		what = p.u.Phase
	}
	if p.u.Percent >= 0 {
		what = fmt.Sprintf("%s, %d%%", what, int(p.u.Percent))
	}
	if p.passes > 1 && p.pass > 0 {
		return fmt.Sprintf("pass %d of %d: %s", min(p.pass, p.passes), p.passes, what)
	}
	return what
}

// leftWords writes a time left: "about 9 minutes left", "less than a minute left"; "" for none.
func leftWords(d time.Duration) string {
	switch {
	case d >= time.Minute:
		return "about " + roundWords(d) + " left"
	case d > 0:
		return "less than a minute left"
	}
	return ""
}

// allPortsHold is how long the weekly scan of every port keeps the nmap lane from a run queued behind it (run.Kind.Hold): no time, it
// gives the lane up at once (allPortsGiveWay; a queued one never starts nmap while other work waits).
func (s *Service) allPortsHold(_ context.Context, r run.Run) (time.Duration, bool) {
	return 0, r.Status == run.Running || r.Status == run.Queued
}

// allPortsGiveWay stops the weekly scan of every port that holds the nmap lane: another run is queued behind it (run.Kind.GiveWay,
// told once that run is committed). It stays due.
func (s *Service) allPortsGiveWay(context.Context, string) { s.stopWeekly() }

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
	return fmt.Sprintf("at most %s left at %d packets/s", boundWords(left), rate)
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
