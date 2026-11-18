package exposure

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The box runs one external scan at a time (INV-12). Scans that come while one runs wait in one queue, in the order they came, and
// start one after another (INV-36): a Scan now of another target (POST …/scan answers 202 with status queued and its place) and every
// scheduled scan that is due. The queue lives in memory, like the run (INV-18): after a restart a person's queued Scan now is gone, and
// a scheduled one is queued again by the next tick of the schedule, which counts from the stored last scan. The gate runs again for
// each scan right before it starts (INV-1: the TXT record, the proof, the box's IP, the commitment, the shared safety block).

// queueStartTimeout bounds the checks right before a queued scan starts (the gate may run one full check of the box's IPs).
const queueStartTimeout = 2 * time.Minute

// queuedScan is one scan that waits. Guarded by Service.runMu.
type queuedScan struct {
	id        string // the id its run gets
	targetID  string
	value     string
	by        string // who pressed Scan now, or SystemUser for the schedule
	scheduled bool
	at        time.Time
	starting  bool // its checks run now: it can no longer be removed and is the next to run

	state schedState // scheduled: the stored schedule when it was queued
	prev  *Snapshot  // scheduled: the newest snapshot before it started, to compare with (alerts)
}

// QueuedScan is a scan that waits (contract.ts QueuedScan).
type QueuedScan struct {
	TargetID    string `json:"target_id"`
	TargetValue string `json:"target_value"`
	By          string `json:"by"`
	QueuedAt    string `json:"queued_at"`
	Scheduled   bool   `json:"scheduled"`
	Starting    bool   `json:"starting"`
}

// RunQueued is the ScanRun status of a Scan now that waits behind another scan (only in the 202 answer).
const RunQueued = "queued"

// queueViewsLocked is the queue in order; nil when empty. The caller holds runMu.
func (s *Service) queueViewsLocked() []QueuedScan {
	var out []QueuedScan
	for _, q := range s.queue {
		out = append(out, QueuedScan{TargetID: q.targetID, TargetValue: q.value, By: q.by, QueuedAt: store.FormatTS(q.at), Scheduled: q.scheduled, Starting: q.starting})
	}
	return out
}

// queuedViewLocked is the answer to the Scan now that queued q. The caller holds runMu.
func (s *Service) queuedViewLocked(q *queuedScan) ScanRun {
	return ScanRun{ID: q.id, TargetID: q.targetID, TargetValue: q.value, By: q.by, StartedAt: store.FormatTS(q.at), Status: RunQueued,
		Phase: PhaseQueued, Scheduled: q.scheduled, Queue: s.queueViewsLocked()}
}

// inQueue says whether a scan of target id runs now or waits.
func (s *Service) inQueue(id string) bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.inQueueLocked(id)
}

func (s *Service) inQueueLocked(id string) bool {
	if s.run != nil && s.run.view.Status == RunRunning && s.run.view.TargetID == id {
		return true
	}
	return slices.ContainsFunc(s.queue, func(q *queuedScan) bool { return q.targetID == id })
}

// queuedLocked says whether a scan of target id waits (not the one that runs). The caller holds runMu.
func (s *Service) queuedLocked(id string) bool {
	return slices.ContainsFunc(s.queue, func(q *queuedScan) bool { return q.targetID == id })
}

// enqueue adds a scheduled scan at the end of the queue, unless the module is off, the box shuts down or the target is already in it.
func (s *Service) enqueue(q *queuedScan) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.off || s.closed || s.inQueueLocked(q.targetID) {
		return
	}
	q.id, q.at = store.NewID("sr"), s.clock()
	s.queue = append(s.queue, q)
}

// removeLocked takes q out of the queue. The caller holds runMu.
func (s *Service) removeLocked(q *queuedScan) {
	s.queue = slices.DeleteFunc(s.queue, func(x *queuedScan) bool { return x == q })
}

// dropScheduled takes the scheduled scan of target id out of the queue, when one waits and its checks have not started.
func (s *Service) dropScheduled(id string) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.queue = slices.DeleteFunc(s.queue, func(q *queuedScan) bool { return q.targetID == id && q.scheduled && !q.starting })
}

// clearQueueLocked empties the queue (the module switched off, the box shutting down). The caller holds runMu.
func (s *Service) clearQueueLocked() {
	s.queue = slices.DeleteFunc(s.queue, func(q *queuedScan) bool { return !q.starting })
}

// queueIfBusy queues a Scan now of t that passed its checks when another scan runs or others wait, and answers with its place; nil
// when nothing runs and nothing waits (the scan starts now, begin), when t itself is the one that runs (begin answers 409 busy), or
// when the module is off, the box shuts down or OpenVAS loads its feed (begin refuses). A target already waiting keeps its place (a
// scheduled scan of it becomes this person's). At most one scan of a target every ScanEvery (429), as begin.
func (s *Service) queueIfBusy(user string, t Target) (*ScanRun, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	busy := s.run != nil && s.run.view.Status == RunRunning
	if (!busy && len(s.queue) == 0) || s.off || s.closed || s.feedSync || (busy && s.run.view.TargetID == t.ID) {
		return nil, nil
	}
	for _, q := range s.queue {
		if q.targetID == t.ID {
			if q.scheduled && !q.starting {
				q.scheduled, q.by = false, user
			}
			v := s.queuedViewLocked(q)
			return &v, nil
		}
	}
	if err := s.tooSoonLocked(t, s.clock()); err != nil {
		return nil, err
	}
	q := &queuedScan{id: store.NewID("sr"), targetID: t.ID, value: t.Value, by: user, at: s.clock()}
	s.queue = append(s.queue, q)
	v := s.queuedViewLocked(q)
	return &v, nil
}

// dispatch starts the first scan of the queue when nothing runs: its checks run in the background, then begin. It is called when a
// run ends, by the schedule's tick and after a queued scan could not start.
func (s *Service) dispatch() {
	s.runMu.Lock()
	if s.dispatching || s.off || s.closed || s.feedSync || len(s.queue) == 0 || (s.run != nil && s.run.view.Status == RunRunning) {
		s.runMu.Unlock()
		return
	}
	q := s.queue[0]
	q.starting, s.dispatching = true, true
	s.runMu.Unlock()
	s.spawn(func() { s.startQueued(q) })
}

// startQueued runs the checks of q and starts it; when it cannot start, the scan is dropped from the queue with its reason: a person's
// Scan now ends as a failed run with the refusal (audited), a scheduled scan stores why (noteSkip). Then the next one is started.
func (s *Service) startQueued(q *queuedScan) {
	ctx, cancel := context.WithTimeout(s.bg, queueStartTimeout)
	defer cancel()
	t, err := s.beginQueued(ctx, q)
	s.runMu.Lock()
	s.dispatching = false
	if err != nil {
		s.removeLocked(q)
	}
	s.runMu.Unlock()
	if err != nil {
		s.queuedFailed(ctx, q, t, err)
	}
	s.dispatch()
}

// skipError is why a scheduled scan did not start, in the words of the target's note; stored: judged from what is stored (the terms,
// the proof's age), so the next tick looks again by itself and no retry time is set.
type skipError struct {
	why    string
	stored bool
}

func (e *skipError) Error() string { return "exposure: not scanned on schedule: " + e.why }

// beginQueued is the check and start of a queued scan: a scheduled one needs the scan window open now, the gate again (INV-1, INV-13)
// and accepted testing terms of the current version; every one then reads the shared safety block (INV-31) and begins.
func (s *Service) beginQueued(ctx context.Context, q *queuedScan) (Target, error) {
	if q.scheduled {
		var every string // the schedule may have been turned off since it was queued
		if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT scan_every FROM exp_target WHERE id = ?`, q.targetID).Scan(&every); err != nil || Every(every) == EveryOff {
			return Target{}, errScheduleOff
		}
		win, err := s.window(ctx)
		if err != nil || !win.open(s.clock(), s.loc()) {
			return Target{}, errOutsideWindow
		}
		prev, ok, err := previousSnapshot(ctx, s.cfg.DB.Reader(), q.targetID, "9999-12-31")
		if err != nil {
			return Target{}, err
		}
		if ok {
			q.prev = &prev
		}
	}
	t, reason, err := s.gate(ctx, q.by, q.targetID)
	if err != nil {
		return t, err
	}
	now := s.clock()
	switch {
	case reason != "" && q.scheduled:
		return t, &skipError{why: gateWhy(t, reason, now)}
	case reason != "":
		return t, s.refusal(t, reason, now)
	case q.scheduled:
		if why := scheduleWhy(t, now); why != "" {
			return t, &skipError{why: why, stored: true}
		}
	}
	if err := s.checkSafety(ctx, t); err != nil {
		return t, err
	}
	_, err = s.begin(ctx, q.by, t, "", nil, q)
	return t, err
}

// queuedFailed records a queued scan that could not start.
func (s *Service) queuedFailed(ctx context.Context, q *queuedScan, t Target, err error) {
	if errors.Is(err, errOutsideWindow) || errors.Is(err, errScheduleOff) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrModuleOff) {
		return // left for the next opening of the window; the schedule turned off; deleted meanwhile; the module off or the box stopping
	}
	if t.ID == "" {
		t = Target{ID: q.targetID, Value: q.value}
	}
	if q.scheduled {
		var se *skipError
		var ae *APIError
		if errors.As(err, &ae) && (ae.Code == "busy" || ae.Code == "rate_limited") {
			return // OpenVAS's feed update took the slot first, or the target was scanned minutes ago: the next tick queues it again
		}
		why, retry := "an error on the box stopped it", s.clock().Add(ScheduleRetry)
		switch {
		case errors.As(err, &se) && se.stored:
			why, retry = se.why, time.Time{}
		case errors.As(err, &se):
			why = se.why
		case errors.As(err, &ae):
			why = ae.Message
		default:
			s.cfg.Log.ErrorContext(ctx, "exposure: a scheduled scan could not start", "target", q.value, "error", err)
		}
		s.noteSkip(ctx, t, q.state, why, retry)
		return
	}
	s.auditScanRow(ctx, q.by, q.value, failedDetail(err))
	v := ScanRun{ID: q.id, TargetID: q.targetID, TargetValue: q.value, By: q.by, StartedAt: store.FormatTS(q.at), Status: RunFailed, Phase: PhaseQueued}
	end := store.FormatTS(s.clock())
	v.FinishedAt = &end
	var ae *APIError
	if errors.As(err, &ae) {
		v.Error = &RunError{Code: ae.Code, Message: ae.Message}
	} else {
		s.cfg.Log.ErrorContext(ctx, "exposure: a queued scan could not start", "target", q.value, "error", err)
		v.Error = &RunError{Code: "internal", Message: "The scan could not start because of an error on the box, so nothing was saved. Try again; if it keeps happening, check the box logs."}
	}
	run := &scanRun{view: v, done: make(chan struct{}), cancel: func(error) {}}
	close(run.done)
	s.runMu.Lock()
	if s.run == nil || s.run.view.Status != RunRunning { // the page of the target reads why its queued scan did not run
		s.run = run
	}
	s.runMu.Unlock()
}

// Unqueue takes the Scan now or the scheduled scan of target id out of the queue (DELETE /exposure/targets/{id}/queue, operator),
// audited as exposure.scan. 409 not_queued when no scan of it waits (or its checks have started: Stop it once it runs). A scheduled
// scan taken out skips its period: the schedule tries again one period from now, and the target says who removed it.
func (s *Service) Unqueue(ctx context.Context, by, id string) error {
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return err
	}
	s.runMu.Lock()
	var removed *queuedScan
	if i := slices.IndexFunc(s.queue, func(q *queuedScan) bool { return q.targetID == id && !q.starting }); i >= 0 {
		removed = s.queue[i]
		s.queue = slices.Delete(s.queue, i, i+1)
	}
	s.runMu.Unlock()
	if removed == nil {
		return apiErr(409, "not_queued", "%s is not waiting in the scan queue.", t.Value)
	}
	why := "removed from the queue by " + by
	if !removed.scheduled {
		s.auditScanRow(ctx, by, t.Value, why)
		return nil
	}
	s.noteSkip(ctx, t, removed.state, "the scheduled scan was "+why, removed.state.every.after(s.clock(), s.loc())) // audited there
	return nil
}

// noteRunEnd stores why a scheduled scan that started ended without a snapshot (finish): stopped by a person skips its period, failed
// tries again after ScheduleFailRetry, stopped because the terms were withdrawn waits for them (the stored state stops it anyway);
// stopped by the box (a shutdown, the module switched off) stores nothing, the next tick queues it again.
func (s *Service) noteRunEnd(ctx context.Context, q *queuedScan, t Target, err error) {
	var sb *stoppedBy
	var ae *APIError
	now := s.clock()
	switch {
	case errors.As(err, &sb) && (sb.reason == StopShutdown || sb.reason == StopModule || sb.reason == StopRestart):
	case errors.As(err, &sb) && sb.reason == StopPerson:
		s.noteSkip(ctx, t, q.state, "the scheduled scan was stopped by "+sb.by, q.state.every.after(now, s.loc()))
	case errors.As(err, &sb):
		s.noteSkip(ctx, t, q.state, "the scheduled scan was stopped: "+orWhy(sb.why, sb.by), time.Time{})
	case errors.As(err, &ae):
		s.noteSkip(ctx, t, q.state, "the scheduled scan failed: "+ae.Message, now.Add(ScheduleFailRetry))
	default:
		s.noteSkip(ctx, t, q.state, "the scheduled scan failed because of an error on the box", now.Add(ScheduleFailRetry))
	}
}

func orWhy(why, by string) string {
	if why != "" {
		return why
	}
	return "by " + by
}

// errScheduleOff: the schedule of a queued scheduled scan was turned off before it started; it is dropped, with no note.
var errScheduleOff = errors.New("exposure: the scan schedule is off")
