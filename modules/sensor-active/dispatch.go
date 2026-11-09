package sensoractive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The remote Prober (D-113, sensor-protocol.md section 6.4 and 6.5). The Dispatcher keeps one job in memory: the
// service has already checked the scope, the window and the settings and written the probe row (INV-1..3, INV-9);
// the worker in the scan container fetches the job by long poll, re-checks it, runs nmap and posts the result. Core
// never trusts what the worker says about itself beyond "it ran": the exit code, the size and the XML are checked
// here and by parseNmapXML.
const (
	// heartbeatTimeout is how long without a heartbeat before the worker counts as gone (sensor-protocol.md 6.3).
	heartbeatTimeout = 90 * time.Second
	// pickupTimeout is how long a job may wait for the worker to fetch it.
	pickupTimeout = 60 * time.Second
	// cancelGrace is how long after its context ended a probe waits for the worker to confirm the stop; then it counts
	// as stopped (the next job still waits until the worker says it runs nothing).
	cancelGrace = 30 * time.Second
	// maxJobSeconds is the longest job the protocol carries (2 hours).
	maxJobSeconds = 7200
	dispatchTick  = time.Second
)

// Errors of the remote Prober. ErrWorkerUnavailable and ErrNmapMissing wrap ErrUnavailable (INV-6): the queue keeps
// the device and tries again later. ErrWorkerLost, ErrWorkerRefused and ErrResultRejected fail the probe.
var (
	ErrWorkerUnavailable = fmt.Errorf("%w: worker_unavailable", ErrUnavailable)
	ErrNmapMissing       = fmt.Errorf("%w: nmap_missing", ErrUnavailable)
	ErrWorkerLost        = errors.New("sensoractive: worker_lost")
	ErrWorkerRefused     = errors.New("sensoractive: the worker refused the job")
	ErrResultRejected    = errors.New("sensoractive: the worker's result was rejected")
)

// DispatcherOptions configures a Dispatcher. Both fields are for tests.
type DispatcherOptions struct {
	// Now is the clock of the heartbeat, pickup and grace timeouts. nil means time.Now.
	Now func() time.Time
	// Tick is how often a waiting probe looks at those timeouts. 0 means one second.
	Tick time.Duration
	Log  *slog.Logger
}

// Dispatcher is the Prober that hands a job to the worker, and the sensorlink.Backend of the active role: the
// listener of core serves Jobs, JobRunning, JobResult and ActiveHeartbeat to it. Create it with NewDispatcher.
type Dispatcher struct {
	now      func() time.Time
	tick     time.Duration
	log      *slog.Logger
	instance string

	mu       sync.Mutex
	wake     chan struct{} // closed and replaced whenever something a long poll looks at changes
	pending  *djob         // waiting for the worker to fetch it
	running  *djob         // fetched and not finished (it may be abandoned: its probe stopped, the worker not yet)
	lastDone string        // the job that finished last
	doneSent bool          // a poll that still named it has been answered at once
	beatAt   time.Time
	haveBeat bool
	nmap     sensorlink.HeartbeatNmap
}

type djob struct {
	spec      sensorlink.Job
	deadline  time.Time // of the probe's context, zero when it has none
	done      chan struct{}
	finished  bool
	res       *sensorlink.JobResult
	err       error
	cancelled bool // the probe stopped after the worker had the job: cancel it
	cancelOut bool // a poll reply has carried the cancel
}

// NewDispatcher returns a Dispatcher with a fresh instance nonce, the one the worker's lease is tied to.
func NewDispatcher(o DispatcherOptions) *Dispatcher {
	d := &Dispatcher{now: o.Now, tick: o.Tick, log: o.Log, wake: make(chan struct{})}
	if d.now == nil {
		d.now = time.Now
	}
	if d.tick <= 0 {
		d.tick = dispatchTick
	}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	d.instance = randomHex()
	return d
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return hex.EncodeToString(b)
}

// signal wakes every long poll. The caller holds mu.
func (d *Dispatcher) signal() {
	close(d.wake)
	d.wake = make(chan struct{})
}

// fresh reports whether the worker's last heartbeat is recent. The caller holds mu.
func (d *Dispatcher) fresh(now time.Time) bool {
	return d.haveBeat && now.Sub(d.beatAt) <= heartbeatTimeout
}

// NmapHealth is "" when the worker can run nmap, otherwise what the status page says (INV-6): no heartbeat for 90 s,
// or the heartbeat says nmap is missing.
func (d *Dispatcher) NmapHealth() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case !d.fresh(d.now()):
		return "the scan worker has not reported for 90 seconds; active discovery cannot run until it does"
	case !d.nmap.Present:
		return "nmap is not installed in the scan container; active discovery cannot run until the scan image is rebuilt"
	}
	return ""
}

func (d *Dispatcher) usable() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case !d.fresh(d.now()):
		return ErrWorkerUnavailable
	case !d.nmap.Present:
		return ErrNmapMissing
	}
	return nil
}

// Probe implements Prober. argv is what nmapargv.Build made; the job on the wire carries its shape, rate and targets
// and no argv (D-111 (3)). It returns when the result is in, when the worker is gone, or when ctx ended and the worker
// had 30 seconds to confirm the stop.
func (d *Dispatcher) Probe(ctx context.Context, argv []string) (Output, error) {
	kind, rate, targets, err := nmapargv.Parse(argv)
	if err != nil {
		return Output{}, fmt.Errorf("sensoractive: %w", err)
	}
	if err := d.usable(); err != nil {
		return Output{}, err
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	j := &djob{
		spec: sensorlink.Job{ID: randomHex(), Shape: kind.Name(), Rate: rate, Targets: make([]string, len(targets))},
		done: make(chan struct{}),
	}
	for i, t := range targets {
		j.spec.Targets[i] = t.String()
	}
	j.deadline, _ = ctx.Deadline()

	d.mu.Lock()
	if d.pending != nil {
		d.mu.Unlock()
		return Output{}, errors.New("sensoractive: a probe is already waiting for the worker") // the service runs one at a time
	}
	d.pending = j
	submitted := d.now()
	d.signal()
	d.mu.Unlock()

	tk := time.NewTicker(d.tick)
	defer tk.Stop()
	ctxDone := ctx.Done()
	var abandonAt time.Time
	for {
		select {
		case <-j.done:
			if abandonAt.IsZero() {
				return d.outcome(j)
			}
			return Output{}, ctx.Err()
		case <-ctxDone:
			ctxDone = nil
			d.mu.Lock()
			switch {
			case d.pending == j: // the worker never had it: drop it
				d.pending = nil
				d.mu.Unlock()
				return Output{}, ctx.Err()
			case j.finished:
				d.mu.Unlock()
				return Output{}, ctx.Err()
			}
			j.cancelled = true // the worker has it (or is just fetching it): the next poll reply carries the cancel
			d.signal()
			d.mu.Unlock()
			abandonAt = d.now().Add(cancelGrace)
		case <-tk.C:
			now := d.now()
			d.mu.Lock()
			err := d.lookLocked(j, now, submitted, abandonAt)
			d.mu.Unlock()
			if err != nil {
				if !abandonAt.IsZero() {
					return Output{}, ctx.Err()
				}
				return Output{}, err
			}
		}
	}
}

// lookLocked checks the timeouts of a waiting probe and returns the reason it must end now, or nil.
func (d *Dispatcher) lookLocked(j *djob, now, submitted, abandonAt time.Time) error {
	switch {
	case j.finished:
		return nil
	case d.pending == j && (now.Sub(submitted) >= pickupTimeout || !d.fresh(now)):
		d.pending = nil
		return ErrWorkerUnavailable
	case d.running == j && !d.fresh(now):
		d.running = nil
		d.finishLocked(j, nil, ErrWorkerLost)
		return ErrWorkerLost
	case d.running == j && !abandonAt.IsZero() && !now.Before(abandonAt):
		return ErrStopped // the stop was not confirmed in time; the job stays in running until the worker says it is gone
	}
	return nil
}

// finishLocked records the end of j once and wakes its probe and the long poll.
func (d *Dispatcher) finishLocked(j *djob, res *sensorlink.JobResult, err error) {
	if j.finished {
		return
	}
	j.finished, j.res, j.err = true, res, err
	d.lastDone, d.doneSent = j.spec.ID, false
	close(j.done)
	d.signal()
}

// outcome turns a finished job into what Prober returns. Only the exit code, the truncation and the XML count; the
// status and the reason of the worker are used to explain a failure, never to excuse one (D-113 (5)).
func (d *Dispatcher) outcome(j *djob) (Output, error) {
	if j.err != nil {
		return Output{}, j.err
	}
	res := j.res
	switch {
	case res.Status == "refused":
		d.log.Error("sensor_active_worker_refused_job", "reason", res.Reason) // core and worker disagree on the grammar, or the worker is not what it should be
		return Output{}, fmt.Errorf("%w (%s)", ErrWorkerRefused, res.Reason)
	case res.Reason == "nmap_missing":
		d.mu.Lock()
		d.nmap.Present = false // until the next heartbeat says otherwise
		d.mu.Unlock()
		return Output{}, ErrNmapMissing
	case res.ExitCode > 0:
		return Output{}, &exec.ExitError{Name: "nmap", ExitCode: res.ExitCode}
	case res.ExitCode < 0 || res.Status != "done":
		return Output{}, fmt.Errorf("sensoractive: the worker reported %s (%s), exit %d", res.Status, res.Reason, res.ExitCode)
	}
	return Output{XML: res.XML(), Truncated: res.Truncated}, nil
}

// ---- sensorlink.Backend, active role ----

// Jobs implements sensorlink.Backend: one long poll of the worker. running is the job the worker says it runs.
func (d *Dispatcher) Jobs(ctx context.Context, wait time.Duration, running string) (sensorlink.JobsReply, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		d.mu.Lock()
		rep, ready := d.pollLocked(running)
		wake := d.wake
		d.mu.Unlock()
		if ready {
			return rep, nil
		}
		select {
		case <-wake:
		case <-timer.C:
			return rep, nil
		case <-ctx.Done():
			return rep, nil
		}
	}
}

// pollLocked decides what a poll gets. ready says to answer now rather than keep holding it.
func (d *Dispatcher) pollLocked(running string) (rep sensorlink.JobsReply, ready bool) {
	rep = sensorlink.JobsReply{Instance: d.instance, Jobs: []sensorlink.Job{}, Cancel: []string{}}
	if j := d.running; j != nil && !j.finished && running != j.spec.ID {
		// The worker runs nothing, or something else, and has not answered: it restarted, or its reply was lost (D-113 (4)).
		d.running = nil
		d.finishLocked(j, nil, ErrWorkerLost)
	}
	if j := d.running; j != nil && j.cancelled {
		rep.Cancel = append(rep.Cancel, j.spec.ID)
		if !j.cancelOut {
			j.cancelOut, ready = true, true
		}
	}
	if running != "" && running == d.lastDone && !d.doneSent && (d.running == nil || d.running.spec.ID != running) {
		// The poll still names the job that has just finished: answer now, once, so the worker polls again with a free
		// hand and the next job does not wait for a long poll to run out.
		d.doneSent = true
		return rep, true
	}
	if d.pending != nil && d.running == nil && running == "" {
		j := d.pending
		secs := maxJobSeconds
		if !j.deadline.IsZero() {
			secs = min(secs, int(math.Ceil(time.Until(j.deadline).Seconds())))
		}
		if secs < 1 {
			return rep, ready // its probe is about to stop; Probe drops it
		}
		j.spec.TimeoutS = secs
		d.pending, d.running = nil, j
		rep.Jobs = append(rep.Jobs, j.spec)
		ready = true
	}
	return rep, ready
}

// JobRunning implements sensorlink.Backend: id is the job handed to the worker and not finished.
func (d *Dispatcher) JobRunning(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running != nil && d.running.spec.ID == id && !d.running.finished
}

// JobResult implements sensorlink.Backend. A result of any job but the running one is unknown, which is also what a
// second copy of a result gets.
func (d *Dispatcher) JobResult(_ context.Context, id string, res *sensorlink.JobResult) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	j := d.running
	if j == nil || j.spec.ID != id || j.finished {
		return sensorlink.NewError(sensorlink.CodeUnknownJob)
	}
	d.running = nil
	d.finishLocked(j, res, nil)
	return nil
}

// JobResultRejected implements sensorlink.ResultRejector: the server refused the body of the result (413 or 400). The
// worker does not send it again, so the probe fails now.
func (d *Dispatcher) JobResultRejected(id string, e *sensorlink.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	j := d.running
	if j == nil || j.spec.ID != id || j.finished {
		return
	}
	d.running = nil
	err := fmt.Errorf("%w: %s", ErrResultRejected, e.Code)
	if e.Code == sensorlink.CodePayloadTooLarge {
		err = fmt.Errorf("%w: %w", errXMLTooBig, err)
	}
	d.finishLocked(j, nil, err)
}

// ActiveHeartbeat implements sensorlink.Backend and feeds Health.
func (d *Dispatcher) ActiveHeartbeat(_ context.Context, hb *sensorlink.ActiveHeartbeat) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.beatAt, d.haveBeat, d.nmap = d.now(), true, hb.Nmap
	return d.instance, nil
}
