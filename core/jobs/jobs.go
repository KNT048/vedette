// Package jobs is the in-process job scheduler (docs/ARCHITECTURE.md section 4, core IMPACT "jobs").
// A job belongs to a module and runs only while that module is on: turning the module off cancels the
// run in progress at once and the job stays idle until the module is turned on again. A job never
// overlaps itself, a panic in a job is logged and counted as an error, and every finished run is
// recorded through a Recorder.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"runtime/debug"
	"sync"
	"time"
)

var (
	moduleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// ErrInvalid is wrapped by Add when the job is malformed or a duplicate.
var ErrInvalid = errors.New("jobs: invalid job")

// ErrStopped is returned by Add after the scheduler has stopped.
var ErrStopped = errors.New("jobs: scheduler stopped")

// maxErrorText bounds the error text stored with a run (the core_job_run CHECK allows 1000).
const maxErrorText = 1000

// Job is one scheduled task.
type Job struct {
	Module string                          // owning module id; the job runs only while it is on
	Name   string                          // unique within the module, for example "pull-kev"
	Every  time.Duration                   // delay between the end of one run and the start of the next
	Run    func(ctx context.Context) error // ctx is cancelled when the module is turned off or the scheduler stops
}

// Status is how a run ended.
type Status string

// The values of core_job_run.status.
const (
	StatusOK        Status = "ok"
	StatusError     Status = "error"
	StatusCancelled Status = "cancelled"
)

// Run is the record of one finished run.
type Run struct {
	Module, Job string
	StartedAt   time.Time
	FinishedAt  time.Time
	Status      Status
	Error       string // empty unless Status is error
}

// Gate says whether a module is on. modreg.Registry satisfies it.
type Gate interface {
	Enabled(id string) bool
}

// Recorder stores finished runs. It is called after the run ended, from the job's goroutine.
type Recorder interface {
	Record(ctx context.Context, r Run) error
}

// Option configures a Scheduler.
type Option func(*Scheduler)

// WithRecorder stores run history. Without it runs are only logged.
func WithRecorder(r Recorder) Option { return func(s *Scheduler) { s.rec = r } }

// Scheduler runs jobs. Create it with New, Add jobs, then call Run.
type Scheduler struct {
	log  *slog.Logger
	now  func() time.Time
	gate Gate
	rec  Recorder

	mu      sync.Mutex
	jobs    map[string]*job // key module + "/" + name
	ctx     context.Context // set by Run
	stopped bool
	wg      sync.WaitGroup
}

type job struct {
	Job
	wake chan struct{} // capacity 1: "the module may have changed, look again"

	mu     sync.Mutex
	cancel context.CancelFunc // of the run in progress; nil when idle
}

// New returns a scheduler. gate decides which modules are on and must not be nil; clock may be nil
// (time.Now) and is used only for the timestamps of recorded runs.
func New(log *slog.Logger, gate Gate, clock func() time.Time, opts ...Option) *Scheduler {
	if clock == nil {
		clock = time.Now
	}
	s := &Scheduler{log: log, gate: gate, now: clock, jobs: map[string]*job{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Add registers a job. It may be called before or after Run; after Run starts the job begins at once
// (if its module is on).
func (s *Scheduler) Add(j Job) error {
	switch {
	case !moduleRE.MatchString(j.Module):
		return fmt.Errorf("%w: module %q must match %s", ErrInvalid, j.Module, moduleRE)
	case !nameRE.MatchString(j.Name):
		return fmt.Errorf("%w: name %q must match %s", ErrInvalid, j.Name, nameRE)
	case j.Every <= 0:
		return fmt.Errorf("%w: %s/%s has Every %v, want > 0", ErrInvalid, j.Module, j.Name, j.Every)
	case j.Run == nil:
		return fmt.Errorf("%w: %s/%s has no Run", ErrInvalid, j.Module, j.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return ErrStopped
	}
	key := j.Module + "/" + j.Name
	if _, dup := s.jobs[key]; dup {
		return fmt.Errorf("%w: %s is registered twice", ErrInvalid, key)
	}
	jb := &job{Job: j, wake: make(chan struct{}, 1)}
	s.jobs[key] = jb
	if s.ctx != nil {
		s.start(jb)
	}
	return nil
}

// Run starts every job and blocks until ctx is done and all running jobs have returned. Call it once.
func (s *Scheduler) Run(ctx context.Context) {
	s.mu.Lock()
	if s.ctx != nil || s.stopped {
		s.mu.Unlock()
		s.log.ErrorContext(ctx, "scheduler run called twice")
		return
	}
	s.ctx = ctx
	for _, jb := range s.jobs {
		s.start(jb)
	}
	s.mu.Unlock()

	<-ctx.Done()
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.wg.Wait()
}

// start launches the loop of one job; s.mu is held.
func (s *Scheduler) start(jb *job) {
	s.wg.Go(func() { s.loop(s.ctx, jb) })
}

// ModuleChanged tells the scheduler that a module was turned on or off (modreg.Registry.OnChange).
// The state is read from the gate, not from the arguments, so a late or repeated call is harmless.
// Off: the module's running jobs are cancelled before this returns. On: its idle jobs run now.
func (s *Scheduler) ModuleChanged(id string, _ bool) {
	s.mu.Lock()
	var mine []*job
	for _, jb := range s.jobs {
		if jb.Module == id {
			mine = append(mine, jb)
		}
	}
	s.mu.Unlock()
	on := s.gate.Enabled(id)
	for _, jb := range mine {
		if !on {
			jb.mu.Lock()
			if jb.cancel != nil {
				jb.cancel()
			}
			jb.mu.Unlock()
		}
		select {
		case jb.wake <- struct{}{}:
		default:
		}
	}
}

// loop runs one job: run when the module is on, then wait Every (or a wake-up), forever.
func (s *Scheduler) loop(ctx context.Context, jb *job) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // drain: the first iteration runs at once
	for {
		var wait <-chan time.Time
		if s.gate.Enabled(jb.Module) {
			s.runOnce(ctx, jb)
			if ctx.Err() != nil {
				return
			}
			if s.gate.Enabled(jb.Module) { // turned off during the run: wait for the module, not for the timer
				timer.Reset(jb.Every)
				wait = timer.C
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-jb.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-wait:
		}
	}
}

// runOnce runs the job with a context that ModuleChanged can cancel, recovers panics, and records the result.
func (s *Scheduler) runOnce(parent context.Context, jb *job) {
	ctx, cancel := context.WithCancel(parent)
	jb.mu.Lock()
	jb.cancel = cancel
	jb.mu.Unlock()
	// A module turned off between the gate check and the registration above would miss its cancel.
	if !s.gate.Enabled(jb.Module) {
		cancel()
	}
	started := s.now()
	err := s.call(ctx, jb)
	cancelled := ctx.Err() != nil && err != nil // a run that finished its work counts as ok even if the cancel came late
	jb.mu.Lock()
	jb.cancel = nil
	jb.mu.Unlock()
	cancel()

	run := Run{Module: jb.Module, Job: jb.Name, StartedAt: started, FinishedAt: s.now(), Status: StatusOK}
	switch {
	case cancelled:
		run.Status = StatusCancelled
	case err != nil:
		run.Status = StatusError
		run.Error = truncate(err.Error())
	}
	level := slog.LevelDebug
	if run.Status == StatusError {
		level = slog.LevelWarn
	}
	s.log.Log(parent, level, "job finished", "module", jb.Module, "job", jb.Name, "status", string(run.Status), "error", run.Error)
	if s.rec == nil {
		return
	}
	// The history of a run cancelled by shutdown still gets written: detach from the cancelled context.
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer rcancel()
	if err := s.rec.Record(rctx, run); err != nil {
		s.log.ErrorContext(parent, "recording job run failed", "module", jb.Module, "job", jb.Name, "error", err)
	}
}

// call runs the job and turns a panic into an error (logged with its stack, never sent anywhere).
func (s *Scheduler) call(ctx context.Context, jb *job) (err error) {
	defer func() {
		if p := recover(); p != nil {
			s.log.ErrorContext(ctx, "job panicked", "module", jb.Module, "job", jb.Name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return jb.Run(ctx)
}

func truncate(s string) string {
	r := []rune(s)
	if len(r) <= maxErrorText {
		return s
	}
	return string(r[:maxErrorText-1]) + "…"
}
