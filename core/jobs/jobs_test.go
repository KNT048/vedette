package jobs_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

type gate struct {
	mu sync.Mutex
	on map[string]bool
}

func newGate(on ...string) *gate {
	g := &gate{on: map[string]bool{}}
	for _, id := range on {
		g.on[id] = true
	}
	return g
}

func (g *gate) Enabled(id string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on[id] }
func (g *gate) set(id string, v bool)  { g.mu.Lock(); defer g.mu.Unlock(); g.on[id] = v }

type recorder struct {
	mu     sync.Mutex
	runs   []jobs.Run
	ctxErr error // ctx.Err() as seen inside the last Record call
}

func (r *recorder) Record(ctx context.Context, run jobs.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, run)
	r.ctxErr = ctx.Err()
	return nil
}

func (r *recorder) statuses() []jobs.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]jobs.Status, len(r.runs))
	for i, x := range r.runs {
		out[i] = x.Status
	}
	return out
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// advance moves the bubble's fake clock forward by d and lets every goroutine settle.
func advance(d time.Duration) {
	<-time.After(d)
	synctest.Wait()
}

// start runs the scheduler in the bubble; stop cancels it and waits for Run to return.
func start(s *jobs.Scheduler) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	synctest.Wait()
	return func() { cancel(); <-done }
}

func TestRunsOnlyWhileModuleIsOn(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		g := newGate()
		s := jobs.New(quiet(), g, nil)
		var n atomic.Int32
		if err := s.Add(jobs.Job{Module: "feeds", Name: "pull", Every: time.Minute, Run: func(context.Context) error { n.Add(1); return nil }}); err != nil {
			t.Fatal(err)
		}
		stop := start(s)
		defer stop()

		advance(10 * time.Minute)
		if n.Load() != 0 {
			t.Fatalf("job ran %d times while its module was off", n.Load())
		}
		g.set("feeds", true)
		s.ModuleChanged("feeds", true)
		synctest.Wait()
		if n.Load() != 1 {
			t.Fatalf("runs right after enabling = %d, want 1 (runs at once)", n.Load())
		}
		advance(5*time.Minute + time.Second)
		if n.Load() != 6 {
			t.Fatalf("runs after 5 more minutes = %d, want 6", n.Load())
		}
		g.set("feeds", false)
		s.ModuleChanged("feeds", false)
		advance(10 * time.Minute)
		if n.Load() != 6 {
			t.Fatalf("job kept running after its module was turned off: %d", n.Load())
		}
	})
}

func TestModuleOnAtStartRunsAtOnce(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		s := jobs.New(quiet(), newGate("feeds"), nil)
		_ = s.Add(jobs.Job{Module: "feeds", Name: "pull", Every: time.Hour, Run: func(context.Context) error { n.Add(1); return nil }})
		stop := start(s)
		defer stop()
		if n.Load() != 1 {
			t.Fatalf("runs at start = %d, want 1", n.Load())
		}
	})
}

func TestNeverOverlaps(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var running, peak, total atomic.Int32
		s := jobs.New(quiet(), newGate("feeds"), nil)
		_ = s.Add(jobs.Job{Module: "feeds", Name: "slow", Every: time.Second, Run: func(context.Context) error {
			cur := running.Add(1)
			peak.Store(max(peak.Load(), cur))
			total.Add(1)
			<-time.After(5 * time.Second) // five times longer than Every
			running.Add(-1)
			return nil
		}})
		stop := start(s)
		defer stop()
		advance(40 * time.Second)
		if peak.Load() != 1 {
			t.Fatalf("peak concurrent runs = %d, want 1", peak.Load())
		}
		if total.Load() < 5 {
			t.Fatalf("only %d runs in 40 s", total.Load())
		}
	})
}

// POST-2 for jobs: turning the module off cancels the run in progress, and the history says cancelled.
func TestDisableCancelsRunningJob(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		g := newGate("scan")
		rec := &recorder{}
		s := jobs.New(quiet(), g, nil, jobs.WithRecorder(rec))
		var sawCancel atomic.Bool
		_ = s.Add(jobs.Job{Module: "scan", Name: "sweep", Every: time.Minute, Run: func(ctx context.Context) error {
			<-ctx.Done()
			sawCancel.Store(true)
			return ctx.Err()
		}})
		_ = s.Add(jobs.Job{Module: "feeds", Name: "other", Every: time.Minute, Run: func(context.Context) error { return nil }})
		g.set("feeds", true)
		stop := start(s)
		defer stop()

		g.set("scan", false)
		s.ModuleChanged("scan", false)
		synctest.Wait()
		if !sawCancel.Load() {
			t.Fatal("the running job's context was not cancelled")
		}
		var scan []jobs.Status
		rec.mu.Lock()
		for _, r := range rec.runs {
			if r.Module == "scan" {
				scan = append(scan, r.Status)
			}
		}
		rec.mu.Unlock()
		if len(scan) != 1 || scan[0] != jobs.StatusCancelled {
			t.Fatalf("scan runs = %v, want one cancelled", scan)
		}
		advance(time.Hour)
		rec.mu.Lock()
		n := 0
		for _, r := range rec.runs {
			if r.Module == "scan" {
				n++
			}
		}
		rec.mu.Unlock()
		if n != 1 {
			t.Fatalf("scan ran again while off: %d runs", n)
		}
	})
}

func TestPanicIsRecoveredAndRecorded(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{}
		var calls atomic.Int32
		s := jobs.New(quiet(), newGate("feeds"), nil, jobs.WithRecorder(rec))
		_ = s.Add(jobs.Job{Module: "feeds", Name: "bad", Every: time.Minute, Run: func(context.Context) error {
			if calls.Add(1) == 1 {
				panic("kaboom")
			}
			return nil
		}})
		stop := start(s)
		defer stop()
		advance(time.Minute + time.Second)
		got := rec.statuses()
		if len(got) != 2 || got[0] != jobs.StatusError || got[1] != jobs.StatusOK {
			t.Fatalf("statuses = %v, want [error ok]: the job must survive its own panic", got)
		}
		if !strings.Contains(rec.runs[0].Error, "kaboom") {
			t.Fatalf("error text = %q", rec.runs[0].Error)
		}
	})
}

func TestErrorTextIsBounded(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{}
		s := jobs.New(quiet(), newGate("feeds"), nil, jobs.WithRecorder(rec))
		_ = s.Add(jobs.Job{Module: "feeds", Name: "loud", Every: time.Hour, Run: func(context.Context) error {
			return errors.New(strings.Repeat("é", 5000))
		}})
		stop := start(s)
		defer stop()
		if n := len([]rune(rec.runs[0].Error)); n != 1000 || rec.runs[0].Status != jobs.StatusError {
			t.Fatalf("stored error: %d runes, status %s", n, rec.runs[0].Status)
		}
	})
}

func TestAddValidation(t *testing.T) {
	t.Parallel()
	ok := func(context.Context) error { return nil }
	s := jobs.New(quiet(), newGate(), nil)
	for name, j := range map[string]jobs.Job{
		"bad module":    {Module: "Feeds", Name: "x", Every: time.Second, Run: ok},
		"empty module":  {Module: "", Name: "x", Every: time.Second, Run: ok},
		"bad name":      {Module: "feeds", Name: "has space", Every: time.Second, Run: ok},
		"zero interval": {Module: "feeds", Name: "x", Every: 0, Run: ok},
		"negative":      {Module: "feeds", Name: "x", Every: -time.Second, Run: ok},
		"no run":        {Module: "feeds", Name: "x", Every: time.Second},
	} {
		if err := s.Add(j); !errors.Is(err, jobs.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if err := s.Add(jobs.Job{Module: "feeds", Name: "x", Every: time.Second, Run: ok}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(jobs.Job{Module: "feeds", Name: "x", Every: time.Second, Run: ok}); !errors.Is(err, jobs.ErrInvalid) {
		t.Errorf("duplicate: err = %v", err)
	}
	if err := s.Add(jobs.Job{Module: "scan", Name: "x", Every: time.Second, Run: ok}); err != nil {
		t.Errorf("same name in another module: %v", err)
	}
}

func TestAddAfterRunStarts(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var n atomic.Int32
		s := jobs.New(quiet(), newGate("feeds"), nil)
		stop := start(s)
		_ = s.Add(jobs.Job{Module: "feeds", Name: "late", Every: time.Hour, Run: func(context.Context) error { n.Add(1); return nil }})
		synctest.Wait()
		if n.Load() != 1 {
			t.Fatalf("a job added after Run did not start: %d", n.Load())
		}
		stop()
		if err := s.Add(jobs.Job{Module: "feeds", Name: "after", Every: time.Hour, Run: func(context.Context) error { return nil }}); !errors.Is(err, jobs.ErrStopped) {
			t.Fatalf("Add after stop: %v", err)
		}
	})
}

// Shutdown: Run waits for the running job, and the cancelled run is still recorded.
func TestShutdownWaitsAndRecords(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rec := &recorder{}
		s := jobs.New(quiet(), newGate("feeds"), nil, jobs.WithRecorder(rec))
		finished := make(chan struct{})
		_ = s.Add(jobs.Job{Module: "feeds", Name: "long", Every: time.Hour, Run: func(ctx context.Context) error {
			<-ctx.Done()
			<-time.After(time.Second) // cleanup that Run must wait for
			close(finished)
			return ctx.Err()
		}})
		stop := start(s)
		stop()
		select {
		case <-finished:
		default:
			t.Fatal("Run returned before the job finished")
		}
		got := rec.statuses()
		if len(got) != 1 || got[0] != jobs.StatusCancelled {
			t.Fatalf("statuses = %v", got)
		}
		if rec.ctxErr != nil {
			t.Fatal("the recorder got an already-cancelled context; the shutdown run would be lost")
		}
	})
}
