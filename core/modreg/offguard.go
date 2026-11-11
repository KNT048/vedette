package modreg

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Teardown is what a module offers so that "off" means off (SYS-5): it makes sure nothing of the module still runs
// outside this process (a container, an address on the host) and returns nil only when the host has confirmed it.
// It must be idempotent, must return nil at once if the module has been turned on again, and must respect ctx (each
// attempt gets OffAttempt, a Teardown that ignores ctx blocks its own retries and the shutdown wait).
type Teardown func(ctx context.Context) error

// OffAttempt is the longest one attempt of a Teardown may take; its context is cancelled after that, and the next
// attempt follows the backoff.
var OffAttempt = 60 * time.Second

// OffBackoff is the wait before each retry of a failed Teardown (D-189): 10 s, 30 s, 2 min, then every 10 min.
var OffBackoff = []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}

// OffGuard converges the real state to "off" for modules that have a Teardown, like a Kubernetes controller that
// reconciles until the actual state matches (D-189). It runs the Teardown once when core starts with the module off
// and again whenever the module is switched off, retrying with backoff until it succeeds, the module is turned on
// again or the guard's context ends. It is not a job: an off module has no jobs.
type OffGuard struct {
	ctx     context.Context
	reg     interface{ Enabled(id string) bool }
	log     *slog.Logger
	backoff []time.Duration
	// wantOn flips the guard: it converges while the module is ON (NewOnGuard), for what must run only while it is on.
	wantOn bool

	mu    sync.Mutex
	fns   map[string]Teardown
	runs  map[string]*offRun
	group sync.WaitGroup
}

type offRun struct{ cancel context.CancelFunc }

// NewOffGuard returns a guard whose retries stop when ctx ends. backoff nil means OffBackoff.
func NewOffGuard(ctx context.Context, reg interface{ Enabled(id string) bool }, log *slog.Logger, backoff []time.Duration) *OffGuard {
	if len(backoff) == 0 {
		backoff = OffBackoff
	}
	return &OffGuard{ctx: ctx, reg: reg, log: log, backoff: backoff, fns: map[string]Teardown{}, runs: map[string]*offRun{}}
}

// NewOnGuard is the mirror of NewOffGuard (M3): the same retry loop, but it runs the func registered with Add while the
// module is ON (at start with the module on, and after every switch-on), until it returns nil; a switch-off cancels it.
// The func is idempotent, returns nil at once if the module has been turned off again, and respects ctx, as a Teardown.
func NewOnGuard(ctx context.Context, reg interface{ Enabled(id string) bool }, log *slog.Logger, backoff []time.Duration) *OffGuard {
	g := NewOffGuard(ctx, reg, log, backoff)
	g.wantOn = true
	return g
}

// Add registers the Teardown of module id; if the module is in the state the guard converges in (off, or on for an
// OnGuard) right now it starts converging at once.
func (g *OffGuard) Add(id string, fn Teardown) {
	g.mu.Lock()
	g.fns[id] = fn
	g.mu.Unlock()
	if g.reg.Enabled(id) == g.wantOn {
		g.start(id)
	}
}

// ModuleChanged is a Registry.OnChange subscriber: off starts the teardown, on cancels it. It never blocks. It reads the
// state from the registry instead of trusting its argument: Publish calls subscribers after it unlocks, so two quick
// switches can arrive out of order (the scheduler does the same, jobs.go).
func (g *OffGuard) ModuleChanged(id string, _ bool) {
	if g.reg.Enabled(id) != g.wantOn {
		g.mu.Lock()
		if r := g.runs[id]; r != nil {
			r.cancel()
			delete(g.runs, id)
		}
		g.mu.Unlock()
		return
	}
	g.start(id)
}

// Wait blocks until every retry loop has ended (after the guard's context is cancelled).
func (g *OffGuard) Wait() { g.group.Wait() }

func (g *OffGuard) start(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn := g.fns[id]
	if fn == nil || g.runs[id] != nil || g.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(g.ctx)
	r := &offRun{cancel: cancel}
	g.runs[id] = r
	g.group.Add(1)
	go func() {
		defer g.group.Done()
		defer cancel()
		g.converge(ctx, id, fn)
		g.mu.Lock()
		if g.runs[id] == r {
			delete(g.runs, id)
		}
		g.mu.Unlock()
	}()
}

func (g *OffGuard) converge(ctx context.Context, id string, fn Teardown) {
	for i := 0; ; i++ {
		if ctx.Err() != nil || g.reg.Enabled(id) != g.wantOn {
			return
		}
		actx, cancel := context.WithTimeout(ctx, OffAttempt)
		err := fn(actx)
		cancel()
		if err == nil {
			return
		}
		wait := g.backoff[min(i, len(g.backoff)-1)]
		if g.wantOn {
			g.log.WarnContext(ctx, "module start has not converged; retrying", "module", id, "error", err, "retry_in", wait.String())
		} else {
			g.log.WarnContext(ctx, "module teardown has not converged; retrying", "module", id, "error", err, "retry_in", wait.String())
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
