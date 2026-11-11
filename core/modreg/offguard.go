package modreg

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Teardown is what a module offers so that "off" means off (SYS-5): it makes sure nothing of the module still runs
// outside this process (a container, an address on the host) and returns nil only when the host has confirmed it.
// It must be idempotent and must return nil at once if the module has been turned on again.
type Teardown func(ctx context.Context) error

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

// Add registers the Teardown of module id; if the module is off right now it starts converging at once.
func (g *OffGuard) Add(id string, fn Teardown) {
	g.mu.Lock()
	g.fns[id] = fn
	g.mu.Unlock()
	if !g.reg.Enabled(id) {
		g.start(id)
	}
}

// ModuleChanged is a Registry.OnChange subscriber: off starts the teardown, on cancels it. It never blocks.
func (g *OffGuard) ModuleChanged(id string, enabled bool) {
	if enabled {
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
		if ctx.Err() != nil || g.reg.Enabled(id) {
			return
		}
		err := fn(ctx)
		if err == nil {
			return
		}
		wait := g.backoff[min(i, len(g.backoff)-1)]
		g.log.WarnContext(ctx, "module teardown has not converged; retrying", "module", id, "error", err, "retry_in", wait.String())
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
