package auth

import (
	"context"
	"math"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// Every argon2 run takes 64 MiB, and sign-in and resend-code are public: without a cap, a few dozen
// parallel requests would exceed the memory limit of core (DEPLOYMENT 2.5) and the restart would also wipe
// the in-memory rate limiter. The gate lets at most MaxHashing runs go at once; a request that cannot get
// a slot within HashWait, or finds the queue full, is refused with 503 server_busy and Retry-After.
const (
	defaultHashWait = 2 * time.Second
	hashQueueFactor = 4 // waiting requests allowed per slot
	busyRetryAfter  = 3 // seconds, in the response
)

// maxHashingFor is the default size of the gate: half of procs (the CPUs this process may use), at least 1,
// and when the Go memory limit is set at most a quarter of it spent on argon2 (the rest is the database,
// the scanners and the Go heap). memLimit is debug.SetMemoryLimit(-1): math.MaxInt64 means "none".
func maxHashingFor(procs int, memLimit int64, runKiB uint32) int {
	n := max(1, procs/2)
	if memLimit > 0 && memLimit != math.MaxInt64 && runKiB > 0 {
		n = min(n, max(1, int(memLimit/4/(int64(runKiB)*1024))))
	}
	return n
}

func defaultMaxHashing(p Params) int {
	return maxHashingFor(runtime.GOMAXPROCS(0), debug.SetMemoryLimit(-1), p.Memory)
}

type gate struct {
	slots    chan struct{}
	waiting  atomic.Int32
	maxQueue int32
	wait     time.Duration
}

func newGate(n int, wait time.Duration, p Params) *gate {
	if n < 1 {
		n = defaultMaxHashing(p)
	}
	if wait <= 0 {
		wait = defaultHashWait
	}
	return &gate{slots: make(chan struct{}, n), maxQueue: int32(n * hashQueueFactor), wait: wait} //nolint:gosec // n is a small CPU count
}

func errBusy() *apierr.Error {
	return apierr.New(503, CodeBusy, "The box is busy checking other sign-ins. Try again in a few seconds.").With("retry_after", busyRetryAfter)
}

// acquire waits for a free slot and returns the function that gives it back. It returns errBusy when the
// queue is full or the wait ran out, and the context's error when the request was cancelled first.
func (g *gate) acquire(ctx context.Context) (release func(), err error) {
	release = func() { <-g.slots }
	select {
	case g.slots <- struct{}{}:
		return release, nil
	default:
	}
	if g.waiting.Add(1) > g.maxQueue {
		g.waiting.Add(-1)
		return nil, errBusy()
	}
	defer g.waiting.Add(-1)
	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return release, nil
	case <-timer.C:
		return nil, errBusy()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// hashPassword is Params.Hash under the gate.
func (s *Service) hashPassword(ctx context.Context, password string) (string, error) {
	release, err := s.gate.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	s.probeEnter()
	defer s.probeLeave()
	return s.params.Hash(password)
}

// verifyPassword is Params.Verify under the gate.
func (s *Service) verifyPassword(ctx context.Context, encoded, password string) (ok, needsRehash bool, err error) {
	release, gerr := s.gate.acquire(ctx)
	if gerr != nil {
		return false, false, gerr // busy or cancelled: not ErrBadHash, so callers can tell
	}
	defer release()
	s.probeEnter()
	defer s.probeLeave()
	return s.params.Verify(encoded, password)
}

func (s *Service) probeEnter() {
	if s.probe != nil {
		s.probe(1)
	}
}

func (s *Service) probeLeave() {
	if s.probe != nil {
		s.probe(-1)
	}
}
