package server

import (
	"sync"
	"time"
)

// Default limits (spec section 10). The numbers are starting points, not measured (ARCH section 8).
const (
	defaultRequestsPerMinute = 60
	defaultWritesPerMinute   = 10
	maxBodyBytes             = 512 << 10
	checkTimeout             = 5 * time.Second
	defaultKillGrace         = 3 * time.Second
)

// window is a sliding-window rate limiter: at most max events in any span of per.
type window struct {
	mu    sync.Mutex
	max   int
	per   time.Duration
	times []time.Time
}

func newWindow(limit int, per time.Duration) *window { return &window{max: limit, per: per} }

// allow records an event and returns true, or returns false and how long until a slot frees.
func (w *window) allow(now time.Time) (bool, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := 0
	for i < len(w.times) && now.Sub(w.times[i]) >= w.per {
		i++
	}
	w.times = w.times[i:]
	if len(w.times) >= w.max {
		return false, w.per - now.Sub(w.times[0])
	}
	w.times = append(w.times, now)
	return true, 0
}
