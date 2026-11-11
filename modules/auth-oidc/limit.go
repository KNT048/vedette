package authoidc

import (
	"net/netip"
	"sync"
	"time"
)

// Start and callback are public: each is counted per client address, 30 per 15 minutes (INV-5); IPv6 per /64, the block one
// machine usually holds. ponytail: in memory, lost on restart and per process; upgrade path: core/auth's limiter if it is exported.
const (
	limitN      = 30
	limitWindow = 15 * time.Minute
	limitKeys   = 10000
)

type limiter struct {
	mu   sync.Mutex
	now  func() time.Time
	hits map[string][]time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, hits: map[string][]time.Time{}}
}

// key is the counted unit of an address.
func limitKey(kind string, a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return kind + " " + p.String()
		}
	}
	return kind + " " + clientIP(a)
}

// allow counts one try and reports whether it is within the limit, with the wait until the oldest counted try leaves the window.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > limitKeys {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > limitWindow {
				delete(l.hits, k)
			}
		}
		if len(l.hits) > limitKeys { // a flood of addresses: start over rather than grow without end
			l.hits = map[string][]time.Time{}
		}
	}
	ts := l.hits[key]
	for len(ts) > 0 && now.Sub(ts[0]) > limitWindow {
		ts = ts[1:]
	}
	if len(ts) >= limitN {
		l.hits[key] = ts
		return false, limitWindow - now.Sub(ts[0])
	}
	l.hits[key] = append(ts, now)
	return true, 0
}
