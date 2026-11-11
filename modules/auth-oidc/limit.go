package authoidc

import (
	"net/netip"
	"sync"
	"time"
)

// Start and callback are public: each is counted per client address, 30 per 15 minutes (INV-5); IPv6 per /64, the block one
// machine usually holds, and also per /48 (100 per 15 minutes), the block one site usually gets, so one network cannot spread over
// thousands of /64s. Starts are also counted for the whole box (startBudget per flowLifetime, D-299): fewer than maxFlows, so a
// flood can delay new SSO sign-ins but never push out one in progress (password sign-in is not touched). ponytail: in memory, lost
// on restart and per process.
const (
	limitN      = 30
	limit48N    = 100
	limitWindow = 15 * time.Minute
	limitKeys   = 10000
	startBudget = 300 // starts per flowLifetime for the whole box: far above a team's sign-ins, below maxFlows
)

type limiter struct {
	mu       sync.Mutex
	now      func() time.Time
	hits     map[string][]time.Time
	warnedAt time.Time // the last warning that the box's budget was used up: at most one a minute
}

// warnBudget reports whether the refusal by the box's budget should be logged now: at most once a minute, not once a refused start.
func (l *limiter) warnBudget() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); l.warnedAt.IsZero() || now.Sub(l.warnedAt) >= time.Minute || now.Before(l.warnedAt) {
		l.warnedAt = now
		return true
	}
	return false
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

// allowStart counts one start: per address (or IPv6 /64), per IPv6 /48, then against the box's budget. A start refused at one
// step is still counted at the steps before it. site is true when the box's budget refused it (the message is not "your address").
func (l *limiter) allowStart(a netip.Addr) (ok bool, wait time.Duration, site bool) {
	if ok, wait := l.allow(limitKey("start", a), limitN, limitWindow); !ok {
		return false, wait, false
	}
	if a = a.Unmap(); a.Is6() {
		if p, err := a.Prefix(48); err == nil {
			if ok, wait := l.allow("start48 "+p.String(), limit48N, limitWindow); !ok {
				return false, wait, false
			}
		}
	}
	if ok, wait := l.allow("start box", startBudget, flowLifetime); !ok {
		return false, wait, true
	}
	return true, 0, false
}

// allow counts one try of key against n per window and reports whether it is within the limit, with the wait until the oldest
// counted try leaves the window.
func (l *limiter) allow(key string, n int, window time.Duration) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > limitKeys {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > limitWindow {
				delete(l.hits, k)
			}
		}
		for k := range l.hits { // still full of live keys (a flood of addresses): drop arbitrary ones down to half, never all
			if len(l.hits) <= limitKeys/2 {
				break
			}
			if k != "start box" { // the box's budget is never dropped: that is what a flood of addresses must not reset
				delete(l.hits, k)
			}
		}
	}
	ts := l.hits[key]
	for len(ts) > 0 && now.Sub(ts[0]) > window {
		ts = ts[1:]
	}
	if len(ts) >= n {
		l.hits[key] = ts
		return false, window - now.Sub(ts[0])
	}
	l.hits[key] = append(ts, now)
	return true, 0
}
