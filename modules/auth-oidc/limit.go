package authoidc

import (
	"net/netip"
	"strings"
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

// allowStart counts one start: per address (or IPv6 /64), per IPv6 /48, and against the box's budget. Nothing is counted unless all
// three allow it, so a refused start creates no key and costs no try (D-299). site is true when the box's budget refused it (the
// message is not "your address").
func (l *limiter) allowStart(a netip.Addr) (ok bool, wait time.Duration, site bool) {
	rules := []rule{{limitKey("start", a), limitN, limitWindow}}
	if a = a.Unmap(); a.Is6() {
		if p, err := a.Prefix(48); err == nil {
			rules = append(rules, rule{"start48 " + p.String(), limit48N, limitWindow})
		}
	}
	rules = append(rules, rule{budgetKey, startBudget, flowLifetime})
	ok, wait, failed := l.allowAll(rules...)
	return ok, wait, !ok && rules[failed].key == budgetKey
}

// budgetKey is the box's budget of starts; keepKey says which keys a flood of addresses must never make the limiter drop.
const budgetKey = "start box"

func keepKey(k string) bool { return k == budgetKey || strings.HasPrefix(k, "start48 ") }

// rule is one count: at most n tries of key per window.
type rule struct {
	key    string
	n      int
	window time.Duration
}

// allow counts one try of key against n per window and reports whether it is within the limit, with the wait until the oldest
// counted try leaves the window.
func (l *limiter) allow(key string, n int, window time.Duration) (bool, time.Duration) {
	ok, wait, _ := l.allowAll(rule{key, n, window})
	return ok, wait
}

// allowAll checks every rule and counts the try against all of them only when all allow it; otherwise it counts nothing and
// returns the index of the first rule that refused, with its wait.
func (l *limiter) allowAll(rules ...rule) (bool, time.Duration, int) {
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
			if !keepKey(k) { // the budget and the /48 counts are never dropped: a flood of addresses must not reset them
				delete(l.hits, k)
			}
		}
	}
	for i, r := range rules {
		ts := l.hits[r.key]
		for len(ts) > 0 && now.Sub(ts[0]) > r.window {
			ts = ts[1:]
		}
		if len(ts) >= r.n {
			if len(ts) > 0 {
				l.hits[r.key] = ts
			}
			return false, r.window - now.Sub(ts[0]), i
		}
	}
	for _, r := range rules {
		ts := l.hits[r.key]
		for len(ts) > 0 && now.Sub(ts[0]) > r.window {
			ts = ts[1:]
		}
		l.hits[r.key] = append(ts, now)
	}
	return true, 0, -1
}
