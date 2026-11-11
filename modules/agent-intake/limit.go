package agentintake

import (
	"net/netip"
	"sync"
	"time"
)

// Rate limits of the public operations (D-169 (8), plan 2.3). In memory: counts reset on restart and are per process.
// ponytail: a flood of distinct source addresses can evict others' entries (the oldest go first); upgrade path: a table pruned by a job.
const (
	failMax      = 10               // credential failures per source per failWindow before the source is blocked
	failWindow   = time.Minute      //
	failBaseWait = 30 * time.Second // first block; doubles with each further failure while blocked out, at most failMaxWait
	failMaxWait  = 10 * time.Minute
	failForget   = 30 * time.Minute // quiet for this long: the source starts again from zero
	limiterKeys  = 50_000

	configPerMin = 6  // config calls per node per minute
	logPerMin    = 12 // log calls per node per minute
)

// srcKey is the counted unit of a source address: the address, an IPv6 client by its /64 (the block one machine usually holds).
func srcKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return "-"
	}
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

type failure struct {
	count        int
	windowStart  time.Time
	last         time.Time
	wait         time.Duration
	blockedUntil time.Time
}

// failLimiter counts credential failures per source: after failMax in a minute the source is refused (429) for a wait that doubles from
// 30 seconds to 10 minutes with every failure that comes after the block ended. A refused call is not counted, so hammering cannot
// lengthen the wait. A 160-bit token cannot be guessed; the limit protects the writer and the log.
type failLimiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*failure
}

func newFailLimiter(now func() time.Time) *failLimiter {
	return &failLimiter{now: now, m: map[string]*failure{}}
}

// blocked returns the time left of the source's block, 0 when it may call.
func (l *failLimiter) blocked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.m[key]; f != nil {
		if now := l.now(); now.Before(f.blockedUntil) {
			return f.blockedUntil.Sub(now)
		}
	}
	return 0
}

// fail counts one credential failure of the source.
func (l *failLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) >= limiterKeys {
		l.evict(now)
	}
	f := l.m[key]
	if f == nil || now.Sub(f.last) > failForget {
		f = &failure{windowStart: now}
		l.m[key] = f
	}
	if now.Sub(f.windowStart) > failWindow {
		f.windowStart, f.count = now, 0
	}
	f.last = now
	f.count++
	if f.count > failMax {
		if f.wait == 0 {
			f.wait = failBaseWait
		} else {
			f.wait = min(f.wait*2, failMaxWait)
		}
		f.blockedUntil = now.Add(f.wait)
		f.windowStart, f.count = now, 0
	}
}

// evict drops the entries that are quiet; if the table is still full of live sources, the arbitrary half.
func (l *failLimiter) evict(now time.Time) {
	for k, f := range l.m {
		if now.Sub(f.last) > failForget && now.After(f.blockedUntil) {
			delete(l.m, k)
		}
	}
	for k := range l.m {
		if len(l.m) <= limiterKeys/2 {
			break
		}
		delete(l.m, k)
	}
}

// nodeLimiter counts calls per node (config and log have separate limits) in a sliding minute.
type nodeLimiter struct {
	mu   sync.Mutex
	now  func() time.Time
	hits map[string][]time.Time
}

func newNodeLimiter(now func() time.Time) *nodeLimiter {
	return &nodeLimiter{now: now, hits: map[string][]time.Time{}}
}

// allow counts a call of kind ("config" or "log") by node and reports whether it is within max per minute; if not, the wait until
// the oldest counted call leaves the minute.
func (l *nodeLimiter) allow(node, kind string, limit int) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) >= limiterKeys {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > time.Minute {
				delete(l.hits, k)
			}
		}
		for k := range l.hits {
			if len(l.hits) <= limiterKeys/2 {
				break
			}
			delete(l.hits, k)
		}
	}
	key := kind + " " + node
	ts := l.hits[key]
	for len(ts) > 0 && now.Sub(ts[0]) >= time.Minute {
		ts = ts[1:]
	}
	if len(ts) >= limit {
		l.hits[key] = ts
		return false, time.Minute - now.Sub(ts[0])
	}
	l.hits[key] = append(ts, now)
	return true, 0
}
