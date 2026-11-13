package server

import (
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// The per-address limit of public requests that carry no valid session (API_CONVENTIONS §8, D-320): sign-in, setup, approval links,
// the block-list URL. Counted per client address, IPv6 per /64 (one machine's block). Not counted: a request with a valid session
// (the signed-in app polls GET /setup), a 401 of a protected route (it costs one indexed read and writes nothing, and the app needs
// the 401 to go to the sign-in page), the osquery agents' enrollment, intake and installer routes (a fleet behind one NAT address;
// they carry their own enrollment secret and body limits), and loopback (the box itself: the health check, `vedette` commands).
// ponytail: in memory, a sliding window per key, lost on restart; at most pubKeys keys (a flood of addresses, for example one /48's
// /64s, drops arbitrary keys and so resets other addresses' counts: the sign-in limits of core/auth still hold).
const (
	pubWindow = time.Minute
	pubKeys   = 10000
)

// pubExempt are the operationId prefixes of the agent routes that are not counted.
var pubExempt = []string{"inventory_post_intake_", "inventory_get_intake_", "inventory_get_install_"}

type pubLimiter struct {
	n    int
	now  func() time.Time
	mu   sync.Mutex
	hits map[netip.Addr][]time.Time
}

func newPubLimiter(n int, now func() time.Time) *pubLimiter {
	if n <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &pubLimiter{n: n, now: now, hits: map[netip.Addr][]time.Time{}}
}

// pubKey is the counted unit of a request's peer; ok is false when it is not counted (loopback, or no address to key on).
func pubKey(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	a := ap.Addr().Unmap().WithZone("")
	if a.IsLoopback() {
		return netip.Addr{}, false
	}
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr(), true
		}
	}
	return a, true
}

// allow counts one request of r's peer and reports whether it is within the limit, with the wait until a slot frees.
func (l *pubLimiter) allow(r *http.Request) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	k, ok := pubKey(r)
	if !ok {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > pubKeys {
		for a, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > pubWindow {
				delete(l.hits, a)
			}
		}
		for a := range l.hits { // still full of live keys (a flood of addresses): drop arbitrary ones down to half
			if len(l.hits) <= pubKeys/2 {
				break
			}
			delete(l.hits, a)
		}
	}
	ts := l.hits[k]
	for len(ts) > 0 && now.Sub(ts[0]) >= pubWindow {
		ts = ts[1:]
	}
	if len(ts) >= l.n {
		l.hits[k] = ts
		return false, pubWindow - now.Sub(ts[0])
	}
	l.hits[k] = append(ts, now)
	return true, 0
}

func pubCounted(opID string) bool {
	for _, p := range pubExempt {
		if strings.HasPrefix(opID, p) {
			return false
		}
	}
	return true
}

func pubLimited(wait time.Duration) *apierr.Error {
	secs := max(1, int(math.Ceil(wait.Seconds())))
	return apierr.New(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("Too many requests from this address. Try again in %d seconds.", secs)).With("retry_after", secs)
}

// AddrLimiter is the same per-address sliding window for a public handler outside the API: the URL honey token, /t/<id> (D-507),
// which writes a hit per request and so must not be a way to make the box write or alert without end. Loopback is not counted.
type AddrLimiter struct{ l *pubLimiter }

// NewAddrLimiter allows perMinute requests per client address (IPv6 per /64) and minute; now is the clock (nil: time.Now).
func NewAddrLimiter(perMinute int, now func() time.Time) *AddrLimiter {
	return &AddrLimiter{l: newPubLimiter(perMinute, now)}
}

// Allow counts one request of r's peer and reports whether it is within the limit.
func (a *AddrLimiter) Allow(r *http.Request) bool {
	ok, _ := a.l.allow(r)
	return ok
}
