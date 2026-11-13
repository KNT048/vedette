package sensorlink

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the protocol (sensor-protocol.md section 9). They are starting points to measure again, not measurements.
const (
	ProtoHeader  = "X-Vedette-Proto"
	ProtoVersion = "4" // 4: capture_error in the passive heartbeat (D-399); 3: host_errors on a nuclei result (D-165); 2: nuclei jobs (D-133)
	// ProtoPrevious is the one older protocol core still takes (D-459): a sensor or scan worker one protocol behind core, while
	// an update runs (core switches first) and after a sensor's switch that went back by itself. Never a newer one, never two
	// behind. A bump sets it to the old ProtoVersion (TestProtoPreviousIsOneBelow) and must keep core able to serve that peer:
	// what the new protocol adds to a request is optional (absent = the old meaning). A bump that changes a reply core sends
	// must first add what does not exist yet: the request's protocol passed to the handler and the old shape sent to a
	// ProtoPrevious peer, with a test. 4 over 3 only added capture_error to a request, so nothing differs in core's replies.
	ProtoPrevious = "3"
	PathPrefix    = "/sensor/v1"

	MaxObservationsBody = 1 << 20
	MaxHeartbeatBody    = 64 << 10
	MaxResultBody       = 11 << 20
	MaxResultXML        = 8 << 20
	MaxResultJSONL      = 4 << 20 // the cap of a nuclei run's stdout (nucleiargv.MaxOutput; a test in sensoractive checks they agree)
	MaxHostErrors       = 16      // entries of host_errors on a nuclei result: one per target (nucleiargv.MaxTargets; a test in the worker checks they agree)
	MaxItems            = 500
	MaxRunning          = 2 // jobs a worker runs at once: one nmap and one nuclei (D-125 (3))

	// What a sensor reads back from core.
	MaxConfigReply = 64 << 10
	MaxJobsReply   = 64 << 10
	MaxOtherReply  = 16 << 10

	MaxWait     = 30 * time.Second
	DefaultWait = 25 * time.Second

	// MaxBodiesPerRole is how many request bodies core holds in memory at once for one role, MaxResultBodies how many of them
	// may be a job result (up to 11 MiB; a worker runs one job at a time). A request that cannot get a slot is 503 store_busy
	// with Retry-After: 1, before its body is read. MaxConns caps the connections of the whole listener: the pending pool plus
	// the two role shares.
	MaxBodiesPerRole = 2
	MaxResultBodies  = 1
	MaxConns         = MaxPending + MaxConnsPassive + MaxConnsActive
	// MaxPending, MinPendingAge and HandshakeDeadline are the pool of connections that have not finished their TLS handshake
	// (PendingListener, D-326).
	MaxPending        = 16
	MinPendingAge     = 250 * time.Millisecond
	HandshakeDeadline = 3 * time.Second
	// MaxConnsPassive and MaxConnsActive are the shares of the roles (D-176 (4)): a connection is charged to its role at the TLS
	// handshake (the verified certificate tells which), and a handshake over the share fails, so a passive sensor can never hold the
	// slots the scan worker needs (the worker keeps one long poll, one or two result uploads and a heartbeat: well under 16).
	MaxConnsPassive = 32
	MaxConnsActive  = 16

	RatePerSecond = 10
	RateBurst     = 20

	ReadHeaderTimeout = 5 * time.Second
	WriteTimeout      = 35 * time.Second
	// BodyTimeout bounds reading one request body (a slow body is as much a slowloris as slow headers). The largest upload is
	// MaxResultBody (11 MiB), so the whole request (headers plus body) is at most ReadHeaderTimeout + BodyTimeout, which is
	// http.Server.ReadTimeout (D-176 (3)); a long poll lifts that deadline for itself (serve). IdleTimeout closes keep-alive
	// connections nobody uses.
	BodyTimeout = 10 * time.Second
	IdleTimeout = 2 * time.Minute
	// DrainGrace is how long a connection whose request was refused without reading its body may keep sending that body.
	DrainGrace = time.Second

	// Backoff of a sensor retrying (D-112 (4)).
	BackoffStart = time.Second
	BackoffCap   = 60 * time.Second
)

// bucket is a token bucket: RatePerSecond tokens a second up to RateBurst, one per request.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// take spends one token. When there is none it returns how long until there is one.
func (b *bucket) take(now time.Time) (ok bool, retry time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = RateBurst
	} else if d := now.Sub(b.last); d > 0 {
		b.tokens = min(RateBurst, b.tokens+d.Seconds()*RatePerSecond)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / RatePerSecond * float64(time.Second))
}

// gate lets one long poll through at a time.
type gate struct{ busy atomic.Bool }

func (g *gate) enter() bool { return g.busy.CompareAndSwap(false, true) }
func (g *gate) leave()      { g.busy.Store(false) }

// PendingListener returns the listener of the sensor link (D-326). A connection that has not finished its TLS handshake is unauthenticated:
// any local process can open one. Those connections get a pool of their own, MaxPending, separate from the shares of the roles that a
// connection is charged to at the handshake (MaxConnsPassive, MaxConnsActive), so the whole listener holds at most MaxConns. When the
// pending pool is full, a new connection takes the place of the oldest pending one if that one has waited at least MinPendingAge (a
// handshake on loopback takes milliseconds, so a sensor's connection is never the one evicted unless it hangs); otherwise the new one is
// closed at once (the sensor retries with its back-off). Every pending connection is closed after HandshakeDeadline whatever net/http does.
// What this stops: a process that opens connections and holds them (before, 64 idle connections held every slot until net/http's own
// handshake timeout, D-176 (5)). What it does not stop: a process that keeps opening connections without pause; it wins most places as
// they free up, so a sensor gets in only now and then. That needs a listener per role that other processes cannot reach (deferred).
func PendingListener(l net.Listener) net.Listener {
	return newPendingListener(l, MaxPending, MinPendingAge, HandshakeDeadline, time.Now)
}

func newPendingListener(l net.Listener, limit int, minAge, deadline time.Duration, now func() time.Time) *pendingListener {
	return &pendingListener{Listener: l, max: limit, minAge: minAge, deadline: deadline, now: now}
}

type pendingListener struct {
	net.Listener
	max      int
	minAge   time.Duration
	deadline time.Duration
	now      func() time.Time

	mu      sync.Mutex
	pending []*limitConn // oldest first
}

func (l *pendingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		lc := &limitConn{Conn: c, l: l, at: l.now()}
		l.mu.Lock()
		var evict *limitConn
		if len(l.pending) >= l.max {
			if oldest := l.pending[0]; lc.at.Sub(oldest.at) >= l.minAge {
				evict, l.pending = oldest, l.pending[1:]
				oldest.pending = false
			} else {
				l.mu.Unlock()
				_ = c.Close() // the pool is full of connections still young enough to be a sensor's: this one waits for its retry
				continue
			}
		}
		lc.pending = true
		l.pending = append(l.pending, lc)
		l.mu.Unlock()
		if evict != nil {
			_ = evict.Close()
		}
		lc.mu.Lock()
		lc.timer = time.AfterFunc(l.deadline, func() {
			if l.drop(lc) {
				_ = lc.Close()
			}
		})
		lc.mu.Unlock()
		return lc, nil
	}
}

// drop takes c out of the pending pool; false when it was not there (already promoted, evicted or closed).
func (l *pendingListener) drop(c *limitConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !c.pending {
		return false
	}
	c.pending = false
	for i, p := range l.pending {
		if p == c {
			l.pending = append(l.pending[:i], l.pending[i+1:]...)
			break
		}
	}
	return true
}

type limitConn struct {
	net.Conn
	l       *pendingListener
	at      time.Time // when it was accepted
	pending bool      // in l.pending; guarded by l.mu

	mu     sync.Mutex
	timer  *time.Timer // the handshake deadline; guarded by mu (its callback may run before Accept has stored it)
	closed bool
	extra  []func() // run once when the connection closes: the role charge
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.l.drop(c)
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.closed = true
	extra := c.extra
	c.extra = nil
	c.mu.Unlock()
	for _, f := range extra {
		f()
	}
	return err
}

// promote takes c out of the pending pool at the end of a good handshake; false when it is no longer there (evicted or past its deadline):
// the handshake then fails.
func (c *limitConn) promote() bool {
	if !c.l.drop(c) {
		return false
	}
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return true
}

// onClose runs f when the connection closes; false when it already has (f is not kept).
func (c *limitConn) onClose(f func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.extra = append(c.extra, f)
	return true
}

// connCap is the share of MaxConns a role may hold (0 for anything else: not tracked).
func connCap(r Role) int {
	switch r {
	case Passive:
		return MaxConnsPassive
	case Active:
		return MaxConnsActive
	}
	return 0
}

// roleTracker counts the connections each role holds. A connection is charged to its role at the TLS handshake (the verified
// client certificate says which role it is), which also takes it out of the pending pool, and the charge is given back when the
// connection closes. A connection that is not one of PendingListener's (a test server) is not charged.
type roleTracker struct {
	mu sync.Mutex
	n  map[Role]int
}

func newRoleTracker() *roleTracker { return &roleTracker{n: map[Role]int{}} }

// charge takes one connection of role's share for c; an error (the handshake fails) when the role is at its share.
func (t *roleTracker) charge(c net.Conn, r Role) error {
	lc, ok := c.(*limitConn)
	if !ok {
		return nil
	}
	if !lc.promote() {
		return fmt.Errorf("sensorlink: the handshake took longer than its place in the pending pool")
	}
	t.mu.Lock()
	if t.n[r] >= connCap(r) {
		t.mu.Unlock()
		return fmt.Errorf("sensorlink: %s connections are at their share of %d", r, connCap(r))
	}
	t.n[r]++
	t.mu.Unlock()
	if !lc.onClose(func() { t.mu.Lock(); t.n[r]--; t.mu.Unlock() }) {
		t.mu.Lock()
		t.n[r]--
		t.mu.Unlock()
		return net.ErrClosed
	}
	return nil
}
