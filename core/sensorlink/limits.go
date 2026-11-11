package sensorlink

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the protocol (sensor-protocol.md section 9). They are starting points to measure again, not measurements.
const (
	ProtoHeader  = "X-Vedette-Proto"
	ProtoVersion = "2"
	PathPrefix   = "/sensor/v1"

	MaxObservationsBody = 1 << 20
	MaxHeartbeatBody    = 64 << 10
	MaxResultBody       = 11 << 20
	MaxResultXML        = 8 << 20
	MaxResultJSONL      = 4 << 20 // the cap of a nuclei run's stdout (nucleiargv.MaxOutput; a test in sensoractive checks they agree)
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
	// with Retry-After: 1, before its body is read. MaxConns caps the connections of the whole listener.
	MaxBodiesPerRole = 2
	MaxResultBodies  = 1
	MaxConns         = 64
	// MaxConnsPassive and MaxConnsActive split MaxConns by role (D-176 (4)): a role counts its connections once the TLS handshake
	// has told which role it is, and a connection over its share is closed. 32 + 16 leaves 16 of the 64 for connections that are
	// still in their handshake or are not a sensor, so a passive sensor can never hold the slots the scan worker needs (the
	// worker keeps one long poll, one or two result uploads and a heartbeat: well under 16).
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

// LimitListener returns a listener that accepts at most n connections at a time: Accept waits until a connection that was
// accepted has been closed. A small stdlib version of the usual limit listener, so that no dependency is added.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
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

// roleTracker counts the connections of each role. net/http calls ConnState for the connection, which at StateActive has done
// its handshake, so the verified client certificate says which role it is.
type roleTracker struct {
	mu   sync.Mutex
	role map[net.Conn]Role
	n    map[Role]int
}

func newRoleTracker() *roleTracker {
	return &roleTracker{role: map[net.Conn]Role{}, n: map[Role]int{}}
}

// connState is http.Server.ConnState: a connection of a role that is at its share is closed before its request is handled.
func (t *roleTracker) connState(c net.Conn, st http.ConnState) {
	t.mu.Lock()
	switch st {
	case http.StateActive:
		if _, seen := t.role[c]; seen {
			break
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			break
		}
		certs := tc.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			break
		}
		r, err := ClientRole(certs[0])
		if err != nil {
			break // callerRole refuses it per request
		}
		if t.n[r] >= connCap(r) {
			t.mu.Unlock()
			_ = c.Close()
			return
		}
		t.role[c] = r
		t.n[r]++
	case http.StateClosed, http.StateHijacked:
		if r, ok := t.role[c]; ok {
			delete(t.role, c)
			t.n[r]--
		}
	}
	t.mu.Unlock()
}
