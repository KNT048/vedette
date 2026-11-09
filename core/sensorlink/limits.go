package sensorlink

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the protocol (sensor-protocol.md section 9). They are starting points to measure again, not measurements.
const (
	ProtoHeader  = "X-Vedette-Proto"
	ProtoVersion = "1"
	PathPrefix   = "/sensor/v1"

	MaxObservationsBody = 1 << 20
	MaxHeartbeatBody    = 64 << 10
	MaxResultBody       = 11 << 20
	MaxResultXML        = 8 << 20
	MaxItems            = 500

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

	RatePerSecond = 10
	RateBurst     = 20

	ReadHeaderTimeout = 5 * time.Second
	WriteTimeout      = 35 * time.Second
	// BodyTimeout bounds reading one request body (a slow body is as much a slowloris as slow headers, and net/http has no
	// body timeout that spares a long poll). IdleTimeout closes keep-alive connections nobody uses.
	BodyTimeout = 10 * time.Second
	IdleTimeout = 2 * time.Minute

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
