package logs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/logs/listen"
)

// Network helpers with a context, as the linter wants (loopback only).
func dialCtx(network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func listenPacket(network, addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, addr)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// syslogEnv is an env whose listener binds loopback on free ports and batches quickly.
func syslogEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.svc.cfg.Syslog = SyslogConfig{Host: "127.0.0.1", Ports: []int{0}, Limits: listen.Limits{BatchWait: 10 * time.Millisecond}}
	return e
}

// runSyslogJob runs the listener the way core/jobs does and returns stop, which waits for it to end.
func (e *env) runSyslogJob() (stop func() error) {
	ctx, cancel := context.WithCancel(e.t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	return func() error { cancel(); return <-done }
}

func (e *env) addrs() (udp, tcp net.Addr) {
	srv := e.svc.listening.Load()
	if srv == nil {
		return nil, nil
	}
	return srv.Addrs()
}

func (e *env) sourceOn(name, proto string) Source {
	e.t.Helper()
	s, err := e.svc.AddSource(e.t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: name, SenderIP: "127.0.0.1", Proto: proto, Port: 514})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) searchLines() []string {
	v, err := e.svc.Events(e.t.Context(), EventQuery{Window: "24h"})
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, ev := range v.Events {
		out = append(out, ev.Line)
	}
	return out
}

func TestUDPSyslogIsStoredAndSearchable(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	src := e.sourceOn("FW-HQ", "udp")
	stop := e.runSyslogJob()
	var udp net.Addr
	waitUntil(t, "the UDP socket", func() bool { udp, _ = e.addrs(); return udp != nil })
	c, err := dialCtx("udp4", udp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "<189>date=2026-11-09 devname=fg-hq logid=0000000013 srcip=10.1.1.5\x00 ESC\x1b[31m"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the line to be stored", func() bool { return len(e.searchLines()) == 1 })
	if got := e.searchLines()[0]; got != "<189>date=2026-11-09 devname=fg-hq logid=0000000013 srcip=10.1.1.5  ESC [31m" {
		t.Errorf("stored %q (the control characters must be cleaned by Ingest)", got)
	}
	v, _ := e.svc.Events(t.Context(), EventQuery{Window: "24h", Q: "logid=0000000013", Source: src.ID})
	if v.Total != 1 || v.Events[0].SourceName != "FW-HQ" {
		t.Errorf("search %+v", v)
	}
	if view, err := e.svc.Sources(t.Context()); err != nil || view.Sources[0].State != "receiving" {
		t.Errorf("state %+v %v", view.Sources, err)
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("job ended with %v", err)
	}
}

func TestTCPSyslogBothFramingsAreStored(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.sourceOn("FW-HQ", "tcp")
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var tcp net.Addr
	waitUntil(t, "the TCP socket", func() bool { _, tcp = e.addrs(); return tcp != nil })
	c, err := dialCtx("tcp4", tcp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "<34>one\n10 <34>two ab<34>three\n"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "three lines", func() bool { return len(e.searchLines()) == 3 })
}

func TestASenderThatIsNotDeclaredStoresNothing(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "Other", SenderIP: "10.9.9.9", Proto: "udp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var udp net.Addr
	waitUntil(t, "the UDP socket", func() bool { udp, _ = e.addrs(); return udp != nil })
	c, _ := dialCtx("udp4", udp.String())
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "<34>from 127.0.0.1, which nobody declared")
	waitUntil(t, "the datagram to be counted", func() bool { return e.svc.ListenStatus().Stats.Unknown == 1 })
	if n := len(e.searchLines()); n != 0 {
		t.Errorf("%d lines stored for an undeclared sender", n)
	}
}

func TestListenersOpenAndCloseWithTheSources(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the listener to be up", func() bool { return e.svc.listening.Load() != nil })
	if u, tc := e.addrs(); u != nil || tc != nil {
		t.Fatalf("no sources, yet sockets are open: %v %v", u, tc)
	}
	if st := e.svc.ListenStatus(); !st.Listening || st.UDP || st.TCP {
		t.Fatalf("status %+v", st)
	}
	s := e.sourceOn("FW", "udp") // POST-1: adding a source opens the socket
	waitUntil(t, "the UDP socket after the source was added", func() bool { u, _ := e.addrs(); return u != nil })
	if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", s.ID, Input{Kind: "fortigate", Name: "FW", SenderIP: "127.0.0.1", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "tcp instead of udp after the edit", func() bool { u, tc := e.addrs(); return u == nil && tc != nil })
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", s.ID); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "no socket after the last source was deleted", func() bool { u, tc := e.addrs(); return u == nil && tc == nil })
}

// A row with proto tls can only be left over (the API refuses it, D-203): it gets no socket and does not hurt the others.
func TestALeftOverTLSRowGetsNoSocketFromThisListener(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old', 'fortigate', 'FW-TLS', '127.0.0.1', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the listener to be up", func() bool { return e.svc.listening.Load() != nil })
	if u, tc := e.addrs(); u != nil || tc != nil {
		t.Fatalf("a TLS row opened a plain socket: %v %v", u, tc)
	}
}

// toggleGate is a core/jobs gate that the test switches.
type toggleGate struct {
	mu    sync.Mutex
	on    bool
	calls atomic.Int32 // how often the scheduler has asked: proof that it has looked at the gate
}

func (g *toggleGate) Enabled(string) bool {
	g.calls.Add(1)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.on
}
func (g *toggleGate) set(v bool) { g.mu.Lock(); defer g.mu.Unlock(); g.on = v }

// SYS-5: with the module off nothing listens; turning it on opens the sockets of the declared sources; turning it off closes them.
func TestNoSocketWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.sourceOn("FW", "tcp")
	gate := &toggleGate{}
	sched := jobs.New(slog.New(slog.DiscardHandler), gate, nil)
	for _, j := range Jobs(e.svc) {
		if j.Name == "syslog" {
			if j.Housekeeping {
				t.Fatal("the listener job is housekeeping: it would run with the module off")
			}
			if err := sched.Add(j); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	defer func() { cancel(); err := <-done; _ = err }()

	waitUntil(t, "the scheduler to have asked the gate", func() bool { return gate.calls.Load() > 0 })
	if e.svc.listening.Load() != nil { // it has looked at the gate, which is off: nothing may have started
		t.Fatal("the listener runs while the module is off")
	}
	gate.set(true)
	sched.ModuleChanged(ModuleID, true)
	var tcp net.Addr
	waitUntil(t, "the socket after the module was turned on", func() bool { _, tcp = e.addrs(); return tcp != nil })
	addr := tcp.String()
	c, err := dialCtx("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitUntil(t, "the connection to be registered", func() bool { return e.svc.ListenStatus().Conns == 1 })

	gate.set(false)
	sched.ModuleChanged(ModuleID, false)
	waitUntil(t, "the listener to stop", func() bool { return e.svc.listening.Load() == nil })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isNetTimeout(err) { // the open connection is cut, not left to idle out
		t.Errorf("the open connection survived the module being turned off: %v", err)
	}
	if conn, err := dialCtx("tcp4", addr); err == nil {
		_ = conn.Close()
		t.Error("the port still accepts connections after the module was turned off")
	}
}

func TestTheListenerJobIsNotTheHousekeepingOne(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var names []string
	for _, j := range Jobs(e.svc) {
		names = append(names, j.Name)
		if j.Name == "syslog" && (j.Housekeeping || j.Module != ModuleID || j.Every != SyslogRetry) {
			t.Errorf("syslog job %+v", j)
		}
		if j.Name == "purge" && !j.Housekeeping {
			t.Error("the purge job must stay housekeeping")
		}
		if j.Name == "siem" && j.Housekeeping { // it sends data out: never while the module is off (SYS-5, FORBID-3)
			t.Error("the siem job must not be housekeeping")
		}
	}
	if len(names) != 4 { // purge, syslog, anomaly (L3), siem (L5)
		t.Errorf("jobs %v", names)
	}
}

// Review finding 2, at the job: the TCP port is busy, so TCP is down and says why; UDP keeps working, the job does not end, and
// when the port is free the retry opens it without anybody touching the sources.
func TestABusyTCPPortDoesNotStopUDPAndIsRetried(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	hold, err := listenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := hold.LocalAddr().(*net.UDPAddr).Port
	_ = hold.Close()
	var lc net.ListenConfig
	busy, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("the port is taken: %v", err)
	}
	defer func() { _ = busy.Close() }()
	e.svc.cfg.Syslog.Ports = []int{port}
	e.svc.cfg.Syslog.RetryEvery = 20 * time.Millisecond
	e.sourceOn("FW", "udp")
	if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "FW2", SenderIP: "10.9.9.9", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	defer func() { cancel(); err := <-done; _ = err }()
	waitUntil(t, "UDP up and TCP reported down", func() bool { st := e.svc.ListenStatus(); return st.UDP && !st.TCP && st.TCPErr != "" })
	select {
	case err := <-done:
		t.Fatalf("the job ended with %v", err)
	default:
	}
	_ = busy.Close()
	waitUntil(t, "the retry to open TCP", func() bool { st := e.svc.ListenStatus(); return st.UDP && st.TCP && st.TCPErr == "" })
}

// Review finding 2, the other case: a failing read of the sources keeps the sockets that are open and is retried.
func TestAFailingReadOfTheSourcesKeepsTheSocketsAndIsRetried(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.svc.cfg.Syslog.RetryEvery = 20 * time.Millisecond
	e.sourceOn("FW", "udp")
	var fail atomic.Bool
	var reads atomic.Int32
	e.svc.loadForListener = func(ctx context.Context) ([]sourceRow, error) {
		reads.Add(1)
		if fail.Load() {
			return nil, errors.New("database is locked")
		}
		return e.svc.loadSources(ctx)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	defer func() { cancel(); err := <-done; _ = err }()
	waitUntil(t, "UDP", func() bool { return e.svc.ListenStatus().UDP })
	fail.Store(true)
	base := reads.Load()
	if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "FW2", SenderIP: "10.9.9.9", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "three failed reads", func() bool { return reads.Load() >= base+3 }) // the wake-up and two timed retries
	if st := e.svc.ListenStatus(); !st.Listening || !st.UDP || st.TCP {
		t.Fatalf("a failing read touched the sockets: %+v", st)
	}
	fail.Store(false)
	waitUntil(t, "the retry to pick up the new source", func() bool { st := e.svc.ListenStatus(); return st.UDP && st.TCP })
}

func TestTheListenerBatchIsNeverLargerThanWhatIngestTakes(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.svc.cfg.Syslog.Limits.BatchLines = 5000
	e.sourceOn("FW", "tcp")
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var tcp net.Addr
	waitUntil(t, "the TCP socket", func() bool { _, tcp = e.addrs(); return tcp != nil })
	c, err := dialCtx("tcp4", tcp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var b strings.Builder
	for i := range 1200 {
		fmt.Fprintf(&b, "<34>l%d\n", i)
	}
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "all lines stored (a batch over MaxBatch would be refused whole)", func() bool {
		v, _ := e.svc.Events(t.Context(), EventQuery{Window: "24h"})
		return v.Total == 1200
	})
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// logCapture keeps the messages of a logger.
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, r.Message)
	return nil
}
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }
func (c *logCapture) count(sub string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// Review (round 2) 3: the same warning is not repeated by every retry.
func TestTheSameWarningIsNotLoggedByEveryRetry(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	logs := &logCapture{}
	e.svc.cfg.Log = slog.New(logs)
	e.svc.cfg.Syslog.RetryEvery = 5 * time.Millisecond
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old', 'fortigate', 'FW-TLS', '10.8.8.8', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	var reads atomic.Int32
	var fail atomic.Bool
	e.svc.loadForListener = func(ctx context.Context) ([]sourceRow, error) {
		reads.Add(1)
		if fail.Load() {
			return nil, errors.New("database is locked")
		}
		return e.svc.loadSources(ctx)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	defer func() { cancel(); err := <-done; _ = err }()
	waitUntil(t, "the listener to be up", func() bool { return e.svc.listening.Load() != nil && reads.Load() >= 2 })
	for range 5 { // five more applies with the same tls row
		base := reads.Load() // read before the wake-up: an apply that finishes first must still count
		e.svc.sourcesChanged()
		waitUntil(t, "an apply", func() bool { return reads.Load() > base })
	}
	if n := logs.count("TLS"); n != 1 {
		t.Errorf("the TLS warning was logged %d times for one unchanged row", n)
	}
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old2', 'fortigate', 'FW-TLS2', '10.8.8.9', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	e.svc.sourcesChanged()
	waitUntil(t, "the warning for the changed count", func() bool { return logs.count("TLS") == 2 })

	fail.Store(true)
	base := reads.Load()
	e.svc.sourcesChanged()
	waitUntil(t, "five failed reads", func() bool { return reads.Load() >= base+5 })
	if n := logs.count("could not read the sources"); n != 1 {
		t.Errorf("the failed read was logged %d times for one error", n)
	}
	fail.Store(false)
	reads.Store(0)
	waitUntil(t, "recovery", func() bool { return reads.Load() >= 1 })
	fail.Store(true) // a new failure after a recovery is news again
	base = reads.Load()
	e.svc.sourcesChanged()
	waitUntil(t, "a failed read", func() bool { return reads.Load() > base })
	waitUntil(t, "the second warning", func() bool { return logs.count("could not read the sources") == 2 })
}

// tlsEnv is a syslogEnv whose box has a TLS configuration with a self-made certificate (made at run time, never committed).
func tlsEnv(t *testing.T) (*env, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "box"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	e := syslogEnv(t)
	e.svc.cfg.Syslog.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }}
	return e, pool
}

func (e *env) tlsAddr() net.Addr {
	srv := e.svc.listening.Load()
	if srv == nil {
		return nil
	}
	return srv.TLSAddr()
}

func dialTLS(addr string, pool *x509.CertPool) (*tls.Conn, error) {
	d := tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(context.Background(), "tcp4", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

// POST-1 (D-214): on a box with a certificate a TLS source is accepted, adding it opens the TLS socket and a line sent over TLS from the
// declared sender is stored; deleting the last TLS source closes the socket. Nothing plain opens for it.
func TestTLSSyslogIsStoredAndTheSocketFollowsTheSources(t *testing.T) {
	t.Parallel()
	e, pool := tlsEnv(t)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the listener to be up", func() bool { return e.svc.listening.Load() != nil })
	if a := e.tlsAddr(); a != nil {
		t.Fatalf("no sources, yet the TLS socket is open: %v", a)
	}
	src := e.sourceOn("FW-TLS", "tls")
	var addr net.Addr
	waitUntil(t, "the TLS socket", func() bool { addr = e.tlsAddr(); return addr != nil })
	if u, tc := e.addrs(); u != nil || tc != nil {
		t.Fatalf("a TLS source opened a plain socket: %v %v", u, tc)
	}
	if st := e.svc.ListenStatus(); !st.TLS || st.TLSErr != "" {
		t.Fatalf("status %+v", st)
	}
	c, err := dialTLS(addr.String(), pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "<34>one\n10 <34>two ab"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "two lines over TLS", func() bool { return len(e.searchLines()) == 2 })
	if view, err := e.svc.Sources(t.Context()); err != nil || view.Sources[0].State != "receiving" {
		t.Errorf("state %+v %v", view.Sources, err)
	}
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", src.ID); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the TLS socket to close with the last TLS source", func() bool { return e.tlsAddr() == nil })
}

// A TLS source is accepted on create and on edit when the box has a certificate, and a plain client from another address is dropped.
func TestTLSSourceFromAnotherSenderStoresNothing(t *testing.T) {
	t.Parallel()
	e, pool := tlsEnv(t)
	if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "Other", SenderIP: "10.9.9.9", Proto: "tls", Port: 6514}); err != nil {
		t.Fatal(err)
	}
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var addr net.Addr
	waitUntil(t, "the TLS socket", func() bool { addr = e.tlsAddr(); return addr != nil })
	if c, err := dialTLS(addr.String(), pool); err == nil { // 127.0.0.1 is not the declared sender
		_ = c.Close()
		t.Fatal("an undeclared sender completed a TLS handshake")
	}
	waitUntil(t, "the connection to be counted", func() bool { return e.svc.ListenStatus().Stats.Unknown == 1 })
	if n := len(e.searchLines()); n != 0 {
		t.Errorf("%d lines stored for an undeclared sender", n)
	}
}

// With no TLS configuration the API refuses proto tls and, if a row was left over, the listener opens nothing for it.
func TestWithoutATLSConfigTLSIsRefusedAndNothingListens(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t) // Syslog.TLS is nil
	_, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "FW-TLS", SenderIP: "127.0.0.1", Proto: "tls", Port: 6514})
	if code(err) != "tls_unavailable" {
		t.Fatalf("create: %v", err)
	}
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old', 'fortigate', 'FW-TLS', '127.0.0.1', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the listener to be up", func() bool { return e.svc.listening.Load() != nil })
	if a := e.tlsAddr(); a != nil {
		t.Fatalf("a TLS socket is open without a TLS config: %v", a)
	}
}

// SYS-5: with the module off the TLS socket is not open either; turning it on opens it, turning it off closes it and cuts the connection.
func TestNoTLSSocketWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	e, pool := tlsEnv(t)
	e.sourceOn("FW", "tls")
	gate := &toggleGate{}
	sched := jobs.New(slog.New(slog.DiscardHandler), gate, nil)
	for _, j := range Jobs(e.svc) {
		if j.Name == "syslog" {
			if err := sched.Add(j); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "the scheduler to have asked the gate", func() bool { return gate.calls.Load() > 0 })
	if e.svc.listening.Load() != nil {
		t.Fatal("the listener runs while the module is off")
	}
	gate.set(true)
	sched.ModuleChanged(ModuleID, true)
	var addr net.Addr
	waitUntil(t, "the TLS socket after the module was turned on", func() bool { addr = e.tlsAddr(); return addr != nil })
	c, err := dialTLS(addr.String(), pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitUntil(t, "the connection to be registered", func() bool { return e.svc.ListenStatus().Conns == 1 })
	gate.set(false)
	sched.ModuleChanged(ModuleID, false)
	waitUntil(t, "the listener to stop", func() bool { return e.svc.listening.Load() == nil })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isNetTimeout(err) {
		t.Errorf("the open TLS connection survived the module being turned off: %v", err)
	}
	if conn, err := dialCtx("tcp4", addr.String()); err == nil {
		_ = conn.Close()
		t.Error("the TLS port still accepts connections after the module was turned off")
	}
}

// Editing a source to TLS is accepted on a box that has a TLS config, and opens the TLS socket in place of the plain one.
func TestEditingASourceToTLSIsAcceptedOnABoxWithTLS(t *testing.T) {
	t.Parallel()
	e, _ := tlsEnv(t)
	s := e.sourceOn("FW", "udp")
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the UDP socket", func() bool { u, _ := e.addrs(); return u != nil })
	got, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", s.ID, Input{Kind: "fortigate", Name: "FW", SenderIP: "127.0.0.1", Proto: "tls", Port: 6514})
	if err != nil || got.Proto != "tls" {
		t.Fatalf("edit to tls: %+v %v", got, err)
	}
	waitUntil(t, "the TLS socket instead of the UDP one", func() bool { u, _ := e.addrs(); return u == nil && e.tlsAddr() != nil })
}

// A left-over tls row on a box that now has a TLS config is served, and the "not served" warning (for a box with none) is not logged.
func TestALeftOverTLSRowIsServedAndNotWarnedAboutOnABoxWithTLS(t *testing.T) {
	t.Parallel()
	e, _ := tlsEnv(t)
	logs := &logCapture{}
	e.svc.cfg.Log = slog.New(logs)
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old', 'fortigate', 'FW-TLS', '127.0.0.1', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the TLS socket for the old row", func() bool { return e.tlsAddr() != nil })
	if n := logs.count("are not served"); n != 0 {
		t.Errorf("the not-served warning was logged %d times on a box that serves TLS", n)
	}
}
