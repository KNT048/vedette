package logs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
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

// D-443: the sockets are open while the listener runs, with or without sources, so a sender that is not declared yet is named by
// UnknownSenders (walk 4: lines sent before any source left no trace). D-444: a UDP source takes TCP from its address too, a TCP
// source no UDP, so the datagram of a TCP source is listed again.
func TestSocketsAreOpenWithoutSourcesAndAnUndeclaredSenderIsNamed(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var udp, tcp net.Addr
	waitUntil(t, "both sockets with no source", func() bool { udp, tcp = e.addrs(); return udp != nil && tcp != nil })
	send := func(proto, text string) {
		t.Helper()
		a := udp
		if proto == "tcp4" {
			a = tcp
		}
		c, err := dialCtx(proto, a.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, text)
	}
	named := func(proto string) bool {
		v, err := e.svc.UnknownSenders(t.Context())
		return err == nil && len(v.Items) == 1 && v.Items[0].IP == "127.0.0.1" && v.Items[0].Proto == proto
	}
	send("udp4", "<34>before any source")
	waitUntil(t, "the sender to be named", func() bool { return named("udp") })
	s := e.sourceOn("FW", "udp")
	if v, err := e.svc.UnknownSenders(t.Context()); err != nil || len(v.Items) != 0 {
		t.Fatalf("a declared sender is still named: %+v %v", v, err)
	}
	// The listener learns of the source when its wake-up has run: send until it has.
	waitUntil(t, "the tcp line of the udp source", func() bool { send("tcp4", "<34>a udp source over tcp\n"); return len(e.searchLines()) > 0 })
	if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", s.ID, Input{Kind: "fortigate", Name: "FW", SenderIP: "127.0.0.1", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "a datagram of the tcp source to be named", func() bool { send("udp4", "<34>not over tcp"); return named("udp") })
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", s.ID); err != nil {
		t.Fatal(err)
	}
	if st := e.svc.ListenStatus(); !st.UDP || !st.TCP {
		t.Errorf("deleting the last source closed a socket: %+v", st.Status)
	}
	for _, l := range e.searchLines() {
		if !strings.Contains(l, "a udp source over tcp") {
			t.Errorf("stored %q, which its sender sent while it was not a source of that protocol", l)
		}
	}
}

// A row with proto tls can only be left over (the API refuses it, D-203): it gets no TLS socket and does not hurt the others.
func TestALeftOverTLSRowGetsNoSocketFromThisListener(t *testing.T) {
	t.Parallel()
	e := syslogEnv(t)
	e.exec(e.cfg, `INSERT INTO logs_sources (id, kind, name, sender_ip, proto, port, created_at) VALUES ('ls-old', 'fortigate', 'FW-TLS', '127.0.0.1', 'tls', 6514, '2026-11-01T00:00:00.000Z')`)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	waitUntil(t, "the plain sockets", func() bool { u, tc := e.addrs(); return u != nil && tc != nil })
	if a := e.tlsAddr(); a != nil {
		t.Fatalf("a TLS row opened a TLS socket on a box with no TLS configuration: %v", a)
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
	s := e.sourceOn("FW", "udp")
	var fail atomic.Bool
	var failed atomic.Int32
	e.svc.loadForListener = func(ctx context.Context) ([]sourceRow, error) {
		rows, err := e.svc.loadSources(ctx)
		// Failure is decided when the read returns, not when it starts: a read already in flight when the test sets fail (the wake-up
		// that sourceOn left pending, say) may have loaded the source added below, and must not open its socket. A read that returned
		// before fail was set finished before the source was added, so it cannot have seen it.
		if fail.Load() {
			failed.Add(1)
			return nil, errors.New("database is locked")
		}
		return rows, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	defer func() { cancel(); err := <-done; _ = err }()
	var udp net.Addr
	waitUntil(t, "UDP", func() bool { udp, _ = e.addrs(); return udp != nil })
	c, err := dialCtx("udp4", udp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	fail.Store(true)
	if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", s.ID, Input{Kind: "fortigate", Name: "FW", SenderIP: "127.0.0.1", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "three failed reads", func() bool { return failed.Load() >= 3 }) // the wake-up and two timed retries
	if st := e.svc.ListenStatus(); !st.Listening || !st.UDP || !st.TCP {
		t.Fatalf("a failing read touched the sockets: %+v", st)
	}
	_, _ = io.WriteString(c, "<34>the listener still has the last sources it read")
	waitUntil(t, "the datagram of the source as last read", func() bool { return len(e.searchLines()) == 1 })
	fail.Store(false)
	waitUntil(t, "the retry to pick up the edit (a TCP source takes no datagram)", func() bool {
		_, _ = io.WriteString(c, "<34>after the edit")
		return e.svc.ListenStatus().Stats.Unknown > 0
	})
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
	var reads, oks atomic.Int32 // oks counts the reads that succeeded: nothing reads again after a success, so a counter that is reset can lose the one that matters
	var fail atomic.Bool
	e.svc.loadForListener = func(ctx context.Context) ([]sourceRow, error) {
		reads.Add(1)
		if fail.Load() {
			return nil, errors.New("database is locked")
		}
		rows, err := e.svc.loadSources(ctx)
		if err == nil {
			oks.Add(1)
		}
		return rows, err
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
	okBase := oks.Load()
	fail.Store(false)
	waitUntil(t, "recovery", func() bool { return oks.Load() > okBase })
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

// POST-1 (D-214): on a box with a certificate a TLS source is accepted and a line sent over TLS from the
// declared sender is stored; the TLS socket is open with no source (D-443), and once the last TLS source is deleted its sender gets no handshake.
func TestTLSSyslogIsStoredAndTheSocketFollowsTheSources(t *testing.T) {
	t.Parallel()
	e, pool := tlsEnv(t)
	stop := e.runSyslogJob()
	defer func() { _ = stop() }()
	var addr net.Addr
	waitUntil(t, "the TLS socket with no source (D-443)", func() bool { addr = e.tlsAddr(); return addr != nil })
	src := e.sourceOn("FW-TLS", "tls")
	if st := e.svc.ListenStatus(); !st.TLS || st.TLSErr != "" {
		t.Fatalf("status %+v", st)
	}
	var c *tls.Conn
	waitUntil(t, "a handshake once the listener has the source", func() bool { // until its wake-up has run, the sender is not one
		var err error
		c, err = dialTLS(addr.String(), pool)
		return err == nil
	})
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
	waitUntil(t, "the deleted source's sender to get no handshake", func() bool {
		c2, err := dialTLS(addr.String(), pool)
		if err == nil {
			_ = c2.Close()
		}
		return err != nil
	})
	if e.tlsAddr() == nil {
		t.Error("the TLS socket closed with the last TLS source")
	}
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

// Editing a source to TLS is accepted on a box that has a TLS config; the TLS socket is open (D-443).
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
	waitUntil(t, "the TLS socket", func() bool { return e.tlsAddr() != nil })
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

// D-434: the Sources answer carries the certificate of the TLS port (fingerprint, subject, self-signed, PEM), and nothing on a box without TLS.
func TestSourcesShowTheBoxCertificateOfTheTLSPort(t *testing.T) {
	t.Parallel()
	e, _ := tlsEnv(t)
	view, err := e.svc.Sources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tc := view.Box.TLS
	if tc == nil {
		t.Fatal("no certificate in the box block of a box with TLS")
	}
	cert, _ := e.svc.cfg.Syslog.TLS.GetCertificate(nil)
	sum := sha256.Sum256(cert.Certificate[0])
	block, _ := pem.Decode([]byte(tc.PEM))
	if tc.Fingerprint != hex.EncodeToString(sum[:]) || tc.Kind != "self_signed" || tc.Port != 6514 || tc.Subject != "CN=box" || block == nil || !bytes.Equal(block.Bytes, cert.Certificate[0]) || tc.NotAfter.IsZero() {
		t.Errorf("certificate info %+v", tc)
	}
	plain := syslogEnv(t)
	if view, err := plain.svc.Sources(t.Context()); err != nil || view.Box.TLS != nil {
		t.Errorf("a box without TLS showed a certificate: %+v %v", view.Box.TLS, err)
	}
}

// D-435: a TLS source may pin a client certificate; the pin is validated, stored, shown, and handed to the listener; other protocols refuse it.
func TestTLSSourceClientCertificatePin(t *testing.T) {
	t.Parallel()
	e, _ := tlsEnv(t)
	pin := strings.Repeat("ab", 32)
	in := Input{Kind: "fortigate", Name: "FW-TLS", SenderIP: "10.9.9.9", Proto: "tls", Port: 6514, ClientCertSHA256: pin}
	for name, bad := range map[string]func(*Input){
		"on udp":      func(i *Input) { i.Proto, i.Port = "udp", 514 },
		"upper case":  func(i *Input) { i.ClientCertSHA256 = strings.ToUpper(pin) },
		"short":       func(i *Input) { i.ClientCertSHA256 = pin[:63] },
		"not hex":     func(i *Input) { i.ClientCertSHA256 = strings.Repeat("zz", 32) },
		"with colons": func(i *Input) { i.ClientCertSHA256 = "ab:" + pin[3:] },
	} {
		b := in
		bad(&b)
		if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", b); code(err) != "bad_client_cert" {
			t.Errorf("%s: %v", name, err)
		}
	}
	s, err := e.svc.AddSource(t.Context(), "admin@acme.example", in)
	if err != nil || s.ClientCert == nil || *s.ClientCert != pin {
		t.Fatalf("%+v %v", s, err)
	}
	m, _, err := e.svc.listenSources(t.Context())
	if err != nil || m[netip.MustParseAddr("10.9.9.9")].ClientCertSHA256 != pin {
		t.Fatalf("the listener was not given the pin: %+v %v", m, err)
	}
	in.ClientCertSHA256 = ""
	s, err = e.svc.UpdateSource(t.Context(), "admin@acme.example", s.ID, in)
	if err != nil || s.ClientCert != nil {
		t.Fatalf("the pin was not removed: %+v %v", s, err)
	}
}

// A leaf signed by a CA (the box's own CA on a default box, D-262/D-351): the card hands out the CA, not the leaf, names it as the box CA
// when the CA is the box's, and says "issued" (with the owner's chain) for another authority. A private key in the trust file is never kept.
func TestBoxCertificateCardNamesTheCAThatSignedTheLeaf(t *testing.T) {
	t.Parallel()
	mk := func(cn string, parent *x509.Certificate, pkey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true, IsCA: ca, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if ca {
			tpl.KeyUsage = x509.KeyUsageCertSign
		}
		signer, signKey := tpl, key
		if parent != nil {
			signer, signKey = parent, pkey
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key, der
	}
	for name, tc := range map[string]struct {
		caName, kind string
		anchorErr    bool
		wantCard     bool
	}{
		"the box CA":         {"Vedette box CA", "box_ca", false, true},
		"an owner's CA":      {"Acme Root", "issued", false, true},
		"the box CA is busy": {"Vedette box CA", "", true, false},
	} {
		e, _ := tlsEnv(t)
		ca, caKey, caDER := mk(tc.caName, nil, nil, true)
		_, leafKey, leafDER := mk("box", ca, caKey, false)
		leaf := &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
		e.svc.cfg.Syslog.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return leaf, nil }}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
		file := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
		e.svc.cfg.TrustAnchor = func() ([]byte, error) {
			if tc.anchorErr {
				return nil, errors.New("being renewed")
			}
			return file, nil
		}
		view, err := e.svc.Sources(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		got := view.Box.TLS
		if !tc.wantCard {
			if got != nil {
				t.Errorf("%s: a card was shown while the CA cannot be handed out: %+v", name, got)
			}
			continue
		}
		sum := sha256.Sum256(caDER)
		if got == nil || got.Kind != tc.kind || got.Subject != "CN="+tc.caName || got.Issuer != "CN="+tc.caName || got.Fingerprint != hex.EncodeToString(sum[:]) || strings.Contains(got.PEM, "PRIVATE") || strings.Count(got.PEM, "BEGIN CERTIFICATE") != 1 {
			t.Errorf("%s: %+v", name, got)
		}
	}
}
