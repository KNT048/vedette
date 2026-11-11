package logs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	mu sync.Mutex
	on bool
}

func (g *toggleGate) Enabled(string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on }
func (g *toggleGate) set(v bool)          { g.mu.Lock(); defer g.mu.Unlock(); g.on = v }

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
	defer func() { cancel(); <-done }()

	if e.svc.listening.Load() != nil { // the scheduler is running and the gate is off: nothing may have started
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
	waitUntil(t, "the connection to be registered", func() bool { return e.svc.ListenStatus().Stats.Unknown == 0 && e.svc.listening.Load() != nil })

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
	}
	if len(names) != 2 {
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
	defer func() { cancel(); <-done }()
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
	e.svc.loadForListener = func(ctx context.Context) ([]sourceRow, error) {
		if fail.Load() {
			return nil, errors.New("database is locked")
		}
		return e.svc.loadSources(ctx)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.svc.runSyslog(ctx) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "UDP", func() bool { return e.svc.ListenStatus().UDP })
	fail.Store(true)
	if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: "FW2", SenderIP: "10.9.9.9", Proto: "tcp", Port: 514}); err != nil {
		t.Fatal(err)
	}
	<-time.After(150 * time.Millisecond) // several retries fail
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
