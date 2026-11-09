// Package servertest starts a real host server on a temporary unix socket with an injected fake
// peer check, for tests of host/server, host/client and the host contract. It is test support:
// the binary never imports it (a contract test asserts that).
package servertest

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
)

// FakePeer is a peer.Checker whose answer tests set.
type FakePeer struct {
	mu    sync.Mutex
	info  peer.Info
	err   error
	calls atomic.Int64
}

// Check implements peer.Checker.
func (f *FakePeer) Check(net.Conn) (peer.Info, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.err
}

// Allow makes later connections pass as info.
func (f *FakePeer) Allow(info peer.Info) {
	f.mu.Lock()
	f.info, f.err = info, nil
	f.mu.Unlock()
}

// Deny makes later connections fail with err (info is what the check "read" before failing).
func (f *FakePeer) Deny(info peer.Info, err error) {
	f.mu.Lock()
	f.info, f.err = info, err
	f.mu.Unlock()
}

// Calls is how many connections were checked.
func (f *FakePeer) Calls() int { return int(f.calls.Load()) }

// Clock is a settable clock for the server's rate limits and timestamps.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now implements the Options.Now function.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Harness is a running server and a client for it.
type Harness struct {
	Server    *server.Server
	Client    *client.Client
	Peer      *FakePeer
	Clock     *Clock
	Socket    string
	StateDir  string
	AuditPath string
	Dir       string
	Options   server.Options
	// Exited receives the code when the server decides to exit the process (a wedged command).
	Exited   chan int
	serveErr chan error
}

// CoreInfo is the peer the harness allows by default.
var CoreInfo = peer.Info{UID: 10001, PID: 4242, Unit: "vedette-core.service"}

// Start builds the server with the commands, listens on a short temp path (macOS limits unix
// socket paths to about 100 bytes, so t.TempDir() is too long), and serves until test cleanup.
// mutate may adjust the Options before the server is created.
func Start(t testing.TB, cmds []server.Command, mutate ...func(*server.Options)) *Harness {
	t.Helper()
	h := Prepare(t, cmds, mutate...)
	h.Serve(t)
	return h
}

// Prepare creates the server but does not listen yet (for tests of start-up).
func Prepare(t testing.TB, cmds []server.Command, mutate ...func(*server.Options)) *Harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	reg, err := server.NewRegistry(cmds...)
	if err != nil {
		t.Fatal(err)
	}
	h := &Harness{
		Peer:  &FakePeer{},
		Clock: &Clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)},
		Dir:   dir, Socket: filepath.Join(dir, "run", "h.sock"),
		StateDir: filepath.Join(dir, "state"), AuditPath: filepath.Join(dir, "log", "audit.jsonl"),
		Exited: make(chan int, 4),
	}
	h.Peer.Allow(CoreInfo)
	osrel := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osrel, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.Options = server.Options{
		SocketPath: h.Socket, SocketGID: os.Getgid(), StateDir: h.StateDir, AuditPath: h.AuditPath,
		Registry: reg, PeerCheck: h.Peer.Check, Version: "test", Now: h.Clock.Now, OSReleasePath: osrel,
		Logger: slog.New(slog.DiscardHandler), KillGrace: 100 * time.Millisecond,
		// Tests poll and stream; the limits of spec section 10 are tested by setting these to 0 (= defaults).
		RequestsPerMinute: 100_000, WritesPerMinute: 100_000,
		OwnerUID: os.Getuid(), Exit: func(code int) { h.Exited <- code },
	}
	for _, m := range mutate {
		m(&h.Options)
	}
	h.Socket, h.StateDir, h.AuditPath = h.Options.SocketPath, h.Options.StateDir, h.Options.AuditPath
	h.Server, err = server.New(h.Options)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Serve listens and serves in the background; cleanup shuts down.
func (h *Harness) Serve(t testing.TB) {
	t.Helper()
	ln, err := h.Server.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.serveErr = make(chan error, 1)
	go func() { h.serveErr <- h.Server.Serve(ln) }()
	h.Client = client.New(h.Socket)
	t.Cleanup(func() {
		h.Client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Server.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		if err := <-h.serveErr; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
}

// NewClient returns a client with its own connection pool (a fresh connection is peer-checked again).
func (h *Harness) NewClient(t testing.TB) *client.Client {
	t.Helper()
	c := client.New(h.Socket)
	t.Cleanup(c.Close)
	return c
}
