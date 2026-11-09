// Package server is the vedette-host socket server: a unix-socket HTTP/1.1 JSON API with a closed
// command table, durable runs, one global write lock, a hash-chained audit log and per-connection
// peer authentication (docs/specs/host-api.md). It is the framework of WP-07a; the system
// commands arrive in WP-07b through DefaultRegistry.
//
// OS assumption: the real peer check needs Linux (SO_PEERCRED, /proc). The server itself is
// portable so its tests run anywhere with an injected peer.Checker.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/config"
	"github.com/knt048/vedette/host/peer"
)

// Options configures a Server. Zero values of the optional fields mean the defaults of spec section 10.
type Options struct {
	SocketPath string // absolute, validated by config.ValidSocketPath
	SocketGID  int    // group that owns the socket and its directory (the "vedette" group)
	StateDir   string // runs, idempotency records; mode 0700
	AuditPath  string // audit.jsonl; its directory is created 0700
	Registry   *Registry
	PeerCheck  peer.Checker // layers 2 and 3 of the peer check; required
	Version    string

	Logger        *slog.Logger
	Now           func() time.Time
	OSReleasePath string // default /etc/os-release

	RequestsPerMinute int
	WritesPerMinute   int
	KillGrace         time.Duration // how long a command may ignore its cancelled context before the run is failed anyway
	AuditThrottle     time.Duration // minimum spacing of unauthenticated-flood audit lines (default 10 s)
}

// Server serves the host API.
type Server struct {
	o        Options
	log      *slog.Logger
	now      func() time.Time
	reg      *Registry
	runs     *runStore
	audit    *auditLog
	throttle *auditThrottle
	reqLim   *window
	writeLim *window

	baseCtx  context.Context //nolint:containedctx // the server's lifetime context, cancelled by Shutdown to stop commands and streams
	cancel   context.CancelFunc
	draining atomic.Bool
	wg       sync.WaitGroup

	mu     sync.Mutex // guards active, live and the submit sequence
	active string     // run id holding the write lock, "" when free
	live   map[string]*eventLog

	srv *http.Server
}

// New opens the state, verifies the audit chain and recovers runs a crash left in progress.
// A broken audit chain does not stop it: writes are refused with audit_unavailable and
// /v1/info reports audit_ok=false; the caller should also log AuditError.
func New(o Options) (*Server, error) {
	switch {
	case o.PeerCheck == nil:
		return nil, errors.New("host: PeerCheck is required (fail closed)")
	case o.Registry == nil:
		return nil, errors.New("host: Registry is required")
	case o.StateDir == "" || o.AuditPath == "":
		return nil, errors.New("host: StateDir and AuditPath are required")
	}
	if err := config.ValidSocketPath(o.SocketPath); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.OSReleasePath == "" {
		o.OSReleasePath = "/etc/os-release"
	}
	if o.RequestsPerMinute <= 0 {
		o.RequestsPerMinute = defaultRequestsPerMinute
	}
	if o.WritesPerMinute <= 0 {
		o.WritesPerMinute = defaultWritesPerMinute
	}
	if o.KillGrace <= 0 {
		o.KillGrace = defaultKillGrace
	}
	if o.AuditThrottle <= 0 {
		o.AuditThrottle = 10 * time.Second
	}
	if err := ensureDir(o.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := ensureDir(filepath.Dir(o.AuditPath), 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		o: o, log: o.Logger, now: o.Now, reg: o.Registry,
		throttle: newAuditThrottle(o.AuditThrottle),
		reqLim:   newWindow(o.RequestsPerMinute, time.Minute),
		writeLim: newWindow(o.WritesPerMinute, time.Minute),
		live:     map[string]*eventLog{},
	}
	s.baseCtx, s.cancel = context.WithCancel(context.Background())
	s.srv = s.newHTTPServer()
	var err error
	if s.audit, err = openAudit(o.AuditPath, o.Now); err != nil {
		s.cancel()
		return nil, err
	}
	if s.runs, err = openRunStore(o.StateDir, o.Logger); err != nil {
		_ = s.audit.close()
		s.cancel()
		return nil, err
	}
	s.recover()
	s.runs.prune(s.now())
	return s, nil
}

// AuditError is nil while the audit chain verifies; otherwise it says why writes are refused.
func (s *Server) AuditError() error { return s.audit.brokenErr() }

// recover fails every run a crash left in progress as host_restarted, audits it, and gives it a
// final event. WP-07b must also decide what an awaiting_confirm net.apply does here (deferred).
func (s *Server) recover() {
	for _, sr := range s.runs.nonTerminal() {
		now := s.now().UTC()
		sr.Run.Status = api.StatusFailed
		sr.Run.FinishedAt = &now
		sr.Run.Error = &api.RunError{Code: api.CodeHostRestarted, Message: "The host restarted while the command was running."}
		sr.Run.RevertAt = nil
		if sr.Run.AuditID == "" {
			sr.Run.AuditID, _ = newID("au_")
		}
		if err := s.audit.append(auditEntry{
			ID: sr.Run.AuditID, RequestID: sr.Run.RequestID, Actor: sr.Run.Actor, Command: sr.Run.Command,
			ArgsDigest: sr.ArgsDigest, ArgsRedacted: nil, Result: resultFailed, Code: api.CodeHostRestarted, RunID: sr.Run.RunID,
		}); err != nil {
			s.log.Error("could not audit a recovered run", "run_id", sr.Run.RunID)
		}
		if err := s.runs.put(sr); err != nil {
			s.log.Error("could not save a recovered run", "run_id", sr.Run.RunID)
			continue
		}
		l := newEventLog(s.now)
		l.add(api.Event{Kind: api.KindState, Status: api.StatusFailed, Line: "The host restarted while the command was running."})
		l.finish()
		if err := writeJSONAtomic(s.runs.eventsPath(sr.Run.RunID), l.snapshot()); err != nil {
			s.log.Error("could not save events of a recovered run", "run_id", sr.Run.RunID)
		}
	}
}

// Listen prepares the directory and returns the unix listener: directory 0750 (an existing one
// must not be more open), a stale socket file replaced, a live one refused, socket 0660 owned by
// group SocketGID. There is no other listener anywhere in the program (FORBID-2).
func (s *Server) Listen(ctx context.Context) (net.Listener, error) {
	path := s.o.SocketPath
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("host: create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // 0750 is the specified directory mode
			return nil, fmt.Errorf("host: chmod %s: %w", dir, err)
		}
		if err := os.Chown(dir, -1, s.o.SocketGID); err != nil {
			return nil, fmt.Errorf("host: chown %s: %w", dir, err)
		}
	case err != nil:
		return nil, fmt.Errorf("host: stat %s: %w", dir, err)
	case !st.IsDir() || st.Mode().Perm()&0o027 != 0:
		return nil, fmt.Errorf("host: %s must be a directory with mode 0750 or stricter", dir)
	}
	if err := removeStaleSocket(ctx, path); err != nil {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("host: listen: %w", err)
	}
	fail := func(err error) (net.Listener, error) {
		_ = ln.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // 0660 is the specified socket mode
		return fail(fmt.Errorf("host: chmod socket: %w", err))
	}
	if err := os.Chown(path, -1, s.o.SocketGID); err != nil {
		return fail(fmt.Errorf("host: chown socket: %w", err))
	}
	return ln, nil
}

func removeStaleSocket(ctx context.Context, path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("host: stat %s: %w", path, err)
	}
	if st.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("host: %s exists and is not a socket", path)
	}
	d := net.Dialer{Timeout: time.Second}
	if c, err := d.DialContext(ctx, "unix", path); err == nil {
		_ = c.Close()
		return fmt.Errorf("host: another vedette-host is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("host: remove stale socket: %w", err)
	}
	return nil
}

// authConn carries the authenticated peer through to the request context.
type authConn struct {
	net.Conn
	info peer.Info
}

type ctxKey struct{}

// authListener runs the peer check on EVERY accepted connection before any byte is read.
type authListener struct {
	net.Listener
	s *Server
}

func (l authListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		info, err := l.s.o.PeerCheck(c)
		if err != nil {
			_ = c.Close()
			l.s.deniedPeer(info, err)
			continue
		}
		return &authConn{Conn: c, info: info}, nil
	}
}

// deniedPeer audits peer_not_allowed, throttled: strangers need no credentials to knock.
func (s *Server) deniedPeer(info peer.Info, cause error) {
	s.log.Warn("peer not allowed", "uid", info.UID, "pid", info.PID, "cause", cause.Error())
	ok, skipped := s.throttle.allow("peer_not_allowed", s.now())
	if !ok {
		return
	}
	id, err := newID("au_")
	if err != nil {
		return
	}
	info.Unit = ""
	if err := s.audit.append(auditEntry{
		ID: id, Actor: "-", Peer: info, Command: "-", Result: resultRefused, Code: api.CodePeerNotAllowed,
		ArgsRedacted: map[string]any{"skipped": skipped},
	}); err != nil {
		s.log.Error("could not audit a denied peer")
	}
}

// newHTTPServer builds the http.Server once, in New, so Serve and Shutdown never race on it.
func (s *Server) newHTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return s.baseCtx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if ac, ok := c.(*authConn); ok {
				return context.WithValue(ctx, ctxKey{}, ac.info)
			}
			return ctx // unreachable: authListener wraps every connection; the handler denies a missing peer
		},
	}
}

// Serve accepts connections on ln until Shutdown. It returns nil after a Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	err := s.srv.Serve(authListener{Listener: ln, s: s})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting work: new requests get 503 host_shutting_down, running commands have
// their context cancelled, and it waits for them (bounded by ctx) before closing the listener
// and the audit log.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	s.cancel()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		err = fmt.Errorf("host: shutdown: commands still running: %w", ctx.Err())
	}
	if e := s.srv.Shutdown(ctx); e != nil {
		_ = s.srv.Close()
		err = errors.Join(err, fmt.Errorf("host: shutdown: %w", e))
	}
	return errors.Join(err, s.audit.close())
}

func peerFrom(ctx context.Context) (peer.Info, bool) {
	p, ok := ctx.Value(ctxKey{}).(peer.Info)
	return p, ok
}
