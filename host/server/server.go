// Package server is the vedette-host socket server: a unix-socket HTTP/1.1 JSON API with a closed
// command table, durable runs, one global write lock, a hash-chained audit log and per-connection
// peer authentication (docs/specs/host-api.md). It is the framework of WP-07a; the system
// commands live in host/ops (WP-07b) and are handed in through Options.Registry and Options.Readers.
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
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
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
	Readers    Readers // read-only state endpoints (spec section 5); zero value: none
	// WriteGate, when set, is asked before a write command is accepted (after the idempotency
	// lookup, so a retry of an accepted request still gets its run). A non-nil refusal ends the
	// request like busy does: no run, one audit line. It must not block or take locks the server holds.
	WriteGate func() *Refusal
	// Resume is asked, during New (so before Listen), about each run a restart found in
	// awaiting_confirm (D-100). True: the run stays awaiting and keeps the write lock; the caller
	// then re-arms its timer (after New returns) and settles the run with Settle, at once if
	// revert_at has passed. False, nil, a panic, or a second awaiting run: the run is settled
	// failed host_restarted like any run a crash cut short. Resume must only read.
	Resume    func(api.Run) bool
	PeerCheck peer.Checker // layers 2 and 3 of the peer check; required
	Version   string

	Logger        *slog.Logger
	Now           func() time.Time
	OSReleasePath string // default /etc/os-release

	RequestsPerMinute int
	WritesPerMinute   int
	KillGrace         time.Duration // how long a command may ignore its cancelled context before the run is reported failed (the write lock stays held)
	AbandonCeiling    time.Duration // how long past KillGrace a command may keep running before the host exits for systemd to restart it (default 5 min)
	CheckTimeout      time.Duration // bound of a command's synchronous Check (default 5 s)
	BodyDeadline      time.Duration // how long a request body may take to arrive (default 30 s)
	AuditThrottle     time.Duration // minimum spacing of unauthenticated-flood audit lines per uid (default 10 s)
	// OwnerUID is the uid that must own the state, audit and socket directories and the audit
	// file: 0 in production (the host runs as root). Tests set their own uid.
	OwnerUID int
	// Exit ends the process when a command cannot be stopped (default os.Exit). Tests replace it.
	Exit func(code int)
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

	mu       sync.Mutex // guards active, waiting, inflight, live and the submit sequence
	active   string     // run id holding the write lock, "" when free (a waiting run holds it)
	waiting  *liveRun   // the run parked in awaiting_confirm, nil when none; it is active
	inflight string     // run id of the WhileAwaiting command running now, "" when none
	live     map[string]*eventLog

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
	if o.AbandonCeiling <= 0 {
		o.AbandonCeiling = 5 * time.Minute
	}
	if o.CheckTimeout <= 0 {
		o.CheckTimeout = checkTimeout
	}
	if o.BodyDeadline <= 0 {
		o.BodyDeadline = 30 * time.Second
	}
	if o.Exit == nil {
		o.Exit = os.Exit
	}
	if err := ensureDir(o.StateDir, 0o700, o.OwnerUID); err != nil {
		return nil, err
	}
	if err := ensureDir(filepath.Dir(o.AuditPath), 0o700, o.OwnerUID); err != nil {
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
	if s.audit, err = openAudit(o.AuditPath, o.OwnerUID, o.Now); err != nil {
		s.cancel()
		return nil, err
	}
	if s.runs, err = openRunStore(o.StateDir, o.OwnerUID, o.Logger); err != nil {
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
// final event. A run found in awaiting_confirm is kept instead when Options.Resume says so (D-100).
func (s *Server) recover() {
	for _, sr := range s.runs.nonTerminal() {
		if s.resumeAwaiting(sr) {
			continue
		}
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
			ArgsDigest: sr.ArgsDigest, Result: resultFailed, Code: api.CodeHostRestarted, RunID: sr.Run.RunID,
			ArgsRedacted: map[string]any{"accepted_audit_id": sr.AcceptedAuditID},
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

// Listen prepares the directory and returns the unix listener. The directory must be a real
// directory owned by OwnerUID and group SocketGID, mode 0750 or stricter (created so when absent);
// a stale socket file is replaced, a live one refused. The socket is then given to group SocketGID
// (Lchown, which never follows a symlink) and set to 0660 by path, and the path is checked, before
// and after, to still be that very socket (same inode); see secureSocket for why this is safe.
// There is no other listener anywhere in the program (FORBID-2).
func (s *Server) Listen(ctx context.Context) (net.Listener, error) {
	path := s.o.SocketPath
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("host: create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // 0750 is the specified directory mode
			return nil, fmt.Errorf("host: chmod %s: %w", dir, err)
		}
		if err := os.Lchown(dir, s.o.OwnerUID, s.o.SocketGID); err != nil {
			return nil, fmt.Errorf("host: chown %s: %w", dir, err)
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("host: stat %s: %w", dir, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || int(sys.Uid) != s.o.OwnerUID || int(sys.Gid) != s.o.SocketGID || st.Mode().Perm()&0o027 != 0 {
		return nil, fmt.Errorf("host: %s must be a directory owned by uid %d and gid %d with mode 0750 or stricter", dir, s.o.OwnerUID, s.o.SocketGID)
	}
	if err := removeStaleSocket(ctx, path); err != nil {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("host: listen: %w", err)
	}
	if err := secureSocket(path, s.o.SocketGID); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// secureSocket sets mode 0660 and group gid and verifies the path is still the socket that was just
// bound. Lchown never follows a symlink; chmod has no no-follow form, so it is bracketed by two
// Lstat checks of the same inode. The directory is owned by root with no write for anyone else
// (checked in Listen), so nobody can swap the path in between. A bind under umask 0117 would give
// the socket its mode at birth, but umask is process-wide and breaks concurrent mkdir calls.
func secureSocket(path string, gid int) error {
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("host: %s is not the socket that was just bound", path)
	}
	if err := os.Lchown(path, -1, gid); err != nil {
		return fmt.Errorf("host: chown socket: %w", err)
	}
	mid, err := os.Lstat(path)
	if err != nil || mid.Mode().Type() != os.ModeSocket || !os.SameFile(before, mid) {
		return fmt.Errorf("host: %s changed while it was being secured", path)
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // 0660 is the specified socket mode
		return fmt.Errorf("host: chmod socket: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode().Type() != os.ModeSocket || !os.SameFile(before, after) || after.Mode().Perm() != 0o660 {
		return fmt.Errorf("host: %s changed while it was being secured", path)
	}
	return nil
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
	if SocketLive(ctx, path) {
		return fmt.Errorf("host: another vedette-host is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("host: remove stale socket: %w", err)
	}
	return nil
}

// SocketLive says whether something accepts connections on the unix socket at path: the host's own
// "is a daemon running" test. A daemon takes the socket before it serves, so a bootstrap that finds it
// live must not touch the state the daemon owns.
func SocketLive(ctx context.Context, path string) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
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
			l.s.deniedPeer(info, err) // audited before the close, so a denied caller that gets EOF knows the line exists
			_ = c.Close()
			continue
		}
		return &authConn{Conn: c, info: info}, nil
	}
}

// deniedPeer audits peer_not_allowed, throttled per uid: strangers need no credentials to knock,
// but a noisy uid must not hide another one.
func (s *Server) deniedPeer(info peer.Info, cause error) {
	s.log.Warn("peer not allowed", "uid", info.UID, "pid", info.PID, "cause", cause.Error())
	s.flushThrottle()
	info.Unit = ""
	e := auditEntry{Actor: "-", Peer: info, Command: "-", Result: resultRefused, Code: api.CodePeerNotAllowed}
	if s.throttle.allow("peer_not_allowed:"+strconv.Itoa(info.UID), s.now(), e) {
		s.writeThrottled(e, nil)
	}
}

// newHTTPServer builds the http.Server once, in New, so Serve and Shutdown never race on it.
func (s *Server) newHTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		// No ReadTimeout: it would also cut event streams. Bodies get their own deadline in handleCommand.
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:    func(net.Listener) context.Context { return s.baseCtx },
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
	go s.sweepThrottle()
	err := s.srv.Serve(authListener{Listener: ln, s: s})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting work: new requests get 503 host_shutting_down, running commands have
// their context cancelled, and it waits for them (bounded by ctx) before closing the listener
// and the audit log. A run awaiting confirmation stays awaiting on disk (the next start decides,
// Options.Resume); Settle after Shutdown began returns ErrShuttingDown and changes nothing.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock() // under the lock so a Settle either sees draining or has already joined the wait group
	s.draining.Store(true)
	s.mu.Unlock()
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
