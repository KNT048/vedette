package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// ModuleID is the module's id in the registry.
const ModuleID = "mcp-server"

// startRetry is how long Follow waits before it tries a failed start again.
const startRetry = 15 * time.Second

// DefaultListen is where the server listens: loopback only (INV-5, D-230).
var DefaultListen = netip.MustParseAddrPort("127.0.0.1:8765")

// Enabler says whether a module is on (the module registry).
type Enabler interface{ Enabled(id string) bool }

// Config is what New needs.
type Config struct {
	DB      *store.DB
	Audit   *audit.Log
	Log     *slog.Logger
	Clock   func() time.Time // nil: time.Now
	Source  Source
	Modules Enabler
	// Listen is the address of the MCP endpoint. It must be a loopback address (INV-5, FORBID-4); the zero value is DefaultListen.
	// Port 0 picks a free port (tests).
	Listen netip.AddrPort
	// Version is the build's version, sent as serverInfo.
	Version string
}

// Service owns the tokens and the listener.
type Service struct {
	db      *store.DB
	audit   *audit.Log
	log     *slog.Logger
	now     func() time.Time
	src     Source
	mods    Enabler
	listen  netip.AddrPort
	version string
	limits  *limiter

	follow sync.Mutex // serialises Follow's start and stop
	mu     sync.Mutex
	srvErr error // why the last start failed; nil while listening or stopped on purpose
	srv    *http.Server
	bound  netip.AddrPort // the address the running listener has; zero while stopped
}

// New checks cfg. A listen address off loopback is refused: the switch never opens the port to the network (FORBID-4).
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Log == nil || cfg.Source == nil || cfg.Modules == nil {
		return nil, errors.New("mcpserver: DB, Audit, Log, Source and Modules are required")
	}
	if !cfg.Listen.IsValid() {
		cfg.Listen = DefaultListen
	}
	if !cfg.Listen.Addr().IsLoopback() {
		return nil, fmt.Errorf("mcpserver: listen address %s is not a loopback address: the MCP server only listens on this machine (INV-5)", cfg.Listen)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	return &Service{db: cfg.DB, audit: cfg.Audit, log: cfg.Log, now: cfg.Clock, src: cfg.Source, mods: cfg.Modules, listen: cfg.Listen,
		version: cfg.Version, limits: newLimiter(cfg.Clock)}, nil
}

// Listening reports whether the listener is open, and why the last start failed (shown on Settings → MCP server, so an
// administrator never configures an agent for a port another process holds: that process would get the token).
func (s *Service) Listening() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil, s.srvErr
}

// Endpoint is the address agents use, and bind its listen address: the running listener's when there is one.
func (s *Service) Endpoint() (bind netip.AddrPort, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bind = s.listen
	if s.bound.IsValid() {
		bind = s.bound
	}
	return bind, "http://" + bind.String() + "/mcp"
}

// Start opens the listener; it does nothing when it is already open. The port is open exactly while the module is on (POST-1).
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return nil
	}
	if err := ctx.Err(); err != nil { // shutting down: a late switch-on must not reopen the port
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.listen.String())
	if err != nil {
		s.srvErr = fmt.Errorf("mcpserver: listen on %s: %w", s.listen, err)
		return s.srvErr
	}
	s.srvErr = nil
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.Handler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	s.srv = srv
	s.bound = netip.MustParseAddrPort(ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.ErrorContext(ctx, "the MCP server stopped", "error", err)
		}
	}()
	s.log.InfoContext(ctx, "MCP server listening", "address", s.bound.String())
	return nil
}

// Stop closes the listener and the open connections: every agent loses the connection (SYS-5). Tokens stay.
func (s *Service) Stop(ctx context.Context) {
	s.mu.Lock()
	srv := s.srv
	s.srv, s.bound, s.srvErr = nil, netip.AddrPort{}, nil
	s.mu.Unlock()
	if srv == nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	s.log.InfoContext(ctx, "MCP server stopped")
}

// Follow starts or stops the listener with the module's switch and returns at once. Call it once at start-up with the
// registry's OnChange; the current state is applied now.
func (s *Service) Follow(ctx context.Context, onChange func(func(id string, enabled bool))) {
	var resync func()
	apply := func(on bool) {
		if !on || ctx.Err() != nil {
			s.Stop(ctx)
			return
		}
		if err := s.Start(ctx); err != nil {
			s.log.ErrorContext(ctx, "the MCP server could not start; trying again in a while", "error", err)
			go func() { // the port may be held for a moment (a restart); the page shows the error meanwhile
				select {
				case <-ctx.Done():
				case <-time.After(startRetry):
					resync()
				}
			}()
		}
	}
	// Each change re-reads the switch under one lock, so a quick off-on-off cannot leave the port open in the wrong order.
	resync = func() {
		s.follow.Lock()
		defer s.follow.Unlock()
		apply(s.mods.Enabled(ModuleID))
	}
	onChange(func(id string, _ bool) {
		if id == ModuleID {
			go resync() // OnChange subscribers must not block
		}
	})
	resync()
}
