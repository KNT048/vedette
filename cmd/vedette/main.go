// Command vedette is the box's main process: the core API, the module registry and the job
// scheduler (D-8, D-55). The embedded web interface and TLS arrive with WP-04b and WP-08.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

// shutdownTimeout is how long in-flight requests get after SIGINT or SIGTERM; schedulerStopTimeout is
// how long the scheduler gets to stop its jobs before the process gives up waiting for jobs that
// ignore their context (and closes the database anyway).
const (
	shutdownTimeout      = 10 * time.Second
	schedulerStopTimeout = 10 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vedette:", err)
		os.Exit(1)
	}
}

type options struct {
	db, key, listen string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vedette", flag.ContinueOnError)
	flags.SetOutput(stdout)
	showVersion := flags.Bool("version", false, "print the version and exit")
	var o options
	flags.StringVar(&o.db, "db", "/var/lib/vedette/vedette.db", "path of the SQLite database (created with mode 0600)")
	flags.StringVar(&o.key, "key", "/var/lib/vedette/vedette.key", "path of the secrets master key file (created with mode 0600 when missing)")
	// ponytail: plain HTTP on loopback; TLS on :8443 arrives with WP-04b/WP-08, then this default changes.
	flags.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address to listen on")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if err := checkLoopback(o.listen); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	return serve(ctx, log, o)
}

// checkLoopback refuses a -listen address that is not loopback: sessions and the API travel over
// plain HTTP until TLS lands (WP-04b/WP-08), so the process must not be reachable from the network.
// Only literal loopback IPs and "localhost" pass; an empty host (":8080") or any other name does not.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsLoopback() {
		return nil
	}
	return fmt.Errorf("listen %q: refused, the address must be loopback (127.0.0.0/8, ::1 or localhost) until TLS is built in (WP-04b)", addr)
}

// serve opens everything, serves until ctx is cancelled, then shuts down in order: HTTP server,
// scheduler (running jobs are cancelled and waited for), database.
func serve(ctx context.Context, log *slog.Logger, o options) error {
	if err := ensureKey(o.key); err != nil {
		return err
	}
	key, err := secrets.LoadKeyFile(o.key)
	if err != nil {
		return err
	}
	sec, err := secrets.New(key) // fail at start, not at the first secret
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, o.db, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.ErrorContext(ctx, "closing the database failed", "error", err)
		}
	}()
	wired := wiredModules()
	if err := migrateAll(ctx, db, wired); err != nil {
		return err
	}
	aud := audit.New(nil)
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		return err
	}
	d := deps{Log: log, DB: db, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now}
	sched := jobs.New(log, reg, nil, jobs.WithRecorder(jobs.NewHistory(db)))
	reg.OnChange(sched.ModuleChanged)
	if err := addJobs(sched, d, wired); err != nil {
		return err
	}

	api, err := server.New(server.Config{
		API:        newHandler(d),
		Auth:       noSessions{}, // ponytail: WP-04b replaces this with sessions and CSRF
		Modules:    reg,
		Log:        log,
		BodyLimits: bodyLimits(wired),
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           topHandler(log, api),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", o.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return serveUntilDone(ctx, log, srv, ln, sched, schedulerStopTimeout)
}

// topHandler is everything the listener answers. The Envelope (panic recovery, request id, security
// headers) wraps the ServeMux too, so the mux's own answers (307 for /api/v1, //, .. and the 404 for
// other paths) carry the headers the API's responses do.
func topHandler(log *slog.Logger, api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(server.Prefix+"/", api)
	return server.Envelope(log, mux)
}

// serveUntilDone serves on ln and runs the scheduler until ctx is cancelled or the listener fails,
// then stops in order: HTTP server, scheduler, return (the caller closes the database). The scheduler
// runs on a child context that is cancelled on every exit path, and the wait for it is bounded by
// stopWait so a job that ignores its context cannot hang the shutdown.
func serveUntilDone(ctx context.Context, log *slog.Logger, srv *http.Server, ln net.Listener, sched *jobs.Scheduler, stopWait time.Duration) error {
	schedCtx, cancelSched := context.WithCancel(ctx)
	schedDone := make(chan struct{})
	go func() { defer close(schedDone); sched.Run(schedCtx) }()
	stopSched := func() {
		cancelSched()
		select {
		case <-schedDone:
		case <-time.After(stopWait):
			log.ErrorContext(ctx, "scheduler did not stop in time: a job ignores its context", "waited", stopWait.String())
		}
	}
	defer stopSched()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.InfoContext(ctx, "listening", "addr", ln.Addr().String(), "version", version)

	select {
	case err := <-serveErr: // the listener failed: stop the scheduler (deferred) and report
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	log.InfoContext(ctx, "shutting down")
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := srv.Shutdown(sctx)
	stopSched()
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}
	return nil
}

// ensureKey creates the master key on first start. An existing file is left alone (and validated by
// LoadKeyFile): losing or replacing the key makes every stored secret unreadable.
func ensureKey(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("key file: %w", err)
	}
	return secrets.GenerateKeyFile(path)
}
