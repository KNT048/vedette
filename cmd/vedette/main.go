// Command vedette is the box's main process: the core API, the module registry and the job
// scheduler (D-8, D-55). The embedded web interface and TLS arrive with WP-04b and WP-08.
package main

import (
	"context"
	"crypto/tls"
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
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
	tlsCert, tlsKey string
	hosts           string
	hostSocket      string
	honeypotDir     string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vedette", flag.ContinueOnError)
	flags.SetOutput(stdout)
	showVersion := flags.Bool("version", false, "print the version and exit")
	var o options
	flags.StringVar(&o.db, "db", "/var/lib/vedette/vedette.db", "path of the SQLite database (created with mode 0600)")
	flags.StringVar(&o.key, "key", "/var/lib/vedette/vedette.key", "path of the secrets master key file (created with mode 0600 when missing)")
	flags.StringVar(&o.honeypotDir, "honeypot-dir", "/var/lib/vedette/honeypot", "parent of the two folders shared with the honeypot container: config/ (core writes opencanary.conf; the container mounts it read-only) and log/ (the container writes the trap log, core reads it) (D-89)")
	// Plain HTTP only on loopback; any other address is served over TLS (own certificate, or a self-signed one made at first start).
	flags.StringVar(&o.hostSocket, "host-socket", "/run/vedette/host.sock", "unix socket of vedette-host (operating system updates and backups); empty, or a missing socket file, means a container-only install and those endpoints answer 409 not_appliance. The database and key files must be <dir>/vedette.db and <dir>/vedette.key, where <dir> is the host's core_data")
	flags.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address to listen on; plain HTTP on loopback, TLS on any other address")
	flags.StringVar(&o.tlsCert, "tls-cert", "", "PEM certificate for TLS (with -tls-key); when both are missing and -listen is not loopback, a self-signed pair is made next to the database")
	flags.StringVar(&o.tlsKey, "tls-key", "", "PEM private key for TLS")
	flags.StringVar(&o.hosts, "hosts", "", "comma-separated host names (a leading *. covers one label, like a wildcard certificate) and IP addresses the box answers to (Host header allowlist, 421 for others); default: the loopback names and the names of the certificate")
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
	if (o.tlsCert == "") != (o.tlsKey == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	if _, err := parseHosts(o.hosts); err != nil {
		return err
	}
	if _, err := isLoopback(o.listen); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	return serve(ctx, log, o)
}

// isLoopback reports whether a -listen address is loopback: a literal loopback IP or "localhost". An empty
// host (":8080") or any other name is not (it can resolve, or bind, anywhere). The error is for an address
// that does not parse.
func isLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("listen %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return true, nil
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback(), nil
}

// transport decides how the listener speaks and which Host headers it answers to. Plain HTTP is only for
// loopback (sessions and passwords must not cross a network in clear); anywhere else it is TLS, with the
// certificate of -tls-cert/-tls-key or a self-signed one made next to the database on first start (names:
// -hosts and what localNames finds). The allowlist is -hosts when given, otherwise the names of the
// certificate in use; loopback is always allowed by core/server.HostAllowlist. hsts is true only for a
// certificate the owner supplied: the box then tells browsers to insist on HTTPS. A self-signed pair gets
// no HSTS, or a browser would refuse to let the owner click through its warning for a year.
func transport(o options) (cfg *tls.Config, hosts []string, hsts bool, renew *selfSignedRenewer, err error) {
	hosts, err = parseHosts(o.hosts)
	flagHosts := hosts
	if err != nil {
		return nil, nil, false, nil, err
	}
	loop, err := isLoopback(o.listen)
	if err != nil {
		return nil, nil, false, nil, err
	}
	certPath, keyPath := o.tlsCert, o.tlsKey
	if certPath == "" && loop {
		return nil, hosts, false, nil, nil // plain HTTP on loopback
	}
	if certPath == "" {
		dir := filepath.Dir(o.db)
		certPath, keyPath = filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
		if err := ensureCert(certPath, keyPath, hosts); err != nil {
			return nil, nil, false, nil, err
		}
	}
	cfg, names, err := loadTLS(certPath, keyPath)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if o.tlsCert == "" { // the box's own pair: serve it through GetCertificate so a renewal needs no restart
		renew = &selfSignedRenewer{certPath: certPath, keyPath: keyPath, hosts: flagHosts, now: time.Now, cert: &cfg.Certificates[0]}
		cfg.Certificates, cfg.GetCertificate = nil, renew.GetCertificate
	}
	if len(hosts) == 0 {
		hosts = names
	}
	return cfg, hosts, o.tlsCert != "", renew, nil
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
	tlsCfg, hosts, hsts, renew, err := transport(o)
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
	d := deps{Log: log, DB: db, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now, Bus: events.NewBus(log), Hosts: hosts, BaseURL: baseURL(hosts, o.listen),
		HostSocket: o.hostSocket, HostNet: newHostNetCache(hostSocketNet(o.hostSocket, log), time.Now), DataDir: filepath.Dir(o.db), KeyPath: o.key, HoneypotDir: o.honeypotDir}
	if err := buildServices(&d); err != nil {
		return err
	}
	defer d.OS.Close()
	if o.hostSocket != "" && (filepath.Base(o.db) != "vedette.db" || filepath.Base(o.key) != "vedette.key" || filepath.Dir(o.key) != filepath.Dir(o.db)) {
		log.WarnContext(ctx, "backup restore through vedette-host needs the database and key at <core_data>/vedette.db and <core_data>/vedette.key", "db", o.db, "key", o.key)
	}
	// D-75: while first-run setup is open the box prints its one-time setup code, at every start. This is the
	// one place a secret is logged on purpose: the log is where the person who installed the box looks.
	code, err := d.Core.EnsureSetupCode(ctx)
	if err != nil {
		return err
	}
	if code != "" {
		log.InfoContext(ctx, "first-run setup is open: enter this one-time setup code on the setup page", "setup_code", code)
	}
	sched := jobs.New(log, reg, nil, jobs.WithRecorder(jobs.NewHistory(db)))
	reg.OnChange(sched.ModuleChanged)
	if err := addJobs(sched, d, wired); err != nil {
		return err
	}

	api, err := server.New(server.Config{
		API:        newHandler(d),
		Auth:       d.Auth.Sessions,
		Modules:    reg,
		Log:        log,
		BodyLimits: bodyLimits(wired),
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           topHandler(log, api, hosts, hsts, boxOwnAddress(d.HostNet)), //nolint:contextcheck // the Host check runs per request, with no context to pass
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
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	if renew != nil {
		tick := time.NewTicker(selfSignedCheckEvery)
		defer tick.Stop()
		go renew.Run(ctx, log, tick.C)
	}
	return serveUntilDone(ctx, log, srv, ln, sched, schedulerStopTimeout)
}

// topHandler is everything the listener answers. A Host header outside the allowlist is 421 before anything
// else is routed (DNS rebinding). The Envelope (panic recovery, request id, security
// headers) wraps the ServeMux too, so the mux's own answers (307 for /api/v1, //, .. and the 404 for
// other paths) carry the headers the API's responses do.
func topHandler(log *slog.Logger, api http.Handler, hosts []string, hsts bool, own func(netip.Addr) bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(server.Prefix+"/", api)
	h := server.HostAllowlistWith(hosts, own, mux)
	if hsts {
		h = strictTransportSecurity(h)
	}
	return server.Envelope(log, h)
}

// strictTransportSecurity adds HSTS (one year, no includeSubDomains or preload: the box does not own the
// owner's domain) to every response.
func strictTransportSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
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
