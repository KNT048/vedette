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
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/internal/webui"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/logs"
)

// version is set at build time: -ldflags "-X main.version=0.1.0". It must be SemVer (run refuses anything else), like the version
// of vedette-sensor that goes into its heartbeat; an unreleased build is 0.0.0-dev.
var version = "0.0.0-dev"

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
	// sensorListen and sensorCreds are the sensor link (D-141): the mutual-TLS listener of the two sensor containers and the directory
	// that holds their credentials, <creds>/<role>/sensor.pem. Empty sensorListen = no listener (a container-only install).
	sensorListen, sensorCreds string
	// syslogPort is the port the logs module listens on for syslog; 0 = 514, and 5514 when the process may not bind 514.
	syslogPort int
	// mcpListen is the loopback address of the read-only MCP server (mcp-server module, INV-5, D-230).
	mcpListen string
}

// newFlags builds the flag set of the server and binds it to o. The test that checks the Exec= line of core's
// Quadlet unit parses it with this same constructor (host/ops owns the unit text, D-123), so a flag renamed
// here without the unit following fails a test.
func newFlags(o *options, stdout io.Writer) (flags *flag.FlagSet, showVersion *bool) {
	flags = flag.NewFlagSet("vedette", flag.ContinueOnError)
	flags.SetOutput(stdout)
	showVersion = flags.Bool("version", false, "print the version and exit")
	flags.StringVar(&o.db, "db", "/var/lib/vedette/vedette.db", "path of the SQLite database (created with mode 0600)")
	flags.StringVar(&o.key, "key", "/var/lib/vedette/vedette.key", "path of the secrets master key file (created with mode 0600 when missing)")
	flags.StringVar(&o.honeypotDir, "honeypot-dir", defaultHoneypotDir, "parent of the two folders shared with the honeypot container: config/ (core writes opencanary.conf; the container mounts it read-only) and log/ (the container writes the trap log, core reads it) (D-89)")
	// Plain HTTP only on loopback; any other address is served over TLS (own certificate, or a self-signed one made at first start).
	flags.StringVar(&o.hostSocket, "host-socket", "/run/vedette/host.sock", "unix socket of vedette-host (operating system updates and backups); empty, or a missing socket file, means a container-only install and those endpoints answer 409 not_appliance (the data purge is stricter: with a socket path set, a missing socket refuses it with 502, because the helper holds backups; pass an empty value for a box without a helper). The database and key files must be <dir>/vedette.db and <dir>/vedette.key, where <dir> is the host's core_data")
	flags.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address to listen on; plain HTTP on loopback, TLS on any other address")
	flags.StringVar(&o.tlsCert, "tls-cert", "", "PEM certificate for TLS (with -tls-key); when both are missing and -listen is not loopback, a self-signed pair is made next to the database")
	flags.StringVar(&o.tlsKey, "tls-key", "", "PEM private key for TLS")
	flags.StringVar(&o.hosts, "hosts", "", "comma-separated host names (a leading *. covers one label, like a wildcard certificate) and IP addresses the box answers to (Host header allowlist, 421 for others); default: the loopback names and the names of the certificate")
	flags.StringVar(&o.sensorListen, "sensor-listen", "", "address of the sensor link, a mutual-TLS listener for the sensor and scan containers (D-109), e.g. :8444 inside the container (the unit publishes 127.0.0.1:8444 only); empty = none, and the sensors cannot reach core")
	flags.StringVar(&o.sensorCreds, "sensor-creds", "", "directory where core writes the sensors' credentials, <dir>/passive/sensor.pem and <dir>/active/sensor.pem (needed with -sensor-listen); each role's folder is a volume shared with that container only")
	flags.IntVar(&o.syslogPort, "syslog-port", 0, "port of the syslog listener of the logs module (UDP and TCP, only while the module is on and a source is declared); 0 = 514, or 5514 when this process may not bind 514")
	flags.StringVar(&o.mcpListen, "mcp-listen", "127.0.0.1:8765", "loopback address and port of the read-only MCP server, open only while the mcp-server module is on; an address off loopback is refused (INV-5, D-230)")
	return flags, showVersion
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if kind, ok := healthCommand(args); ok { // the HealthCmd= of the units: before any flag, no database, no key
		return runHealthCommand(ctx, kind)
	}
	var o options
	flags, showVersion := newFlags(&o, stdout)
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
	if o.syslogPort < 0 || o.syslogPort > 65535 {
		return fmt.Errorf("-syslog-port %d is not a port", o.syslogPort)
	}
	if !sensorlink.ValidVersion(version) {
		return fmt.Errorf("the build version %q is not SemVer: build with -ldflags \"-X main.version=<major.minor.patch>\"", version)
	}
	if _, err := parseHosts(o.hosts); err != nil {
		return err
	}
	if _, err := isLoopback(o.listen); err != nil {
		return err
	}
	if o.sensorListen != "" {
		if o.sensorCreds == "" || !filepath.IsAbs(o.sensorCreds) {
			return errors.New("-sensor-listen needs -sensor-creds, an absolute path")
		}
		if _, _, err := net.SplitHostPort(o.sensorListen); err != nil {
			return fmt.Errorf("-sensor-listen %q: %w", o.sensorListen, err)
		}
	} else if o.sensorCreds != "" {
		return errors.New("-sensor-creds needs -sensor-listen")
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
		renew = &selfSignedRenewer{certPath: certPath, keyPath: keyPath, hosts: flagHosts, now: time.Now, cert: &cfg.Certificates[0], kick: make(chan struct{}, 1)}
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
	// A purge ends the process the same way SIGTERM does (graceful stop, exit 0): Quadlet's Restart=always, or the restart policy of
	// a container, starts it on the fresh box (D-154). Without a supervisor the box stays stopped until someone starts it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	var warner *ownerCertWarner // an owner's certificate: never touched, only watched (D-139)
	if o.hostSocket != "" {
		if renew != nil {
			renew.mgmt = hostMgmtIPv4s(hostclient.New(o.hostSocket), log)
		} else {
			warner = newOwnerCertWarner(tlsCfg, hostMgmtIPv4s(hostclient.New(o.hostSocket), log))
		}
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
	// logs.db: the volume of the logs module (received lines), a database of its own with its own writer, next to the main one.
	logsDB, err := store.Open(ctx, filepath.Join(filepath.Dir(o.db), "logs.db"), log)
	if err != nil {
		return err
	}
	defer func() {
		if err := logsDB.Close(); err != nil {
			log.ErrorContext(ctx, "closing the logs database failed", "error", err)
		}
	}()
	if err := store.Migrate(ctx, logsDB, logs.ModuleID, logs.VolumeMigrations); err != nil {
		return err
	}
	wired := wiredModules()
	if err := migrateAll(ctx, db, wired); err != nil {
		return err
	}
	// A purge froze the database at its commit and left a marker: the compaction (VACUUM) that removes the deleted rows from the file
	// happens here, before anything else writes. A failure is logged and retried at the next start (the marker stays).
	if err := core.CompactIfPending(ctx, db, filepath.Dir(o.db)); err != nil {
		log.ErrorContext(ctx, "compacting the database after a purge failed; it is tried again at the next start", "error", err)
	}
	aud := audit.New(nil)
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		return err
	}
	sched := jobs.New(log, reg, nil, jobs.WithRecorder(jobs.NewHistory(db))) // before the services: deps.Wake hands them sched.Wake
	d := deps{Log: log, DB: db, LogsDB: logsDB, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now, Bus: events.NewBus(log), Hosts: hosts, BaseURL: baseURL(hosts, o.listen), CertKick: func() { renew.Kick(); warner.Kick() }, Wake: sched.Wake,
		HostSocket: o.hostSocket, HostNet: newHostNetCache(hostSocketNet(o.hostSocket, log), time.Now), DataDir: filepath.Dir(o.db), KeyPath: o.key, HoneypotDir: o.honeypotDir,
		Restart: func() {
			log.InfoContext(ctx, "the data was purged: stopping so the supervisor starts a fresh box")
			cancel()
		}}
	d.SyslogPort = o.syslogPort // before buildServices: the logs service reads it when it is built
	if d.MCPListen, err = parseMCPListen(o.mcpListen); err != nil {
		return err
	}
	if err := buildServices(ctx, &d); err != nil {
		return err
	}
	defer d.OS.Close()
	defer d.Response.Close()     // ends the approval requests still being sent before the database closes
	defer scanService(d).Close() // stop a live scan and wait for it before the database closes (scan review M4)
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
	var link *sensorLink // the PKI starts and writes the bundles before this listener opens (D-110 (4)); the renew job reads d.Authority
	if o.sensorListen != "" {
		if link, err = openSensorLink(ctx, &d, o.sensorListen, o.sensorCreds); err != nil {
			return err
		}
		defer func() { _ = link.ln.Close() }() // only matters when a later step fails before serveUntilDone owns it
	}
	reg.OnChange(sched.ModuleChanged)
	if err := addJobs(sched, d, wired); err != nil {
		return err
	}
	offCtx, stopOff := context.WithCancel(ctx)
	guard := modreg.NewOffGuard(offCtx, reg, log, nil)
	defer func() { stopOff(); guard.Wait() }()
	reg.OnChange(guard.ModuleChanged)
	if err := startMCP(ctx, d); err != nil { // the port is open exactly while the module is on (POST-1)
		return err
	}
	addOffGuards(guard, d, wired) //nolint:contextcheck // the guard runs on offCtx, the child of ctx made just above; a module that is off at start gets its teardown now, with retries (D-189)

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
		addrTick := time.NewTicker(selfSignedAddrEvery)
		defer addrTick.Stop()
		go renew.Run(ctx, log, tick.C, addrTick.C)
	}
	if warner != nil {
		tick := time.NewTicker(selfSignedCheckEvery)
		defer tick.Stop()
		addrTick := time.NewTicker(selfSignedAddrEvery)
		defer addrTick.Stop()
		go warner.Run(ctx, log, tick.C, addrTick.C)
	}
	return serveUntilDone(ctx, log, srv, ln, link, sched, schedulerStopTimeout)
}

// topHandler is everything the listener answers. A Host header outside the allowlist is 421 before anything
// else is routed (DNS rebinding). The Envelope (panic recovery, request id, security
// headers) wraps the ServeMux too, so the mux's own answers (307 for /api/v1, //, .. and the 404 for
// other paths) carry the headers the API's responses do.
func topHandler(log *slog.Logger, api http.Handler, hosts []string, hsts bool, own func(netip.Addr) bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(server.Prefix+"/", api)
	mux.Handle("/", webui.Handler(webui.FS())) // the interface (D-149): anything that is not the API; paths under /api/ other than the API's are its own 404
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

// serveUntilDone serves on ln (and on the sensor link, when there is one) and runs the scheduler until ctx is cancelled or a
// listener fails, then stops in order: sensor link, HTTP server, scheduler, return (the caller closes the database). The
// scheduler runs on a child context that is cancelled on every exit path, and the wait for it is bounded by
// stopWait so a job that ignores its context cannot hang the shutdown.
func serveUntilDone(ctx context.Context, log *slog.Logger, srv *http.Server, ln net.Listener, link *sensorLink, sched *jobs.Scheduler, stopWait time.Duration) error {
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
	linkErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.InfoContext(ctx, "listening", "addr", ln.Addr().String(), "version", version)
	if link != nil {
		go func() { linkErr <- link.serve() }()
		log.InfoContext(ctx, "sensor link listening", "addr", link.Addr())
		defer func() { _ = link.close() }() // the listener failing below must not leave the sensor link open
	}

	// A listener failing is shut down after exactly like a stop: the other listener and the scheduler are stopped in order, then the error is returned.
	var failure, serveRet error
	served := false // serveErr has been read
	select {
	case err := <-serveErr:
		failure, served = fmt.Errorf("serve: %w", err), true
	case err := <-linkErr:
		failure = fmt.Errorf("serve sensor link: %w", err)
	case <-ctx.Done():
	}
	if failure == nil {
		log.InfoContext(ctx, "shutting down")
	}
	if link != nil {
		_ = link.close()
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	shutdownErr := srv.Shutdown(sctx)
	// Shutdown closes only the listeners Serve has registered: when the other listener failed at once, the Serve goroutine may not
	// have started yet, and the kernel would keep accepting into ln's backlog. Close ln here and wait for Serve to return, so the
	// port is closed when this function returns, whatever the order.
	_ = ln.Close()
	if !served {
		serveRet = <-serveErr
	}
	stopSched()
	if failure != nil {
		return failure
	}
	if err := serveRet; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
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
