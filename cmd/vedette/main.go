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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/pdftext"
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
	if pdftextCommand(os.Args[1:]) { // the PDF reader child (D-264): its own limits, no signals, no database
		os.Exit(pdftext.ChildMain(os.Stdin, os.Stdout, os.Stderr))
	}
	pdftext.UseSelf() // this binary is the one that may serve as the PDF child (D-264); no other binary registers
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
	log             *slog.Logger // set by serve for transport (the box CA's log lines); nil in tests
	hostSocket      string
	honeypotDir     string
	// sensorListen and sensorCreds are the sensor link (D-141): the mutual-TLS listener of the two sensor containers and the directory
	// that holds their credentials, <creds>/<role>/sensor.pem. Empty sensorListen = no listener (a container-only install).
	sensorListen, sensorCreds string
	// syslogPort is the port the logs module listens on for syslog; 0 = 514, and 5514 when the process may not bind 514.
	syslogPort int
	// mcpListen is the loopback address of the read-only MCP server (mcp-server module, INV-5, D-230).
	mcpListen string
	// osqueryDir is the folder of the pinned osquery packages the agent-intake module serves (D-169 (10)); empty or missing = the mirror answers 404 mirror_missing.
	osqueryDir string
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
	flags.StringVar(&o.hostSocket, "host-socket", "/run/vedette/host.sock", "unix socket of vedette-host (operating system updates and backups); empty, or a missing socket file, means a container-only install and those endpoints answer 409 not_appliance (the data purge is stricter: with a socket path set, a missing socket refuses it with 502, because the helper holds backups, and so is the passive sensor: with a socket path set it takes the box's cards only from the helper and holds its batches until the helper answers; pass an empty value for a box without a helper). The database and key files must be <dir>/vedette.db and <dir>/vedette.key, where <dir> is the host's core_data")
	flags.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address to listen on; plain HTTP on loopback, TLS on any other address")
	flags.StringVar(&o.tlsCert, "tls-cert", "", "PEM certificate for TLS (with -tls-key); when both are missing and -listen is not loopback, a self-signed pair is made next to the database")
	flags.StringVar(&o.tlsKey, "tls-key", "", "PEM private key for TLS")
	flags.StringVar(&o.hosts, "hosts", "", "comma-separated host names (a leading *. covers one label, like a wildcard certificate) and IP addresses the box answers to (Host header allowlist, 421 for others); default: the loopback names and the names of the certificate")
	flags.StringVar(&o.sensorListen, "sensor-listen", "", "address of the sensor link, a mutual-TLS listener for the sensor and scan containers (D-109), e.g. :8444 inside the container (the unit publishes 127.0.0.1:8444 only); empty = none, and the sensors cannot reach core")
	flags.StringVar(&o.sensorCreds, "sensor-creds", "", "directory where core writes the sensors' credentials, <dir>/passive/sensor.pem and <dir>/active/sensor.pem (needed with -sensor-listen); each role's folder is a volume shared with that container only")
	flags.IntVar(&o.syslogPort, "syslog-port", 0, "port of the syslog listener of the logs module (UDP and TCP, only while the module is on and a source is declared); 0 = 514, or 5514 when this process may not bind 514")
	flags.StringVar(&o.mcpListen, "mcp-listen", "", "loopback address and port of the read-only MCP server, open only while the mcp-server module is on; an address off loopback is refused, except 0.0.0.0 inside a container. Empty = 127.0.0.1:8765, or 0.0.0.0:8765 inside a container, whose unit publishes it on the machine's 127.0.0.1 only (INV-5, D-230, D-395)")
	flags.StringVar(&o.osqueryDir, "osquery-dir", defaultOsqueryDir, "folder with the pinned osquery packages (.deb, .rpm, .msi and SHA256SUMS) that the agent-intake module serves to servers under /install/osquery/; the core image carries them, a build without the folder answers 404 mirror_missing")
	return flags, showVersion
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if kind, ok := healthCommand(args); ok { // the HealthCmd= of the units: before any flag, no database, no key
		return runHealthCommand(ctx, kind)
	}
	if resetAdminCommand(args) { // D-389: the console's way back in for a locked-out administrator
		return runResetAdmin(ctx, args[1:], stdout, stderr)
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
	if err := syslogPortClash(o); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	return serve(ctx, log, o)
}

// syslogPortClash refuses a -syslog-port whose plain port or TLS port (the plain port + 1) is one the process
// already serves on: -listen or -sensor-listen. 0 means 514 (TLS 6514) or 5514 (TLS 5515).
func syslogPortClash(o options) error {
	own := map[int]string{}
	for flag, addr := range map[string]string{"-listen": o.listen, "-sensor-listen": o.sensorListen} {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				own[n] = flag
			}
		}
	}
	ports := []int{514, 6514, 5514, 5515}
	if o.syslogPort != 0 {
		ports = []int{o.syslogPort, o.syslogPort + 1}
	}
	for _, p := range ports {
		if flag, ok := own[p]; ok {
			return fmt.Errorf("-syslog-port %d: port %d (the plain syslog port or the TLS port, which is the plain port + 1) is already used by %s", o.syslogPort, p, flag)
		}
	}
	return nil
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
// no HSTS, or a browser would refuse to let the owner click through its warning for a year. The box's own pair is signed by the box
// CA that ca keeps in core_secret (D-351), so transport runs once the database is open and migrated.
//
// The box's own pair also covers the box's name (certBoxName of box: the OS host name vedette-host reports, core's own host name
// without a host); links never take a name from the certificate (they carry the Box address, D-465, boxaddr.go), and the renewer adds
// the Box address to the certificate once it is known (selfSignedRenewer.Check). Without -hosts the allowlist is the names
// of the box's own pair that pass defaultAllowed (an address, one label, or .local/.lan/.home.arpa/.internal), the box's name among
// them when it passes: the name may come from DHCP, so a name in a public domain is answered to only through -hosts. It is asked once here (at most boxNameTimeout): vedette-host
// starts before core, so the name is normally known at the first start and on every later one. It only ever adds to the names of
// before (localNames keeps "vedette", the addresses stay), so no name that opened the box before stops working. A box whose
// certificate lacks it (an upgraded box) gets it at the renewer's first Check, right after start; one whose host does not answer
// now gets it in the certificate once the host answers (Check), and in the allowlist at the next start.
// ponytail: the allowlist's names are fixed for the life of the process, as they always were (core/server.HostAllowlistWith);
// a name learned later waits for a restart. Upgrade path: a matcher that also asks certBoxName's cached answer.
func transport(ctx context.Context, o options, ca *boxCAStore, box *boxHostName) (cfg *tls.Config, hosts []string, hsts bool, renew *selfSignedRenewer, err error) {
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
	var name string // the box's name, for its own pair only (an owner's certificate says which names it covers)
	if certPath == "" {
		dir := filepath.Dir(o.db)
		certPath, keyPath = filepath.Join(dir, "vedette-selfsigned.crt"), filepath.Join(dir, "vedette-selfsigned.key")
		certHosts := hosts
		if name = certBoxName(ctx, box); name != "" {
			certHosts = append(append(slices.Clone(hosts), localNames()...), name)
		}
		if err := ensureCertAt(ctx, ca, certPath, keyPath, certHosts, time.Now, o.log); err != nil {
			return nil, nil, false, nil, err
		}
	}
	cfg, names, err := loadTLS(certPath, keyPath)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if o.tlsCert == "" { // the box's own pair: serve it through GetCertificate so a renewal needs no restart
		renew = &selfSignedRenewer{certPath: certPath, keyPath: keyPath, hosts: flagHosts, ca: ca, now: time.Now, cert: &cfg.Certificates[0], kick: make(chan struct{}, 1),
			box: func(ctx context.Context) string { return certBoxName(ctx, box) }}
		cfg.Certificates, cfg.GetCertificate = nil, renew.GetCertificate
	}
	switch {
	case len(hosts) > 0: // -hosts: exactly those
	case o.tlsCert != "":
		hosts = names // an owner's certificate: the names the owner put in it
	default: // the box's own: only names no one outside can own (defaultAllowed, DNS rebinding); others need -hosts
		hosts = slices.DeleteFunc(names, func(h string) bool { return !defaultAllowed(h) })
		if name != "" && defaultAllowed(name) && !slices.Contains(hosts, name) { // an upgraded box: the first Check adds it to the certificate
			hosts = append(hosts, name)
		}
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
	tightenContainerDataDir(o.db, o.sensorCreds, log)
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
	o.log = log
	db, err := store.Open(ctx, o.db, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.ErrorContext(ctx, "closing the database failed", "error", err)
		}
	}()
	// A damaged database stops the program before anything writes to it (fail closed, INV-32). Only an update whose release says
	// rollback.safe=false gets its database back from the snapshot when the health check fails (host/ops update.go); otherwise the box
	// stays down until someone restores a backup (RUNBOOK). A newer schema is not refused: an older core runs on a newer database by design (INV-26, D-183).
	if err := db.QuickCheck(ctx); err != nil {
		log.ErrorContext(ctx, "the database failed SQLite's check; not starting", "error", err)
		return err
	}
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
	// TLS comes after the database (D-351): the box CA that signs the self-made leaf is a core_secret row.
	boxCAs, err := newBoxCAStore(db, sec, aud, filepath.Dir(o.db))
	if err != nil {
		return err
	}
	if err := boxCAs.migrateLegacy(ctx, log); err != nil { // whatever the TLS mode: no plaintext CA key stays on disk (D-351)
		log.WarnContext(ctx, "the old box CA files could not be moved into the database; tried again at the next start", "error", err)
	}
	boxName := newBoxHostName(o.hostSocket) // before TLS: the box's own certificate carries its name
	tlsCfg, hosts, hsts, renew, err := transport(ctx, o, boxCAs, boxName)
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
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: version, Log: log, ContainerOnly: o.hostSocket == ""}) // D-381: the install kind, from the one flag compose sets empty (D-168)
	if err != nil {
		return err
	}
	sched := jobs.New(log, reg, nil, jobs.WithRecorder(jobs.NewHistory(db))) // before the services: deps.Wake hands them sched.Wake
	d := deps{Log: log, DB: db, LogsDB: logsDB, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now, Bus: events.NewBus(log), Hosts: hosts, CertKick: func() { renew.Kick(); warner.Kick() }, Wake: sched.Wake,
		HostSocket: o.hostSocket, HostNet: newHostNetCache(hostSocketNet(o.hostSocket, log), time.Now), BoxName: boxName, DataDir: filepath.Dir(o.db), KeyPath: o.key, HoneypotDir: o.honeypotDir,
		Restart: func() {
			log.InfoContext(ctx, "the data was purged: stopping so the supervisor starts a fresh box")
			cancel()
		}}
	d.SyslogPort = o.syslogPort // before buildServices: the logs service reads it when it is built
	d.SyslogTLS = syslogTLS(tlsCfg)
	flagHosts, _ := parseHosts(o.hosts)                      // checked at the start of run
	wireBoxAddr(&d, o.hostSocket != "", flagHosts, o.listen) //nolint:contextcheck // links are made with no context (notify, response); Host bounds each read (boxAddrTimeout)
	if renew != nil {
		renew.addrs = d.BoxAddr.Names
	}
	d.SelfSigned = renew != nil                                   // the Box network page says who must put the Box address in the certificate
	listed := server.HostMatcher(hosts, boxOwnAddress(d.HostNet)) //nolint:contextcheck // the Host check runs per request, with no context to pass
	hostAllowed := func(h string) bool { return listed(h) || d.BoxAddr.Allows(h) }
	d.TrustAnchor, d.HostAllowed, d.OsqueryDir = trustAnchor(o, intakeTrustAnchor(tlsCfg, boxCAs, renew)), hostAllowed, o.osqueryDir //nolint:contextcheck // agent-intake reads them when it is built; the Host check runs per request, with no context to pass
	d.MCPInContainer = inContainer()
	if d.MCPListen, err = parseMCPListen(o.mcpListen, d.MCPInContainer); err != nil {
		return err
	}
	if err := buildServices(ctx, &d); err != nil {
		return err
	}
	d.BoxAddr.Invalidate() //nolint:contextcheck // one bounded read (boxAddrTimeout) before the listener serves: a saved name is answered to from the first request (review L2)
	defer d.OS.Close()
	defer d.Response.Close()         // ends the approval requests still being sent before the database closes
	defer exposureService(d).Close() // INV-18: the run that runs ends with its audit row before the database closes
	exposureAtStart(ctx, d)          // OpenVAS enabled before this start runs again (D-529)
	defer scanService(d).Close()     // stop a live scan and wait for it before the database closes (scan review M4)
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
	stopGuards := func() {}
	defer func() { stopGuards() }()
	if err := startMCP(ctx, d); err != nil { // the port is open exactly while the module is on (POST-1)
		return err
	}
	stopGuards = startGuards(ctx, reg, log, d, wired)
	perMinute := publicPerMinute(o.hostSocket)
	log.InfoContext(ctx, "per-address limit of public requests without a session (D-320)", "per_minute", perMinute, "on", perMinute > 0)
	api, err := server.New(server.Config{
		API:             newHandler(ctx, d),
		Auth:            d.Auth.Sessions,
		Modules:         reg,
		Log:             log,
		BodyLimits:      bodyLimits(wired),
		PublicPerMinute: perMinute, // D-320
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           topHandler(log, api, honeyTokenHandler(log, d.Honeypot, server.NewAddrLimiter(honeyTokenPerMinute, nil), honeyTokenSources{machine: machineAddrs(&d), appliance: perMinute > 0}), hostAllowed, hsts),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(newHandshakeNoise(log.Handler()), slog.LevelWarn),
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

// topHandler is everything the listener answers. A Host header allowed refuses is 421 before anything else is routed (DNS rebinding):
// allowed is server.HostMatcher of the allowlist and the box's own addresses, plus the Box address (D-465). The Envelope (panic
// recovery, request id, security headers) wraps the ServeMux too, so the mux's own answers (307 for /api/v1, //, .. and the 404 for
// other paths) carry the headers the API's responses do. token answers /t/<id>, the link of a URL honey token (D-507); nil leaves the
// path to the interface.
func topHandler(log *slog.Logger, api, token http.Handler, allowed func(host string) bool, hsts bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(server.Prefix+"/", api)
	if token != nil {
		mux.Handle(urlTrapPath, token)
		mux.Handle(urlTrapDeeper, token)
	}
	mux.Handle("/", webui.Handler(webui.FS())) // the interface (D-149): anything that is not the API; paths under /api/ other than the API's are its own 404
	h := server.HostAllowlistFunc(allowed, mux)
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

// containerDataDir is the data directory of every container image and of the appliance (the -db and -key defaults live in it).
const containerDataDir = "/var/lib/vedette"

// containerCredsDir is the -sensor-creds of the images and the appliance; its passive/ and active/ folders are the two creds volumes.
const containerCredsDir = "/var/lib/vedette-creds" //nolint:gosec // G101: a directory path, not a credential

// tightenContainerDataDir is the call of serve: only the data directory of the images and, with the sensor link, the two role folders
// of the credentials directory (the creds-* volumes, which hold the 0640 credential files; D-409), only when core is not root. The
// sensors read their folder through the group (0750 keeps it), never through "other". The credentials directory itself is left 0755:
// it holds only the two mount points, and on the appliance core (core_uid, not its owner 65532) must traverse it.
func tightenContainerDataDir(db, creds string, log *slog.Logger) {
	uid := os.Geteuid()
	tightenDataDir(filepath.Dir(db), containerDataDir, uid, log)
	if creds == "" {
		return
	}
	for _, sub := range []string{"passive", "active"} {
		tightenDataDir(filepath.Join(creds, sub), filepath.Join(containerCredsDir, sub), uid, log)
	}
}

// tightenDataDir removes group-write and any "other" access (mode bits 0o027) from dataDir when dir is exactly dataDir, is a real
// directory (a symlink is left alone) and is owned by uid, which must not be root. A new named volume may start 0755 (rootless
// Podman, and images built before D-409, whose COPY --chmod left the image directory 0755 on buildah) while the image directory is
// 0750. It only clears those bits (0700 stays 0700; setuid, setgid and sticky are kept), never touches any other directory (a dev
// -db path, /tmp, $HOME), and a failure is logged, not fatal: the key and database files are 0600 either way.
func tightenDataDir(dir, dataDir string, uid int, log *slog.Logger) {
	if dir != dataDir || uid == 0 {
		return
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid {
		return
	}
	perm := fi.Mode().Perm()
	want := perm &^ 0o027
	if want == perm {
		return
	}
	special := fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if err := os.Chmod(dir, special|want); err != nil {
		log.Warn("directory is wider than 0750 and could not be tightened", "dir", dir, "mode", perm.String(), "err", err)
		return
	}
	log.Info("directory tightened", "dir", dir, "was", perm.String(), "now", want.String())
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

// publicPerMinute is the per-address limit of public requests (D-320): on an appliance (vedette-host's socket is there) core sees each
// client's own address; a container-only install may see every client as the port proxy's one address (Docker Desktop, rootless),
// where a per-address limit would be one limit for the whole box, so it is off there.
func publicPerMinute(hostSocket string) int {
	if hostSocket == "" {
		return 0
	}
	if fi, err := os.Stat(hostSocket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return 0
	}
	return server.PublicPerMinuteDefault
}
