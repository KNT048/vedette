// Command vedette-host is the small root helper on the appliance host (D-55): OS updates, box
// network, signed image pulls, container start and rollback, backups. It serves a fixed command
// list on a local unix socket (docs/specs/host-api.md) to one client, core.
//
// OS assumption: Linux, as root. The peer authentication needs SO_PEERCRED and /proc, and the
// process refuses to start anywhere else (fail closed).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/knt048/vedette/host/config"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
)

// version is set at build time: -ldflags "-X main.version=0.1.0" (SemVer without a leading v, like core and vedette-sensor).
var version = "dev"

const shutdownGrace = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("module", "host")
	if err := run(ctx, os.Args[1:], os.Stdout, realEnvironment(logger)); err != nil {
		var ee *exitError
		if errors.As(err, &ee) { // the bootstrap: one line, an exit code the installer reads
			fmt.Fprintln(os.Stderr, ee.line)
			os.Exit(ee.code)
		}
		logger.Error("vedette-host stopped", "error", err.Error())
		fmt.Fprintln(os.Stderr, "vedette-host:", err)
		os.Exit(1)
	}
}

// environment is what run needs from the machine; tests replace it.
type environment struct {
	goos        string
	euid        int
	configOwner int // the uid that must own host.conf (0 in production)
	newChecker  func(coreUID int, unit, cgroup string) (peer.Checker, error)
	logger      *slog.Logger
}

func realEnvironment(logger *slog.Logger) environment {
	return environment{goos: runtime.GOOS, euid: os.Geteuid(), configOwner: 0, newChecker: peer.New, logger: logger}
}

func run(ctx context.Context, args []string, stdout io.Writer, env environment) error {
	fs := flag.NewFlagSet("vedette-host", flag.ContinueOnError)
	fs.SetOutput(stdout)
	showVersion := fs.Bool("version", false, "print the version and exit")
	confPath := fs.String("config", "/etc/vedette/host.conf", "path of the host config written by the installer")
	socket := fs.String("socket", "", "socket path (default: the socket line of the config)")
	stateDir := fs.String("state-dir", "/var/lib/vedette-host", "directory for runs and idempotency records")
	auditLog := fs.String("audit-log", "/var/log/vedette-host/audit.jsonl", "append-only audit log")
	bootstrap := fs.Bool("bootstrap", false, "first install: verify a signed release, pull its images and write the first units, then exit (needs the four documents below; refuses while the daemon runs)")
	var bf bootFlags
	fs.StringVar(&bf.index, "index", "", "-bootstrap: index.json")
	fs.StringVar(&bf.indexSig, "index-sig", "", "-bootstrap: index.json.minisig")
	fs.StringVar(&bf.manifest, "manifest", "", "-bootstrap: release-manifest.json (its image signatures are inside it)")
	fs.StringVar(&bf.manifestSig, "manifest-sig", "", "-bootstrap: release-manifest.json.minisig")
	fs.StringVar(&bf.services, "services", "", "-bootstrap: comma-separated services to install (default core,sensor,scan,honeypot)")
	fs.BoolVar(&bf.forceUnits, "force-units", false, "-bootstrap: replace a unit this host did not write (each file replaced is reported; the old bytes are kept)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !*bootstrap && bf.given() {
		return errors.New("-index, -index-sig, -manifest, -manifest-sig, -services and -force-units belong to -bootstrap")
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if env.goos != "linux" {
		return fmt.Errorf("refusing to start on %s: vedette-host runs only on Linux", env.goos)
	}
	if env.euid != 0 {
		return errors.New("refusing to start: vedette-host must run as root")
	}
	cfg, err := config.Load(*confPath, env.configOwner)
	if err != nil {
		return err
	}
	if *socket != "" {
		if err := config.ValidSocketPath(*socket); err != nil {
			return fmt.Errorf("-socket: %w", err)
		}
		cfg.Socket = *socket
	}
	if *bootstrap {
		return runBootstrap(ctx, cfg, bf, *stateDir, *auditLog, stdout, env)
	}
	check, err := env.newChecker(cfg.CoreUID, cfg.CoreUnit, cfg.CoreCgroup)
	if err != nil {
		return err
	}
	// The system commands (docs/specs/host-api.md section 6) live in host/ops. This is the one
	// place the registry is built: a closed list, frozen here.
	sys, err := ops.New(opsConfig(cfg, *stateDir, *auditLog, env))
	if err != nil {
		return err
	}
	defer sys.Close()
	// One daemon per state directory, and no bootstrap beside it (D-142): the lock lives as long as the process.
	unlock, err := sys.LockState()
	if err != nil {
		return fmt.Errorf("another vedette-host holds %s: %w", *stateDir, err)
	}
	defer unlock()
	registry, err := server.NewRegistry(sys.Commands()...)
	if err != nil {
		return err
	}
	srv, err := server.New(server.Options{
		SocketPath: cfg.Socket, SocketGID: cfg.SocketGID, StateDir: *stateDir, AuditPath: *auditLog, OwnerUID: env.configOwner,
		Registry: registry, Readers: sys.Readers(), WriteGate: sys.WriteGate, Resume: sys.Resume, PeerCheck: check, Version: version, Logger: env.logger,
	})
	if err != nil {
		return err
	}
	if aerr := srv.AuditError(); aerr != nil {
		env.logger.ErrorContext(ctx, "the audit chain does not verify: write commands are refused until a person repairs it", "error", aerr.Error())
	}
	// Before listening: notice a reboot the host started, re-arm the scheduled reboot, recover an
	// interrupted restore, sweep old exports. Lines the host writes on its own go to the audit chain.
	sys.Start(ctx, srv)
	ln, err := srv.Listen(ctx)
	if err != nil {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return errors.Join(err, srv.Shutdown(sctx))
	}
	env.logger.InfoContext(ctx, "listening", "socket", cfg.Socket, "version", version)
	// The namespace of the honeypot is ready, the decoys are back and the socket exists: say so.
	if err := notifyReady(); err != nil {
		env.logger.ErrorContext(ctx, "could not tell systemd that the host is ready", "error", err.Error())
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	// Only now, with the host active, can a unit that is After=vedette-host.service be restarted
	// synchronously: put the services of an interrupted unit change back in the state they had (D-123).
	go sys.AfterReady(ctx, srv)
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	env.logger.InfoContext(ctx, "shutting down")
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	return errors.Join(srv.Shutdown(sctx), <-serveErr)
}
