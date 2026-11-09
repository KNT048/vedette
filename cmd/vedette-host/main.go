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
	"github.com/knt048/vedette/host/peer"
	"github.com/knt048/vedette/host/server"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const shutdownGrace = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("module", "host")
	if err := run(ctx, os.Args[1:], os.Stdout, realEnvironment(logger)); err != nil {
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
	registry    *server.Registry
	logger      *slog.Logger
}

func realEnvironment(logger *slog.Logger) environment {
	return environment{goos: runtime.GOOS, euid: os.Geteuid(), configOwner: 0, newChecker: peer.New, registry: server.DefaultRegistry(), logger: logger}
}

func run(ctx context.Context, args []string, stdout io.Writer, env environment) error {
	fs := flag.NewFlagSet("vedette-host", flag.ContinueOnError)
	fs.SetOutput(stdout)
	showVersion := fs.Bool("version", false, "print the version and exit")
	confPath := fs.String("config", "/etc/vedette/host.conf", "path of the host config written by the installer")
	socket := fs.String("socket", "", "socket path (default: the socket line of the config)")
	stateDir := fs.String("state-dir", "/var/lib/vedette-host", "directory for runs and idempotency records")
	auditLog := fs.String("audit-log", "/var/log/vedette-host/audit.jsonl", "append-only audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
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
	check, err := env.newChecker(cfg.CoreUID, cfg.CoreUnit, cfg.CoreCgroup)
	if err != nil {
		return err
	}
	srv, err := server.New(server.Options{
		SocketPath: cfg.Socket, SocketGID: cfg.SocketGID, StateDir: *stateDir, AuditPath: *auditLog, OwnerUID: env.configOwner,
		Registry: env.registry, PeerCheck: check, Version: version, Logger: env.logger,
	})
	if err != nil {
		return err
	}
	if aerr := srv.AuditError(); aerr != nil {
		env.logger.ErrorContext(ctx, "the audit chain does not verify: write commands are refused until a person repairs it", "error", aerr.Error())
	}
	ln, err := srv.Listen(ctx)
	if err != nil {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return errors.Join(err, srv.Shutdown(sctx))
	}
	env.logger.InfoContext(ctx, "listening", "socket", cfg.Socket, "version", version)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
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
