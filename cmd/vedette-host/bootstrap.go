package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/knt048/vedette/host/config"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server"
)

// vedette-host -bootstrap (D-142): the first install, one shot, from the installer, as root. It never
// listens and is not reachable through the socket. The installer reads the exit code and the one line
// on stderr ("vedette-host: bootstrap: <code>: <message>"); nothing secret is ever printed.
//
// Exit codes: 0 done (or nothing to do), 1 failed, 2 wrong use, 3 refused by a check of the release or
// of the machine (the code on stderr says which), 4 already_installed, 5 unit_foreign or unit_unsafe,
// 6 daemon_running.
const (
	exitFailed           = 1
	exitUsage            = 2
	exitRefused          = 3
	exitAlreadyInstalled = 4
	exitUnit             = 5
	exitDaemonRunning    = 6
)

// exitError is an error with the exit code and the one stderr line of the bootstrap.
type exitError struct {
	code int
	line string
}

func (e *exitError) Error() string { return e.line }

func newExit(code int, errCode, msg string) *exitError {
	msg = strings.Join(strings.Fields(msg), " ") // one line, whatever the message holds
	return &exitError{code: code, line: "vedette-host: bootstrap: " + errCode + ": " + msg}
}

// bootFlags are the flags that only -bootstrap takes.
type bootFlags struct {
	index, indexSig, manifest, manifestSig string
	services                               string
	forceUnits                             bool
}

func (b bootFlags) given() bool {
	return b.index != "" || b.indexSig != "" || b.manifest != "" || b.manifestSig != "" || b.services != "" || b.forceUnits
}

// exitFor maps an error of the bootstrap to its exit.
func exitFor(err error) *exitError {
	code, msg := ops.BootstrapCode(err)
	switch code {
	case ops.BootstrapAlreadyInstalled:
		return newExit(exitAlreadyInstalled, code, msg)
	case ops.BootstrapUnitForeign, "unit_unsafe":
		return newExit(exitUnit, code, msg)
	case ops.BootstrapBadArgs:
		return newExit(exitUsage, code, msg)
	case ops.BootstrapFailed:
		return newExit(exitFailed, code, msg)
	}
	var rf *server.Refusal
	if errors.As(err, &rf) {
		return newExit(exitRefused, code, msg)
	}
	return newExit(exitFailed, code, msg)
}

func runBootstrap(ctx context.Context, cfg config.Config, f bootFlags, stateDir string, stdout io.Writer, env environment) error {
	if f.index == "" || f.indexSig == "" || f.manifest == "" || f.manifestSig == "" {
		return newExit(exitUsage, ops.BootstrapBadArgs, "-index, -index-sig, -manifest and -manifest-sig are all required")
	}
	// A running daemon owns the state directory and the units: the bootstrap is for a box that has none.
	// The daemon's own "already running" test is the live socket.
	if server.SocketLive(ctx, cfg.Socket) {
		return newExit(exitDaemonRunning, "daemon_running", "vedette-host is running; the bootstrap is for a box where it is not (stop it, or use container.pull and container.start)")
	}
	docLimit, sigLimit := ops.BootstrapDocLimits()
	var a ops.BootstrapArgs
	for _, d := range []struct {
		path  string
		limit int64
		dst   *[]byte
		name  string
	}{
		{f.index, docLimit, &a.Index, "-index"}, {f.indexSig, sigLimit, &a.IndexSig, "-index-sig"},
		{f.manifest, docLimit, &a.Manifest, "-manifest"}, {f.manifestSig, sigLimit, &a.ManifestSig, "-manifest-sig"},
	} {
		b, err := ops.ReadBootstrapFile(d.path, d.limit)
		if err != nil || len(b) == 0 {
			return newExit(exitUsage, ops.BootstrapBadArgs, d.name+" is not a non-empty regular file within its size limit")
		}
		*d.dst = b
	}
	a.Services, a.ForceUnits = ops.SplitServices(f.services), f.forceUnits

	sys, err := ops.New(opsConfig(cfg, stateDir, env))
	if err != nil {
		return newExit(exitFailed, ops.BootstrapFailed, "the host's state could not be opened: "+err.Error())
	}
	defer sys.Close()
	if err := sys.Bootstrap(ctx, a, func(s string) { _, _ = fmt.Fprintln(stdout, "vedette-host: bootstrap: "+s) }); err != nil {
		return exitFor(err)
	}
	return nil
}

func opsConfig(cfg config.Config, stateDir string, env environment) ops.Config {
	return ops.Config{
		StateDir: stateDir, CoreData: cfg.CoreData, CoreUnit: cfg.CoreUnit, Version: version,
		CoreUID: cfg.CoreUID, CoreGID: cfg.CoreGID, SensorUID: cfg.SensorUID, SensorGID: cfg.SensorGID, OwnerUID: env.configOwner, Logger: env.logger,
	}
}
