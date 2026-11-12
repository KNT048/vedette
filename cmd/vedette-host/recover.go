package main

import (
	"context"
	"fmt"
	"io"

	"github.com/knt048/vedette/host/config"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server"
)

// vedette-host -recover-core-data [-use rollback|current] [-yes] (D-317, RUNBOOK 5.5): the way out of
// core_data_unrecoverable when core is not running. One shot, as root, never beside the daemon. Without -use it
// shows what is in core_data; with -use it shows what it would do; only -yes does it. The exits are the
// bootstrap's: 0 done (or nothing to do, or only shown), 1 failed, 2 wrong use, 3 refused by a check, 6 daemon_running.
// The one stderr line is "vedette-host: recover-core-data: <code>: <message>".

const recoverCmd = "recover-core-data"

func runRecover(ctx context.Context, cfg config.Config, use string, yes bool, stateDir, auditLog string, stdout io.Writer, env environment) error {
	fail := func(code int, errCode, msg string) *exitError { return newExitIn(recoverCmd, code, errCode, msg) }
	if !ops.RecoverUseValid(use) || (yes && use == "") {
		return fail(exitUsage, ops.BootstrapBadArgs, "-use is rollback or current, and -yes needs one of them")
	}
	// A running daemon owns the state directory and the journal: this is for a box where it is not. Its own
	// "already running" test is the live socket; the state lock below is the second layer.
	if server.SocketLive(ctx, cfg.Socket) {
		return fail(exitDaemonRunning, "daemon_running", "vedette-host is running; stop it first (systemctl stop vedette-host)")
	}
	sys, err := ops.New(opsConfig(cfg, stateDir, auditLog, env))
	if err != nil {
		return fail(exitFailed, ops.BootstrapFailed, "the host's state could not be opened: "+err.Error())
	}
	defer sys.Close()
	unlock, err := sys.LockState(ctx)
	if err != nil {
		return exitForIn(recoverCmd, ops.LockError(err))
	}
	defer unlock()
	if yes { // a report changes nothing, not even the audit log; a change that cannot be recorded is not made
		notes, err := server.OpenNoteWriter(auditLog, env.configOwner)
		if err != nil {
			return fail(exitFailed, ops.BootstrapFailed, "the audit log could not be opened: "+err.Error())
		}
		defer func() { _ = notes.Close() }()
		sys.AuditTo(notes)
	}
	say := func(s string) { _, _ = fmt.Fprintln(stdout, "vedette-host: "+recoverCmd+": "+s) }
	if err := sys.RecoverCoreData(ctx, ops.RecoverArgs{Use: use, Apply: yes, Where: cfg.CoreData}, say); err != nil {
		return exitForIn(recoverCmd, err)
	}
	return nil
}
