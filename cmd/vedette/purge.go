package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	hostapi "github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/core"
)

// What the factory reset (POST /core/data/purge, D-154) needs from the rest of the binary.

// purgeHost is vedette-host for the purge: nil on a box without a helper (no -host-socket), which skips the backups and says so.
func purgeHost(d *deps) core.PurgeHost {
	if d.HostSocket == "" {
		return nil
	}
	return hostPurger{hostclient.New(d.HostSocket)}
}

// hostPurger is the host client as core.PurgeHost: ListRuns comes from the client, BackupPurge (host command backup.purge, D-156) is
// the client's own, minus the run id. The client reports a run that failed as a plain error that names the code; the two codes the
// purge treats specially (transition_pending, busy) are turned back into a *client.Error so core maps them (412, 409) like a refusal
// at the door. core makes a fresh request id for every purge.
type hostPurger struct{ *hostclient.Client }

func (p hostPurger) BackupPurge(ctx context.Context, requestID, actor string) (int, error) {
	n, _, err := p.Client.BackupPurge(ctx, requestID, actor)
	return n, purgeRunError(err)
}

// purgeRunError gives a failed backup.purge run ("host: backup.purge failed: <code>") the typed error of its code, for the codes core
// maps. Any other error is returned as it is.
func purgeRunError(err error) error {
	var typed *hostclient.Error
	if err == nil || errors.As(err, &typed) {
		return err
	}
	for code, status := range map[string]int{hostapi.CodeTransitionPending: 412, hostapi.CodeBusy: 409} {
		if strings.HasSuffix(err.Error(), ": "+code) {
			return &hostclient.Error{Status: status, Code: code, Message: err.Error()}
		}
	}
	return err
}

// purgeBeforeWipe runs before anything is deleted (HandlersConfig.BeforeWipe): the honeypot is turned off through its own Disable path
// while its record of the decoy addresses it placed is still there, so those addresses leave the host (they would stay on the
// interface otherwise, and nothing would remove them after the record is gone). An error refuses the purge. Core does not touch the
// honeypot's raw log: the container owns it and core mounts it read-only (see purgeKeptRows).
func purgeBeforeWipe(d *deps) func(context.Context) error {
	return func(ctx context.Context) error {
		if d.Honeypot == nil {
			return nil
		}
		if err := d.Honeypot.Disable(ctx); err != nil {
			return fmt.Errorf("turn the honeypot off: %w", err)
		}
		return nil
	}
}

// purgeKeptRows and purgeAlsoKept: the honeypot's raw log (opencanary.jsonl under -honeypot-dir/log) stays, because the container owns it
// and core cannot write it (N2). To keep the fresh box from reading its old events as new, the row that holds the honeypot's read position
// in that log survives the wipe (hp_config "tail", the key modules/honeypot stores it under); the answer lists "honeypot_log" as kept.
// Without a honeypot directory there is no log and nothing to keep. The host is to empty the log at a purge once it runs the container
// (deferred: .ai/deferred/feat-core-data-purge.md).
func purgeKeptRows(d *deps) []core.KeepRow {
	if d.HoneypotDir == "" {
		return nil
	}
	return []core.KeepRow{{Table: "hp_config", Column: "key", Value: "tail"}}
}

func purgeAlsoKept(d *deps) []string {
	if d.HoneypotDir == "" {
		return nil
	}
	return []string{"honeypot_log"}
}
