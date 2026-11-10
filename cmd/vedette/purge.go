package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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

// hostPurger adds backup.purge to the host client. The command is D-156 and its client method is on another branch
// (feat/host-backup-purge); until that merges the purge refuses on a box that has a helper, because the helper's backups cannot be
// deleted and "delete all data" must not leave them: the answer is 503 host_unreachable and nothing is deleted.
// Replace this method with the client's own BackupPurge when it lands (.ai/deferred/feat-core-data-purge.md).
type hostPurger struct{ *hostclient.Client }

func (hostPurger) BackupPurge(context.Context, string, string) (int, error) {
	return 0, fmt.Errorf("%w: the host client has no backup.purge yet (D-156)", hostclient.ErrUnreachable)
}

// openCanaryLog is the file the honeypot container writes and the honeypot module tails (modules/honeypot defaultLogFile).
const openCanaryLog = "opencanary.jsonl"

// purgeBeforeWipe runs before anything is deleted (HandlersConfig.BeforeWipe): the honeypot is turned off through its own Disable path
// while its record of the decoy addresses it placed is still there, so those addresses leave the host (they would stay on the
// interface otherwise, and nothing would remove them after the record is gone), and the OpenCanary log is emptied so the old hits are
// never read again. An error refuses the purge.
func purgeBeforeWipe(d *deps) func(context.Context) error {
	return func(ctx context.Context) error {
		if d.Honeypot != nil {
			if err := d.Honeypot.Disable(ctx); err != nil {
				return fmt.Errorf("turn the honeypot off: %w", err)
			}
		}
		if d.HoneypotDir == "" {
			return nil
		}
		log := filepath.Join(d.HoneypotDir, HoneypotLogDir, openCanaryLog)
		if err := os.Truncate(log, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("empty the honeypot log: %w", err)
		}
		return nil
	}
}
