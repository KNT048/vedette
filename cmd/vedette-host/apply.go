package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/knt048/vedette/host/ops"
)

// vedette-host -self-update-apply rn_<16 hex> (D-316, docs/specs/host-api.md section 6.14): the applier of
// host.self_update. systemd-run starts it as vedette-host-upgrade.service, outside the host's cgroup, from the
// copy <state>/selfupdate/applier of the binary that was running; the state directory is the one that copy
// lives in, never a flag. It reads no host.conf, opens no socket, takes no host.lock and never writes the audit
// chain: its phases go to the journal, which the host reads and settles.

var applyRunIDRE = regexp.MustCompile(`^rn_[0-9a-f]{16}$`)

func runApply(ctx context.Context, runID string, env environment) error {
	if !applyRunIDRE.MatchString(runID) {
		return fmt.Errorf("-self-update-apply: %q is not a run id", runID)
	}
	exe, err := env.executable()
	if err != nil {
		return err
	}
	stateDir, err := applierStateDir(exe)
	if err != nil {
		return err
	}
	return ops.Apply(ctx, ops.ApplyConfig{StateDir: stateDir, RunID: runID, Logger: env.logger})
}

// applierStateDir is <state> for an applier at <state>/selfupdate/applier; anything else is refused, so the
// installed /usr/lib/vedette/vedette-host can never act as the applier.
func applierStateDir(exe string) (string, error) {
	if !filepath.IsAbs(exe) || filepath.Base(exe) != "applier" || filepath.Base(filepath.Dir(exe)) != "selfupdate" {
		return "", errors.New("-self-update-apply runs only as <state>/selfupdate/applier")
	}
	return filepath.Dir(filepath.Dir(exe)), nil
}
