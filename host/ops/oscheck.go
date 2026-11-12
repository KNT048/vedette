package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

const (
	snapshotMaxAge = 24 * time.Hour
	minDiskFree    = 1 << 30 // free space on /var before an install (spec 6.2)
)

func (o *Ops) snapshotPath() string { return o.stateFile("os", "snapshot.json") }

func (o *Ops) loadSnapshot() (api.OSState, error) {
	var s api.OSState
	err := readJSONFile(o.snapshotPath(), &s)
	return s, err
}

// cmdOSCheck is os.check (spec 6.1).
func (o *Ops) cmdOSCheck() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdOSCheck, Write: true, Timeout: 5 * time.Minute,
		Check: func(context.Context, struct{}) error {
			if _, err := o.platform(); err != nil {
				return err
			}
			if o.dpkgLocked() {
				return lockedRefusal()
			}
			return nil
		},
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			st, err := o.checkOS(ctx, rc)
			if err != nil {
				return nil, err
			}
			return st, nil
		},
	})
}

// checkOS is the work of os.check, shared with os.install: update the apt index, simulate an
// upgrade, read the reboot flag, store the snapshot.
func (o *Ops) checkOS(ctx context.Context, rc *server.RunContext) (api.OSState, error) {
	plat, err := o.platform()
	if err != nil {
		return api.OSState{}, err
	}
	if o.dpkgLocked() {
		return api.OSState{}, lockedRefusal()
	}
	rc.Log("Updating the package index")
	res, code, err := o.exec(ctx, binAptGet, argsUpdate...)
	logOutput(rc, res.Stdout)
	if err != nil {
		return api.OSState{}, err
	}
	if code != 0 {
		return api.OSState{}, fail(api.CodeAptFailed, fmt.Sprintf("apt-get update failed (exit %d).", code))
	}
	rc.Progress(40)
	return o.refreshSnapshot(ctx, rc, plat, ParseUpdateHosts(res.Stdout), true)
}

// simulate runs the simulated upgrade and parses it.
func (o *Ops) simulate(ctx context.Context) (Simulation, error) {
	res, code, err := o.exec(ctx, binAptGet, argsSimulate...)
	if err != nil {
		return Simulation{}, err
	}
	if code != 0 {
		return Simulation{}, fail(api.CodeAptFailed, fmt.Sprintf("apt-get could not compute the upgrade (exit %d).", code))
	}
	return ParseSimulation(res.Stdout), nil
}

// refreshSnapshot simulates the upgrade, reads reboot and auto-update state and stores the result.
// hosts is the mirror list seen by apt-get update; nil keeps the previous list.
func (o *Ops) refreshSnapshot(ctx context.Context, rc *server.RunContext, plat platform, hosts []string, checked bool) (api.OSState, error) {
	rc.Log("Computing the upgrade")
	sim, err := o.simulate(ctx)
	if err != nil {
		return api.OSState{}, err
	}
	rc.Progress(80)
	return o.storeSnapshot(ctx, plat, sim, hosts, checked)
}

func (o *Ops) storeSnapshot(ctx context.Context, plat platform, sim Simulation, hosts []string, checked bool) (api.OSState, error) {
	prev, _ := o.loadSnapshot()
	now := o.d.Now().UTC().Truncate(time.Second)
	last := prev.LastCheck
	if checked {
		last = now
	}
	if hosts == nil {
		hosts = prev.OS.Mirrors
	}
	if hosts == nil {
		hosts = []string{}
	}
	pending := make([]api.OSPackage, 0, len(sim.Upgrades))
	sec := 0
	for _, u := range sim.Upgrades {
		if u.Security {
			sec++
		}
		pending = append(pending, api.OSPackage{Name: u.Name, Current: u.From, New: u.To, Security: u.Security, Origin: u.Origin, CVEs: []string{}})
	}
	req, reasons := o.rebootInfo()
	var ext *string
	if plat.Support.Extended != "" {
		e := plat.Support.Extended
		ext = &e
	}
	st := api.OSState{
		OS: api.OSDetails{
			Distro: plat.Distro, Name: plat.Name, Release: plat.Release, Kernel: o.kernelRelease(),
			SupportEnd: plat.Support.End, ExtendedEnd: ext, BootedAt: o.bootedAt(), LastCheck: last, Mirrors: hosts,
		},
		Pending: pending, SecurityCount: sec, RebootRequired: req, RebootReasons: reasons,
		AutoSecurity: o.autoSecurityOn(ctx), LastCheck: last,
	}
	st.RebootScheduledAt = o.scheduledAt()
	if err := writeJSONAtomic(o.snapshotPath(), st); err != nil {
		return api.OSState{}, err
	}
	return st, nil
}

// autoSecurityOn reads the effective apt configuration; unreadable means off.
func (o *Ops) autoSecurityOn(ctx context.Context) bool {
	res, code, err := o.exec(ctx, binAptConfig, "dump")
	return err == nil && code == 0 && ParseAptConfig(res.Stdout).Enabled()
}

// readOS is GET /v1/state/os: the stored snapshot with the live reboot state laid over it.
func (o *Ops) readOS(ctx context.Context) (any, error) {
	st, err := o.loadSnapshot()
	if errors.Is(err, os.ErrNotExist) {
		return nil, server.NewReadError(404, api.CodeNoCheckYet, "os.check has not run yet.")
	}
	if err != nil {
		return nil, fmt.Errorf("read os snapshot: %w", err)
	}
	st.RebootRequired, st.RebootReasons = o.rebootInfo()
	st.RebootScheduledAt = o.scheduledAt()
	st.OS.BootedAt = o.bootedAt()
	st.AutoSecurity = o.autoSecurityOn(ctx)
	return st, nil
}

// cmdOSInstall is os.install (spec 6.2).
func (o *Ops) cmdOSInstall() server.Command {
	return server.Define(server.Spec[api.OSInstallArgs]{
		Name: api.CmdOSInstall, Write: true, Timeout: 60 * time.Minute,
		Validate: func(a *api.OSInstallArgs) error {
			if a.Scope != "security" && a.Scope != "all" {
				return server.Invalid("scope", "must be security or all")
			}
			if !hexIDRE.MatchString(a.Snapshot) {
				return server.Invalid("snapshot", "must be the 32 lowercase hex characters of a snapshot core wrote")
			}
			return nil
		},
		Check: func(ctx context.Context, a api.OSInstallArgs) error {
			if _, err := o.platform(); err != nil {
				return err
			}
			if err := o.coreFree(); err != nil { // the pre_os_update backup is a backup of core: same rule as backup.create (D-157)
				return err
			}
			if o.dpkgLocked() {
				return lockedRefusal()
			}
			res, code, err := o.exec(ctx, binDpkg, "--audit")
			if err != nil {
				return err
			}
			if code != 0 || len(strings.TrimSpace(string(res.Stdout))) > 0 {
				return refuse412(api.CodeDpkgInconsistent, "dpkg --audit reports packages in a broken state; fix them before installing updates.")
			}
			free, err := o.d.FreeBytes(o.path("var"))
			if err != nil {
				return err
			}
			if free < minDiskFree {
				return refuse412(api.CodeLowDisk, "Less than 1 GiB is free on /var.")
			}
			// The backup before the install needs a snapshot from core; refuse now rather than
			// after the package index was refreshed.
			return o.backupPreflight(a.Snapshot, true, true)
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.OSInstallArgs) (any, error) {
			return o.installOS(ctx, rc, a.Scope, a.Snapshot)
		},
	})
}

func (o *Ops) installOS(ctx context.Context, rc *server.RunContext, scope, snapshot string) (any, error) {
	plat, err := o.platform()
	if err != nil {
		return nil, err
	}
	o.installing.Store(true)
	defer o.installing.Store(false)

	snap, serr := o.loadSnapshot()
	if serr != nil || o.d.Now().Sub(snap.LastCheck) >= snapshotMaxAge || snap.LastCheck.After(o.d.Now().Add(time.Hour)) {
		rc.Log("The last check is older than 24 hours: checking first")
		if _, err := o.checkOS(ctx, rc); err != nil {
			var ref *server.Refusal
			if errors.As(err, &ref) {
				return nil, err
			}
			return nil, fail(api.CodeStaleCheck, "The package index could not be refreshed, so the list of updates is stale.")
		}
	}
	if o.dpkgLocked() {
		return nil, lockedRefusal()
	}
	// The package list is the host's own: a fresh simulation, filtered by scope. Nothing here
	// comes from the client, and every name passes the package-name rule again in the validator.
	sim, err := o.simulate(ctx)
	if err != nil {
		return nil, err
	}
	var todo []Upgrade
	for _, u := range sim.Upgrades {
		// vedette-host is never upgraded from the host's own cgroup (FORBID-7, D-316): only host.self_update's
		// applier installs it. No apt repository carries it (D-81); this is the second layer.
		if isHostPkg(u.Name) {
			continue
		}
		if scope == "all" || u.Security {
			todo = append(todo, u)
		}
	}
	result := api.OSRunResult{Health: []api.Health{}}
	if len(todo) == 0 {
		rc.Log("Nothing to install")
		if _, err := o.storeSnapshot(ctx, plat, sim, nil, false); err != nil {
			return nil, err
		}
		result.Health = o.health(ctx)
		result.RebootRequired, _ = o.rebootInfo()
		return result, nil
	}

	rc.Log(fmt.Sprintf("Backing up the database before installing %d packages", len(todo)))
	bk, err := o.createBackup(ctx, rc, "pre_os_update", true, "", snapshot)
	if err != nil {
		return nil, err
	}
	result.Backup = bk.BackupID
	rc.Progress(15)

	args := append(append([]string{}, argsInstallPre...), upgradeNames(todo)...)
	rc.Log(fmt.Sprintf("Installing %d packages", len(todo)))
	res, code, err := o.exec(ctx, binAptGet, args...)
	logOutput(rc, res.Stdout)
	if err != nil {
		return nil, err
	}
	rc.Progress(85)

	// Verify by effect: ask apt again what is still pending; do not trust the exit code alone.
	after, serr2 := o.simulate(ctx)
	if serr2 != nil {
		return nil, fail(api.CodeAptFailed, "The install ran but the result could not be read back.")
	}
	remaining := map[string]bool{}
	for _, u := range after.Upgrades {
		remaining[u.Name] = true
	}
	for _, u := range todo {
		if !remaining[u.Name] {
			result.Installed++
			if u.Security {
				result.Security++
			}
		}
	}
	if _, err := o.storeSnapshot(ctx, plat, after, nil, false); err != nil {
		o.log.WarnContext(ctx, "could not store the snapshot after an install")
	}
	result.RebootRequired, _ = o.rebootInfo()
	result.Health = o.health(ctx)
	if code != 0 {
		return nil, &server.Failure{Code: api.CodeAptFailed, Message: fmt.Sprintf("apt-get install failed (exit %d); %d of %d packages were installed. Nothing was rolled back.", code, result.Installed, len(todo)), Result: result}
	}
	for _, h := range result.Health {
		if !h.OK {
			return nil, &server.Failure{Code: api.CodeHealthCheckFailed, Message: "The packages were installed but a health check failed (" + h.Name + "). Nothing was removed; the database backup is " + result.Backup + ".", Result: result}
		}
	}
	return result, nil
}

func upgradeNames(us []Upgrade) []string {
	names := make([]string, 0, len(us))
	for _, u := range us {
		names = append(names, u.Name)
	}
	return names
}

// health is the check after an install or a restore. Part 1 checks core's unit; the checks of the
// other services arrive with the container commands (deferred).
func (o *Ops) health(ctx context.Context) []api.Health {
	if o.cfg.CoreUnit == "" {
		return []api.Health{}
	}
	return []api.Health{{Name: unitName(o.cfg.CoreUnit), OK: o.coreActive(ctx)}}
}

// coreActive is systemctl is-active of core's unit read by its output (the exit code is 3 for inactive).
func (o *Ops) coreActive(ctx context.Context) bool {
	res, _, err := o.exec(ctx, binSystemctl, "is-active", o.cfg.CoreUnit)
	return err == nil && strings.TrimSpace(string(res.Stdout)) == "active"
}
