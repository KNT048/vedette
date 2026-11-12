package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
)

// The applier (spec 6.14 "Bộ áp", D-316 (3)-(5)): vedette-host -self-update-apply <run_id>, run by systemd-run
// as the transient unit vedette-host-upgrade.service, outside the host's cgroup, from the copy of the OLD binary
// in <state>/selfupdate/applier. It opens no socket, takes no host.lock and never writes the audit chain (one
// writer: the host); its phases and at most 50 log lines go to journal.json, everything else to journald. Every
// child goes through its own runner (applierBinaries). It installs the staged package (apt, or dpkg -i when a
// dpkg cut short left this package half done), checks the effect (dpkg-query, then started.json of the new host
// with its MainPID, stable for 30 s), and otherwise puts the version that was running back, after checking that
// it is not already back.

// ApplyConfig is what -self-update-apply gives the applier.
type ApplyConfig struct {
	StateDir string
	RunID    string
	Logger   *slog.Logger
}

// ApplyDeps are the seams of tests (ApplyWithDeps); production calls Apply, which fills the real values.
type ApplyDeps struct {
	Root     string
	BinPaths map[string]string
	Arch     string
	LockHeld func(path string) (bool, error)
	// Sleep waits between two looks and reports whether it did; the windows count the sleeps, not the clock.
	Sleep func(ctx context.Context, d time.Duration) bool
	// Stop, when set (tests only), is asked after each phase the applier writes; true makes it exit there, as a
	// crash would ("applier dies at phase X").
	Stop func(phase string) bool
}

// Timing of the applier (spec 6.14 steps 2 and 4).
const (
	applyPoll     = 2 * time.Second // health looks
	applyLockPoll = 5 * time.Second // F_GETLK looks before dpkg -i
	// applyRestartAfter: when started.json does not carry the new version this long after the install,
	// postinst did not restart the host (policy-rc.d): the applier restarts it itself.
	applyRestartAfter = 10 * time.Second
)

// errApplyStopped is the exit of a test's Stop.
var errApplyStopped = errors.New("ops: the applier stopped (test)")

type applier struct {
	cfg    ApplyConfig
	d      ApplyDeps
	log    *slog.Logger
	runner *vexec.Runner
	ctx    context.Context //nolint:containedctx // the applier's own lifetime: no phase is written once it ended
	j      suJournal
	fromOK bool // the kept package of from has the journal's hash: a reinstall is possible
}

// Apply runs the applier for real.
func Apply(ctx context.Context, cfg ApplyConfig) error { return ApplyWithDeps(ctx, cfg, ApplyDeps{}) }

// ApplyWithDeps is Apply with test seams. It returns nil when the journal ends (installed, rolled_back,
// not_started) and an error otherwise (rollback_failed included).
func ApplyWithDeps(ctx context.Context, cfg ApplyConfig, d ApplyDeps) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Root == "" {
		d.Root = "/"
	}
	if d.Arch == "" {
		d.Arch = (&Ops{}).arch()
	}
	if d.LockHeld == nil {
		d.LockHeld = fcntlLockHeld
	}
	if d.Sleep == nil {
		d.Sleep = sleepCtx
	}
	if !filepath.IsAbs(cfg.StateDir) || !runIDArgRE.MatchString(cfg.RunID) {
		return errors.New("ops: the applier needs an absolute state directory and a run id")
	}
	runner, err := vexec.NewRunner(cfg.Logger, applierBinaries(cfg.StateDir, d.BinPaths)...)
	if err != nil {
		return err
	}
	a := &applier{cfg: cfg, d: d, log: cfg.Logger, runner: runner}
	return a.run(ctx)
}

func (a *applier) run(ctx context.Context) error {
	a.ctx = ctx
	b, st := readSUIn(a.cfg.StateDir, suJournalName)
	if st != jOK {
		return errors.New("ops: the journal does not read")
	}
	j, err := parseSUJournal(b)
	if err != nil || j.RunID != a.cfg.RunID || j.Attempt < 1 {
		return errors.New("ops: the journal is not this run's, or was never dispatched")
	}
	a.j = j
	stagedOK := a.fileHash(stagedPath(a.cfg.StateDir, j.To.SHA256)) == j.To.SHA256
	a.fromOK = a.fileHash(a.keptPath(j.From.Version)) == j.From.SHA256
	switch j.Phase {
	case phDispatched:
		if !stagedOK || !a.fromOK {
			return a.end(phNotStarted, api.CodePackageChanged)
		}
		return a.install(ctx)
	case phInstalling, phChecking:
		if a.effect(ctx, j.To.Version) {
			return a.end(phInstalled, "")
		}
		if !stagedOK {
			return a.rollback(ctx, api.CodeInstallFailed)
		}
		return a.install(ctx)
	case phRollingBack:
		return a.rollback(ctx, derefReason(j.Reason))
	}
	return nil // already ended
}

// The applier's budgets (TestTimeLimitsAreConsistent: two effect checks and two halves fit RuntimeMaxSec).
// applyStep bounds the lock waits (the probe before the tool and apt's own DPkg::Lock::Timeout share
// applierLockBudget), the tool with postinst's try-restart, and the applier's own restart when postinst did not
// restart (policy-rc.d). applyHalf adds the health windows: one install, or one reinstall of from, with its
// check. applyEffect bounds an effect check (one look and the stability window).
const (
	applyStep   = applierLockBudget + hostStartLimit
	applyHalf   = applyStep + suHealthWindow + suStableWindow
	applyEffect = suStableWindow + 30*time.Second
)

// effect is the effect check of version within applyEffect: installed and healthy now, without installing.
func (a *applier) effect(ctx context.Context, version string) bool {
	eff, cancel := context.WithTimeout(ctx, applyEffect)
	defer cancel()
	return a.installed(eff, version) && a.healthy(eff, nil, version)
}

// install is steps 2-4 for the staged package, then step 5 when it does not work.
func (a *applier) install(ctx context.Context) error {
	if err := a.phase(phInstalling, ""); err != nil {
		return err
	}
	half, cancelHalf := context.WithTimeout(ctx, applyHalf)
	defer cancelHalf()
	step, cancel := context.WithTimeout(half, applyStep)
	defer cancel()
	if !a.installFile(step, stagedPath(a.cfg.StateDir, a.j.To.SHA256), false) {
		return a.rollback(ctx, api.CodeInstallFailed)
	}
	if err := a.phase(phChecking, ""); err != nil {
		return err
	}
	if a.installed(half, a.j.To.Version) && a.healthy(half, step, a.j.To.Version) {
		return a.end(phInstalled, "")
	}
	return a.rollback(ctx, api.CodeSelfUpdateUnhealthy)
}

// rollback is step 5: check the effect first (from is installed and healthy: nothing to do), else reinstall
// the kept package of from and check it the same way. A failure stops here (no loop, RUNBOOK).
func (a *applier) rollback(ctx context.Context, reason string) error {
	if err := a.phase(phRollingBack, reason); err != nil {
		return err
	}
	from := a.j.From.Version
	if a.effect(ctx, from) {
		return a.end(phRolledBack, reason)
	}
	half, cancelHalf := context.WithTimeout(ctx, applyHalf)
	defer cancelHalf()
	step, cancel := context.WithTimeout(half, applyStep)
	defer cancel()
	if a.fromOK && a.installFile(step, a.keptPath(from), true) && a.installed(half, from) && a.healthy(half, step, from) {
		return a.end(phRolledBack, reason)
	}
	if err := a.end(phRollbackFail, reason); err != nil {
		return err
	}
	return errors.New("ops: the previous version could not be put back")
}

// installFile installs file (staged, or kept with downgrade) the way step 2 chooses: apt when vedette-host is
// installed and dpkg --audit is clean, else dpkg -i of this package; either way after the F_GETLK wait on the
// four lock files (apt's DPkg::Lock::Timeout covers only dpkg's frontend lock, not apt's archives lock: review
// M6), and apt gets what is left of the lock budget as its own timeout. dpkg -i, which never waits, is tried
// once more when it met the lock. step bounds all of it. It reports whether the tool succeeded; the caller
// checks the effect.
func (a *applier) installFile(step context.Context, file string, downgrade bool) bool {
	budget := applierLockBudget
	if a.cleanDpkg(step) {
		if !a.waitLock(step, &budget) {
			a.logLine("The package lock stayed held for ten minutes")
			return false
		}
		a.logLine("Installing with apt-get")
		return a.exec(step, binAptGet, aptInstallArgv(file, downgrade, int(budget.Seconds()))...) == 0
	}
	a.logLine("dpkg is half done for vedette-host: installing with dpkg -i")
	for try := 0; try < 2; try++ {
		if !a.waitLock(step, &budget) {
			a.logLine("The package lock stayed held for ten minutes")
			return false
		}
		if a.exec(step, binDpkg, dpkgInstallArgv(file)...) == 0 {
			return true
		}
		if !a.lockHeld() {
			return false // failed for another reason than the lock
		}
	}
	return false
}

// cleanDpkg: vedette-host is installed (any version) and dpkg --audit reports nothing.
func (a *applier) cleanDpkg(ctx context.Context) bool {
	_, status := a.query(ctx)
	if status != "installed" {
		return false
	}
	out, code := a.output(ctx, binDpkg, "--audit")
	return code == 0 && strings.TrimSpace(out) == ""
}

// waitLock waits until no dpkg/apt lock is held, looking every applyLockPoll, within budget (shared by the try
// and its retry). False when the budget ran out.
func (a *applier) waitLock(ctx context.Context, budget *time.Duration) bool {
	for a.lockHeld() {
		if *budget <= 0 || !a.d.Sleep(ctx, applyLockPoll) {
			return false
		}
		*budget -= applyLockPoll
	}
	return true
}

func (a *applier) lockHeld() bool {
	for _, rel := range dpkgLockFiles {
		if held, err := a.d.LockHeld(filepath.Join(a.d.Root, rel)); err != nil || held {
			return true
		}
	}
	return false
}

// installed: dpkg-query prints version (Debian form) with status installed.
func (a *applier) installed(ctx context.Context, version string) bool {
	v, status := a.query(ctx)
	return v == debVersion(version) && status == "installed"
}

func (a *applier) query(ctx context.Context) (version, status string) {
	out, code := a.output(ctx, binDpkgQuery, argsDpkgQueryHost...)
	if code != 0 {
		return "", ""
	}
	version, status, _ = strings.Cut(strings.TrimSpace(out), "|")
	return version, status
}

// healthy is step 4 for version: started.json of that version, this boot, and pid = MainPID of an active
// vedette-host.service, then the same MainPID and no new restart for the stability window. After an install
// (step != nil) it waits up to the health window for that, and restarts the host itself (bounded by step) when,
// applyRestartAfter after the install, no host of that version wrote it (postinst did not restart: policy-rc.d).
// As an effect check (step == nil) it looks once: a host that runs has already written its witness.
func (a *applier) healthy(ctx, step context.Context, version string) bool {
	looks := 0
	if step != nil {
		looks = int(suHealthWindow / applyPoll)
	}
	restarted := false
	var pid, restarts int
	found := false
	for i := 0; i <= looks; i++ {
		if s, ok := a.started(); ok && s.Version == version && s.BootID == a.bootID() {
			if active, mainPID, n := a.show(ctx); active && mainPID == s.PID {
				pid, restarts, found = mainPID, n, true
				break
			}
		}
		if i == looks {
			break
		}
		if !restarted && time.Duration(i)*applyPoll >= applyRestartAfter {
			a.logLine("No host of version " + version + " started: restarting vedette-host.service")
			a.exec(step, binSystemctl, argsRestartHost...)
			restarted = true
			continue
		}
		if !a.d.Sleep(ctx, applyPoll) {
			return false
		}
	}
	if !found {
		return false
	}
	for range int(suStableWindow / applyPoll) {
		if !a.d.Sleep(ctx, applyPoll) {
			return false
		}
		if active, mainPID, n := a.show(ctx); !active || mainPID != pid || n > restarts {
			a.logLine("vedette-host " + version + " did not stay up")
			return false
		}
	}
	return true
}

func (a *applier) started() (suStarted, bool) {
	b, st := readSUIn(a.cfg.StateDir, suStartedName)
	if st != jOK {
		return suStarted{}, false
	}
	s, err := parseSUStarted(b)
	return s, err == nil
}

// show reads systemctl show vedette-host.service -p ActiveState,MainPID,NRestarts.
func (a *applier) show(ctx context.Context) (active bool, mainPID, restarts int) {
	out, code := a.output(ctx, binSystemctl, argsShowHost...)
	if code != 0 {
		return false, 0, 0
	}
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ActiveState":
			active = v == "active"
		case "MainPID":
			_, _ = fmt.Sscanf(v, "%d", &mainPID)
		case "NRestarts":
			_, _ = fmt.Sscanf(v, "%d", &restarts)
		}
	}
	return active, mainPID, restarts
}

func (a *applier) bootID() string {
	b, err := os.ReadFile(filepath.Join(a.d.Root, "proc/sys/kernel/random/boot_id"))
	if s := strings.TrimSpace(string(b)); err == nil && bootIDRE.MatchString(s) {
		return s
	}
	return ""
}

func (a *applier) keptPath(version string) string {
	return filepath.Join(keptDir(a.cfg.StateDir), hostPkgName(version, a.d.Arch))
}

// fileHash is the SHA-256 of a regular file (not a link), "" when it cannot be read.
func (a *applier) fileHash(p string) string {
	f, _, err := openRegularNoFollow(p)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sum, err := sha256Reader(f)
	if err != nil {
		return ""
	}
	return sum
}

// phase writes the phase (and the reason) into the journal; a test's Stop may end the applier right after.
//
// Once the applier's own context has ended (RuntimeMaxSec, a reboot, systemctl stop: review H1) nothing more
// is written: every child failed only because of that, so the last real phase stays and the host starts the
// applier again (attempt 2) or ends the run interrupted, never on a decision taken in that state.
func (a *applier) phase(p, reason string) error {
	if err := a.ctx.Err(); err != nil {
		return err
	}
	a.j.Phase = p
	if reason != "" {
		r := reason
		a.j.Reason = &r
	}
	if err := saveSUIn(a.cfg.StateDir, suJournalName, a.j); err != nil {
		a.log.Error("could not write the journal", "phase", p, "error", err.Error())
		return err
	}
	a.log.Info("self-update phase", "phase", p, "attempt", a.j.Attempt)
	if a.d.Stop != nil && a.d.Stop(p) {
		return errApplyStopped
	}
	return nil
}

// end writes a final phase; nil for the phases that end the update as it should end.
func (a *applier) end(p, reason string) error {
	if err := a.phase(p, reason); err != nil {
		return err
	}
	if p == phRollbackFail {
		return errors.New("ops: rollback failed")
	}
	return nil
}

// logLine keeps at most maxSULogLines lines of at most maxSULogLine bytes, without control characters.
func (a *applier) logLine(l string) {
	a.log.Info("applier", "line", l)
	l = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, l)
	if len(l) > maxSULogLine {
		l = strings.ToValidUTF8(l[:maxSULogLine], "")
	}
	if len(a.j.Log) >= maxSULogLines {
		a.j.Log = a.j.Log[1:]
	}
	a.j.Log = append(a.j.Log, l)
}

// exec runs a child within ctx (the step's budget) and returns its exit code (-1 when it could not run).
func (a *applier) exec(ctx context.Context, bin string, args ...string) int {
	res, err := a.runner.Run(ctx, bin, args, nil)
	var ee *vexec.ExitError
	switch {
	case errors.As(err, &ee):
		a.logLine(fmt.Sprintf("%s exited %d", bin, ee.ExitCode))
		return ee.ExitCode
	case err != nil:
		a.logLine(bin + " could not run")
		a.log.ErrorContext(ctx, "child failed", "binary", bin, "error", err.Error())
		return -1
	}
	return res.ExitCode
}

func (a *applier) output(ctx context.Context, bin string, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	res, err := a.runner.Run(ctx, bin, args, nil)
	var ee *vexec.ExitError
	if errors.As(err, &ee) {
		return string(res.Stdout), ee.ExitCode
	}
	if err != nil {
		return "", -1
	}
	return string(res.Stdout), 0
}
