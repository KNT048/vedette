// Package ops implements the system commands of vedette-host (docs/specs/host-api.md section 6)
// that WP-07b part 1 delivers: os.check, os.install, os.auto_security.set, os.reboot,
// os.reboot.cancel, backup.create, backup.restore and logs.export, plus the read-only state
// endpoints that belong to them, and (part 3) net.apply, net.confirm, net.revert and the NTP
// sources. Container commands and decoy addresses come in later slices.
//
// Every child process goes through one core/exec Runner: absolute binary paths, argv validated by a
// per-binary validator, PATH, LANG=C and DEBIAN_FRONTEND=noninteractive only, no shell. Nothing in
// a request names a binary, an argv or a path: files live under the state directory, in
// core's data directory (from host.conf) or at fixed system paths, and are chosen here.
//
// OS assumption: Debian or Ubuntu with apt, dpkg and systemd; it needs root for real. Everything
// that touches the system takes its root directory and binary paths from Deps so tests run on a
// temporary directory with fake binaries.
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/server"
)

type logger = *slog.Logger

var newCommandRunner = server.NewCommandRunner

// Config is what the real host gives Ops: the state directory, core's data directory and unit
// (host.conf), and the uid that must own the state files (0 in production).
type Config struct {
	StateDir string
	CoreData string // "" when host.conf has no core_data: backups then refuse with db_unreadable
	CoreUnit string
	Version  string
	CoreUID  int // host.conf core_uid: the owner every file read from core's tree must have
	CoreGID  int // host.conf core_gid: the group restored files get (with core_uid, mode 0600)
	OwnerUID int
	Logger   *slog.Logger
}

// Deps are the seams of tests. The binary calls New, which fills the production values; a request
// can never reach any of this.
type Deps struct {
	Root         string            // prefix of every fixed system path ("/" in production)
	BinPaths     map[string]string // replaces the constant path of a binary by name; the validators stay
	Now          func() time.Time
	LockHeld     func(path string) (bool, error)                    // is a dpkg/apt lock file held by another process
	NetPending   func() bool                                        // a network change waits for confirmation (default: the server has a run in awaiting_confirm)
	AfterFunc    func(d time.Duration, f func()) (stop func() bool) // arms the scheduled-reboot and export-sweep timers
	Installing   *atomic.Bool                                       // set while os.install runs; a test may pass its own to raise it
	FreeBytes    func(path string) (uint64, error)                  // free space of the filesystem holding path
	ExportLimit  int64                                              // bytes of journal text one export may hold (default 256 MiB)
	CoreWait     time.Duration                                      // how long core may take to stop or start (default 2 min)
	CorePoll     time.Duration                                      // how often to look (default 1 s)
	HealthSettle time.Duration                                      // core must stay active this long after a start (default 5 s)
	// ChainTop ends the walk over the parents of core_data after this directory (tests: the test's temp dir,
	// whose own parent may be a sticky, world-writable /tmp on Linux). Unset in production: the walk goes up
	// to "/" and every parent must be root-owned and closed to group and others.
	ChainTop string
	// Interfaces lists the network interfaces and their addresses (default: the net package). Probe is
	// the ARP side of the network commands (default: the real packet socket, Linux only).
	Interfaces func() ([]HostIface, error)
	Probe      Prober
	// NetPoll and NetWait are how often and how long the effect checks of the network commands look
	// (address on the card, chrony sources): default 1 s and 15 s (D-100, D-106).
	NetPoll time.Duration
	NetWait time.Duration
}

// Ops holds the state of the system commands.
type Ops struct {
	cfg    Config
	d      Deps
	log    *slog.Logger
	runner *vexec.Runner

	installing *atomic.Bool // true while os.install runs (shared with Deps.Installing so a test can raise it)

	mu       sync.Mutex // guards the notifier and the export sweep timer
	notifier Notifier
	sweepOff func() bool

	rbMu     sync.Mutex // guards reboot.json and the scheduled-reboot timer
	stopTick func() bool
	gate     atomic.Pointer[rebootGate] // set while a reboot the host started has not completed (WriteGate); never taken under rbMu

	netMu   sync.Mutex // guards the confirm-window timer and the run Resume kept
	netStop func() bool
	resumed string // the net.apply run Resume kept; Start reads and clears it

	bkMu sync.Mutex // guards backups/index.json
	exMu sync.Mutex // guards exports/index.json
}

// Notifier is what Ops needs from the server once it runs: an audit line for things the host does
// on its own, whether some write command is running, and whether a run waits for confirmation.
type Notifier interface {
	Note(command, code string, detail map[string]any) error
	WriteActive() bool
	AwaitingConfirm() bool
	// Claim takes the right to end the awaiting run (server.Claim): confirm, revert and the timer
	// race through it before any effect.
	Claim(runID string) (*server.Claimed, error)
}

// New builds Ops for the real system.
func New(cfg Config) (*Ops, error) {
	return NewWithDeps(cfg, Deps{})
}

// NewWithDeps is New with test seams. Production code must call New: a contract test checks that
// cmd/vedette-host and the server never reference NewWithDeps.
func NewWithDeps(cfg Config, d Deps) (*Ops, error) {
	if cfg.StateDir == "" || !filepath.IsAbs(cfg.StateDir) {
		return nil, errors.New("ops: StateDir must be an absolute path")
	}
	if cfg.CoreData != "" && !filepath.IsAbs(cfg.CoreData) {
		return nil, errors.New("ops: CoreData must be an absolute path")
	}
	if cfg.CoreData != "" && cfg.CoreUID <= 0 {
		return nil, errors.New("ops: CoreUID (core_uid) must be set when CoreData is")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Root == "" {
		d.Root = "/"
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.LockHeld == nil {
		d.LockHeld = fcntlLockHeld
	}
	if d.AfterFunc == nil {
		d.AfterFunc = func(dur time.Duration, f func()) func() bool { return time.AfterFunc(dur, f).Stop }
	}
	if d.Installing == nil {
		d.Installing = new(atomic.Bool)
	}
	if d.FreeBytes == nil {
		d.FreeBytes = freeBytes
	}
	if d.ExportLimit <= 0 {
		d.ExportLimit = maxExportBytes
	}
	if d.CoreWait <= 0 {
		d.CoreWait = 2 * time.Minute
	}
	if d.CorePoll <= 0 {
		d.CorePoll = time.Second
	}
	if d.HealthSettle <= 0 {
		d.HealthSettle = 5 * time.Second
	}
	if d.Interfaces == nil {
		d.Interfaces = systemInterfaces
	}
	if d.Probe == nil {
		d.Probe = newARPProber()
	}
	if d.NetPoll <= 0 {
		d.NetPoll = time.Second
	}
	if d.NetWait <= 0 {
		d.NetWait = 15 * time.Second
	}
	runner, err := newRunner(cfg.Logger, cfg.CoreUnit, d.BinPaths, min(d.ExportLimit, maxJournalStream))
	if err != nil {
		return nil, fmt.Errorf("ops: %w", err)
	}
	o := &Ops{cfg: cfg, d: d, log: cfg.Logger, runner: runner, installing: d.Installing}
	for _, dir := range []string{"os", "backups", "exports", "tmp", "net"} {
		if err := privDir(filepath.Join(cfg.StateDir, dir), cfg.OwnerUID); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// Commands are the registry entries of this part, for server.NewRegistry.
func (o *Ops) Commands() []server.Command {
	return []server.Command{
		o.cmdOSCheck(), o.cmdOSInstall(), o.cmdAutoSecurity(), o.cmdReboot(), o.cmdRebootCancel(),
		o.cmdBackupCreate(), o.cmdBackupRestore(), o.cmdLogsExport(),
		o.cmdNetApply(), o.cmdNetConfirm(), o.cmdNetRevert(),
	}
}

// Readers are the state endpoints of this part, for server.Options.Readers.
func (o *Ops) Readers() server.Readers {
	return server.Readers{
		OS: o.readOS, Backups: o.readBackups, Net: o.readNet, BackupContent: o.backupContent, ExportContent: o.exportContent,
	}
}

func (o *Ops) path(rel string) string { return filepath.Join(o.d.Root, rel) }

func (o *Ops) stateFile(rel ...string) string {
	return filepath.Join(append([]string{o.cfg.StateDir}, rel...)...)
}

// exec runs one allowlisted binary and reports a non-zero exit as its code (>= 0) with a nil error;
// anything else that went wrong is an error.
func (o *Ops) exec(ctx context.Context, name string, args ...string) (vexec.Result, int, error) {
	res, err := o.runner.Run(ctx, name, args, nil)
	var ee *vexec.ExitError
	if errors.As(err, &ee) {
		return res, ee.ExitCode, nil
	}
	return res, res.ExitCode, err
}

// logOutput sends the head and tail of a program's output to the run's event stream.
func logOutput(rc *server.RunContext, out []byte) {
	const head, tail = 150, 50
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) <= head+tail {
		for _, l := range lines {
			if l != "" {
				rc.Log(l)
			}
		}
		return
	}
	for _, l := range lines[:head] {
		rc.Log(l)
	}
	rc.Log(fmt.Sprintf("... %d lines omitted ...", len(lines)-head-tail))
	for _, l := range lines[len(lines)-tail:] {
		rc.Log(l)
	}
}

// sleepCtx waits for d or the context, whichever comes first, and reports whether d elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func fail(code, msg string) *server.Failure { return &server.Failure{Code: code, Message: msg} }

func refuse412(code, msg string) *server.Refusal {
	return server.Refuse(412, code, msg)
}

func refuse409(code, msg string) *server.Refusal {
	return server.Refuse(409, code, msg)
}

// Start arms what must survive a host restart: it notices a reboot the host started, re-arms the
// scheduled reboot, recovers a restore that was cut short, and sweeps expired exports. It runs once,
// before the server listens. n receives the audit lines of things the host does on its own.
func (o *Ops) Start(ctx context.Context, n Notifier) {
	o.mu.Lock()
	o.notifier = n
	o.mu.Unlock()
	o.recoverNet(ctx)
	o.sweepBackups()
	o.checkCoreAtStart()
	o.recoverRestore(ctx)
	o.startReboot()
	o.sweepExports()
	o.armSweep()
}

// Close stops the timers (the host is shutting down).
func (o *Ops) Close() {
	o.stopNetTimer() // an awaiting run stays awaiting on disk; the next start asks Resume
	o.rbMu.Lock()
	if o.stopTick != nil {
		o.stopTick()
		o.stopTick = nil
	}
	o.rbMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sweepOff != nil {
		o.sweepOff()
		o.sweepOff = nil
	}
}

func (o *Ops) note(command, code string, detail map[string]any) {
	o.mu.Lock()
	n := o.notifier
	o.mu.Unlock()
	if n == nil {
		return
	}
	if err := n.Note(command, code, detail); err != nil {
		o.log.Error("could not write an audit note", "command", command, "code", code)
	}
}

// noteDownload audits one download of a backup or export. It fails closed: a download the audit
// chain cannot record is not served. Before Start there is no notifier and nothing is recorded.
func (o *Ops) noteDownload(command, code string, detail map[string]any) error {
	o.mu.Lock()
	n := o.notifier
	o.mu.Unlock()
	if n == nil {
		return nil
	}
	if err := n.Note(command, code, detail); err != nil {
		o.log.Error("could not write an audit note; the download is refused", "command", command, "code", code)
		return errors.New("ops: the audit log is unavailable")
	}
	return nil
}

// netPending reports whether a network change waits for confirmation (os.reboot refuses then,
// spec 16). Deps.NetPending replaces the server's answer in tests; before Start there is none.
func (o *Ops) netPending() bool {
	if o.d.NetPending != nil {
		return o.d.NetPending()
	}
	o.mu.Lock()
	n := o.notifier
	o.mu.Unlock()
	return n != nil && n.AwaitingConfirm()
}

func (o *Ops) writeActive() bool {
	o.mu.Lock()
	n := o.notifier
	o.mu.Unlock()
	return n != nil && n.WriteActive()
}

// unitName strips the .service suffix for display ("vedette-core").
func unitName(u string) string { return strings.TrimSuffix(u, ".service") }

func refuseRetry(status int, code, msg string, retry int) *server.Refusal {
	return server.RefuseRetry(status, code, msg, retry)
}
