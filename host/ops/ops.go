// Package ops implements the system commands of vedette-host (docs/specs/host-api.md section 6)
// that WP-07b part 1 delivers: os.check, os.install, os.auto_security.set, os.reboot,
// os.reboot.cancel, backup.create, backup.restore and logs.export, plus the read-only state
// endpoints that belong to them, and (part 3) net.apply, net.confirm, net.revert and the NTP
// sources, (slice 3-5) decoy_ip.add and decoy_ip.remove with the honeypot namespace, and (slice 3-6)
// the Quadlet units with container.start (the current image) and container.stop, and (slice 3-7)
// container.pull, which verifies a signed release itself before it pulls an image by digest, and (slice
// 3-8a) container.start with a version, container.rollback and the retention of images, and (slice 3-8b)
// the bootstrap that writes the first units (Bootstrap, run by vedette-host -bootstrap, never from the
// socket) and the way out of core_data_unrecoverable through backup.restore.
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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/internal/release"
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
	// SensorUID and SensorGID are host.conf's sensor_uid and sensor_gid: the user of the sensor and
	// scan units and the group core's unit adds (D-114). 0 means host.conf did not give them: the
	// container commands then refuse the units that need them (host_conf_incomplete).
	SensorUID int
	SensorGID int
	OwnerUID  int
	// AuditDir is the directory of the audit log ("" in tests): core_data must not be, hold or sit under it.
	AuditDir string
	Logger   *slog.Logger
}

// Deps are the seams of tests. The binary calls New, which fills the production values; a request
// can never reach any of this.
type Deps struct {
	Root       string            // prefix of every fixed system path ("/" in production)
	BinPaths   map[string]string // replaces the constant path of a binary by name; the validators stay
	Now        func() time.Time
	LockHeld   func(path string) (bool, error)                    // is a dpkg/apt lock file held by another process
	NetPending func() bool                                        // a network change waits for confirmation (default: the server has a run in awaiting_confirm)
	AfterFunc  func(d time.Duration, f func()) (stop func() bool) // arms the scheduled-reboot and export-sweep timers
	// FwdAfter arms the look at the Docker forward rules (D-267); its own seam so that the tests that count
	// the timers of AfterFunc do not see it. Default: a real timer.
	FwdAfter     func(d time.Duration, f func()) (stop func() bool)
	Installing   *atomic.Bool                      // set while os.install runs; a test may pass its own to raise it
	FreeBytes    func(path string) (uint64, error) // free space of the filesystem holding path
	ExportLimit  int64                             // bytes of journal text one export may hold (default 256 MiB)
	CoreWait     time.Duration                     // how long core may take to stop or start (default 2 min)
	CorePoll     time.Duration                     // how often to look (default 1 s)
	HealthSettle time.Duration                     // core must stay active this long after a start (default 5 s)
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
	// NetRetryGap is the pause between the three tries of a revert's netplan apply (default 30 s, so
	// about 60 s in all, D-100 (8)).
	NetRetryGap time.Duration
	// IsNetNS says whether an open file is a bind-mounted network namespace other than the host's own
	// (default: nsfs, NS_GET_NSTYPE and the identity of /proc/self/ns/net; Linux only). Tests, which
	// have no namespaces, answer for it.
	IsNetNS func(*os.File) (bool, error)
	// HealthWait and HealthPoll are how long and how often the container commands look for a healthy
	// container after a restart: 120 s and 2 s (spec 6.8, D-105 (3)). Sleep waits between two looks
	// and reports whether it did (default: a timer that the context cuts short); tests give a Sleep that
	// does not wait, so the 120 s run in no time. The wait counts the sleeps, not the clock.
	HealthWait time.Duration
	HealthPoll time.Duration
	// CoreWatch is how often the host looks at core's container for a new run, to clear the stale syslog UDP flows (default 30 s, D-268).
	CoreWatch time.Duration
	Sleep     func(ctx context.Context, d time.Duration) bool
	// Keys is the root of trust of container.pull (D-107, D-130): default release.Embedded, the keys
	// compiled into the binary. A build without real keys refuses every pull. Only tests replace it.
	Keys func() (release.Trust, error)
	// JournalFault, when set, is asked before every write of a transition journal with the service and the
	// phase about to be written, and a non-nil answer makes that write fail (a test seam for the durability of
	// the verified phase, D-138 N3). Nil in production.
	JournalFault func(service, phase string) error
	// Arch is the architecture container.pull asks the manifest for, as in "linux/<Arch>" (default
	// runtime.GOARCH).
	Arch string
	// SelfExe is the running binary host.self_update copies for its applier (default /proc/self/exe).
	SelfExe string
	// StartUnit, when set (tests only), is called instead of running systemd-run, after the same argv validator:
	// the fake world starts the applier in a goroutine. PID is this process's pid for started.json (default os.Getpid).
	StartUnit func(argv []string) error
	PID       func() int
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
	noteOnly interface { // the audit file of the bootstrap, which runs no server (AuditTo)
		Note(command, code string, detail map[string]any) error
	}
	sweepOff func() bool

	// ctMu guards the run of core's container last seen and the one-time "conntrack is missing" line (conntrack.go);
	// watchOff ends the look-at-core loop (guarded by mu).
	ctMu            sync.Mutex
	ctSeen          string
	ctMissingLogged bool
	watchOff        context.CancelFunc

	rbMu     sync.Mutex // guards reboot.json and the scheduled-reboot timer
	stopTick func() bool
	gate     atomic.Pointer[rebootGate] // set while a reboot the host started has not completed (WriteGate); never taken under rbMu

	netMu   sync.Mutex // guards the confirm-window timer and the run Resume kept
	netStop func() bool
	resumed string // the net.apply run Resume kept; Start reads and clears it

	hpMu         sync.Mutex  // guards hp/decoys.json and the contents of the honeypot namespace
	hpConfigured atomic.Bool // the sysctls, lo and ruleset were set and read back since this host started
	hpOK         atomic.Bool // the last ensureHP proved the namespace (state/net lists decoys only then)
	hpDirErr     error       // hp/ is not a usable directory: decoys are off (D-121)

	// restorePending lists the services whose unit bytes Start put back and whose state AfterReady still
	// restores; Start sets it before the server listens, AfterReady reads it afterwards.
	restorePending []string

	// afterCtx and afterL are what AfterReady was given (guarded by mu): a run that fails to put core's data
	// back restarts the retry loop with them once it has released the write lock (D-138 N2). kicking keeps it
	// to one loop; recNote is when each service last audited a recovery failure (guarded by mu), so a loop
	// that fails again and again writes one line, then at most one an hour (N5).
	afterCtx context.Context //nolint:containedctx // the process's own context, kept to restart a retry loop
	afterL   Locker
	kicking  atomic.Bool
	recNote  map[string]time.Time

	// Container commands run one at a time under the server's write lock; Start runs before the
	// server listens. Nothing else touches containers/ (no mutex of its own).

	// The Docker forward rules (dockerfwd.go, D-267); all three are guarded by mu.
	fwdLast string      // the state of the last look: a log line is written only when it changes
	fwdOff  func() bool // stops the timer of the next look
	closed  bool        // Close ran: no more looks are armed

	// host.self_update (selfupdatesettle.go): suResumed is the run Resume kept (guarded by suMu), suFollow what
	// Start decided AfterReady follows (Start and AfterReady run one after the other), suGate the write gate of a
	// self-update that did not end cleanly, loopCtx the process's context the settle loop runs on (guarded by mu).
	suMu      sync.Mutex
	suResumed string
	suFollow  *suFollow
	suGate    atomic.Bool
	loopCtx   context.Context //nolint:containedctx // the process's own context, for the settle loop
	loopStop  context.CancelFunc

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
	if d.FwdAfter == nil {
		d.FwdAfter = func(dur time.Duration, f func()) func() bool { return time.AfterFunc(dur, f).Stop }
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
	if d.NetRetryGap <= 0 {
		d.NetRetryGap = 30 * time.Second
	}
	if d.IsNetNS == nil {
		d.IsNetNS = isNetNS
	}
	if d.HealthWait <= 0 {
		d.HealthWait = 2 * time.Minute
	}
	if d.HealthPoll <= 0 {
		d.HealthPoll = 2 * time.Second
	}
	if d.CoreWatch <= 0 {
		d.CoreWatch = coreWatchEvery
	}
	if d.Sleep == nil {
		d.Sleep = sleepCtx
	}
	if d.SelfExe == "" {
		d.SelfExe = "/proc/self/exe"
	}
	if d.PID == nil {
		d.PID = os.Getpid
	}
	runner, err := newRunner(cfg.Logger, cfg.StateDir, cfg.CoreUnit, d.BinPaths, min(d.ExportLimit, maxJournalStream))
	if err != nil {
		return nil, fmt.Errorf("ops: %w", err)
	}
	o := &Ops{cfg: cfg, d: d, log: cfg.Logger, runner: runner, installing: d.Installing}
	for _, dir := range []string{"os", "backups", "exports", "tmp", "net", "containers", "containers/units", "releases",
		suDirName, filepath.Join(suDirName, suStagedName), filepath.Join(suDirName, suPackagesName)} {
		if err := privDir(filepath.Join(cfg.StateDir, dir), cfg.OwnerUID); err != nil {
			return nil, err
		}
	}
	// A bad hp directory (a link, another owner, open to others) turns the decoys off and nothing else:
	// the host must still serve the network commands (D-121).
	if err := privDir(filepath.Join(cfg.StateDir, "hp"), cfg.OwnerUID); err != nil {
		o.hpDirErr = err
		cfg.Logger.Error("the hp state directory is not usable; decoys are off", "error", err.Error())
	}
	return o, nil
}

// Commands are the registry entries of this part, for server.NewRegistry.
func (o *Ops) Commands() []server.Command {
	return []server.Command{
		o.cmdOSCheck(), o.cmdOSInstall(), o.cmdAutoSecurity(), o.cmdReboot(), o.cmdRebootCancel(),
		o.cmdBackupCreate(), o.cmdBackupRestore(), o.cmdBackupPurge(), o.cmdLogsExport(),
		o.cmdNetApply(), o.cmdNetConfirm(), o.cmdNetRevert(),
		o.cmdDecoyAdd(), o.cmdDecoyRemove(),
		o.cmdContainerStart(), o.cmdContainerStop(), o.cmdContainerPull(), o.cmdContainerRollback(),
		o.cmdHostSelfUpdate(),
	}
}

// Readers are the state endpoints of this part, for server.Options.Readers.
func (o *Ops) Readers() server.Readers {
	return server.Readers{
		OS: o.readOS, Backups: o.readBackups, Net: o.readNet, Containers: o.readContainers, Host: o.readHost,
		BackupContent: o.backupContent, ExportContent: o.exportContent,
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

// execIn is exec with a standard input (the nft ruleset).
func (o *Ops) execIn(ctx context.Context, name string, stdin io.Reader, args ...string) (vexec.Result, int, error) {
	res, err := o.runner.Run(ctx, name, args, stdin)
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
	lctx, stop := context.WithCancel(ctx)
	o.mu.Lock()
	o.notifier = n
	o.loopCtx, o.loopStop = lctx, stop
	o.mu.Unlock()
	o.sweepTmp("releases", "containers") // temp files of a write cut short (container.pull state)
	hpReady := o.startHP(ctx)            // before recoverNet: a revert at start re-applies the decoys into it
	o.recoverNet(ctx)
	o.reconcileAtStart(ctx, hpReady)
	o.sweepBackups()
	o.checkCoreAtStart()
	o.recoverRestore(ctx)
	o.recoverTransitions(ctx, true) // unit changes the host died in the middle of: bytes only, the state after READY (D-105 (7), D-123); units of an earlier release (D-316 (10))
	o.adoptHostPackage(ctx)         // the .deb install.sh kept for the running version becomes current (D-316)
	o.startSelfUpdate()             // a self-update under way: follow it after READY, or clean or gate an orphan journal
	o.startReboot()
	o.sweepExports()
	o.armSweep()
	o.armDockerFwd(ctx)
	wctx, cancel := context.WithCancel(ctx)
	o.mu.Lock()
	o.watchOff = cancel
	o.mu.Unlock()
	go o.watchCore(wctx) // the first look is one CoreWatch from now: a host start runs no program of its own for this
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
	o.closed = true
	if o.fwdOff != nil {
		o.fwdOff()
		o.fwdOff = nil
	}
	if o.watchOff != nil {
		o.watchOff()
		o.watchOff = nil
	}
	if o.loopStop != nil {
		o.loopStop() // the settle loop stops; a parked run stays parked on disk for the next host
		o.loopStop = nil
	}
	if o.sweepOff != nil {
		o.sweepOff()
		o.sweepOff = nil
	}
}

func (o *Ops) note(command, code string, detail map[string]any) {
	o.mu.Lock()
	n := o.notifier
	nw := o.noteOnly
	o.mu.Unlock()
	var err error
	switch {
	case n != nil:
		err = n.Note(command, code, detail)
	case nw != nil:
		err = nw.Note(command, code, detail)
	default:
		return
	}
	if err != nil {
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
