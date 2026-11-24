package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

const (
	// The active sweep's own budget of new devices: a fresh install without a passive sensor must find the design scale
	// (1,000 devices, ARCHITECTURE) in one pass, and a taken-over scan container still cannot mint 65k devices on a /16 in one night.
	sweepNewPerMinute = 1000
	sweepNewPerHour   = 1000
	// maxRun bounds one nmap run: the deadline is the end of the window or this, whichever comes first.
	maxRun = 2 * time.Hour
	// ProbeRetention is how long sa_probe rows are kept (INV-9 asks for at least 90 days).
	ProbeRetention = 365 * 24 * time.Hour
	// finishTimeout bounds the writes that must happen even when the run was cancelled.
	finishTimeout = 30 * time.Second
)

// Config is what New needs. Everything except Events and Log is required.
type Config struct {
	DB        *store.DB
	Inventory Inventory
	Observe   observe.Sink         // the inventory, through core/observe
	Software  observe.SoftwareSink // the inventory, through core/observe
	Services  Services             // the inventory's open ports; nil: the open ports are not recorded
	Events    Publisher
	NmapPath  string // absolute path of the OS package's nmap; Health reads it, and the local Prober runs it
	// Prober runs the nmap command the module has already checked. Nil means the local one, core/exec around
	// NmapPath (NewLocalProber). The Dispatcher hands the job to the worker in the scan container; then
	// NmapPath is not used and Health comes from the worker's heartbeat.
	Prober Prober
	Clock  func() time.Time
	Log    *slog.Logger
	// Location is the organization's time zone, the one the windows are read in (INV-3). Nil, or a nil result,
	// means the box's own zone (time.Local).
	Location func() *time.Location
	// SNMP reads. Secrets seals the credentials' secrets (nil: the credential calls answer 501); Audit records who changed
	// or tested a credential; SNMP sends the reads (nil: the Prober when it is one, the Dispatcher, else none).
	Secrets *secrets.Store
	Audit   *audit.Log
	SNMP    SNMPReader
	// Runs is the box's run manager (core/run): every sweep, device check, SNMP read and scan of every port is a run of it. The kinds
	// are registered by New, before the manager starts. Nil (tests): the service builds and starts its own over DB.
	Runs *run.Manager
	// LocalPrefixes is the IPv4 networks the box has a card on: a sweep reaches them with one ARP request an address,
	// everything else through a router with SweepProbes packets. Only the sweep-time estimate reads it; nil: every range counts
	// as routed.
	LocalPrefixes func(context.Context) []netip.Prefix
}

// Service runs active discovery. Create it with New. It is the only writer of the sa_* tables.
type Service struct {
	db  *store.DB
	inv Inventory
	// runs is the run manager; ownRuns when New made it (Close closes it). pend is the work a caller handed with a run that has not
	// started; waits the callers that wait for a run's end (runs.go). Both guarded by mu.
	runs    *run.Manager
	ownRuns bool
	pend    map[string]*pending
	waits   map[string]chan outcome
	// pendingQueued: queuePendingOnce has queued the devices waiting for their gentle scan in this process
	pendingQueued atomic.Bool
	// owedQueued is the start of the window whose owed normal scans (queueOwedNormal) are queued
	owedQueued atomic.Pointer[time.Time]
	// owedTried is the devices queueOwedNormal queued: each once (guarded by mu)
	owedTried map[string]bool
	obs       observe.Sink
	sw        observe.SoftwareSink
	svc       Services // may be nil
	events    Publisher
	path      string
	prober    Prober
	clock     func() time.Time
	log       *slog.Logger
	loc       func() *time.Location
	localNets func(context.Context) []netip.Prefix // may be nil
	// budget is core's budget of new devices (60 a minute, 200 an hour; L8): the scan container is a process that can be taken over,
	// and a sweep over a /16 with random MACs would otherwise mint 65k devices. In memory, like the passive sensor's.
	budget *capture.FloodBudget

	runMu sync.Mutex // one nmap job at a time on the box

	secrets *secrets.Store
	audit   *audit.Log
	snmp    SNMPReader
	snmpMu  sync.Mutex // one snmp job at a time (a Test or a batch of the window's round)

	ver atomic.Uint64 // bumped by every SettingsChanged; a run that sees it move before nmap starts stops
	// stops is bumped by every Stop (the module turned off): a picked run or an external one that was still waiting for runMu when
	// it came sees it move once it has the lock, and stops instead of starting (#723).
	stops atomic.Uint64
	// off is set by Stop and cleared by Resume (the module turned on again): while it is set no SNMP batch sends anything, whatever
	// generation a read or a round captured (SYS-5; #855: a Stop that came before the batch registered had nothing to
	// cancel). Checked by snmpBatch right after it registers, and by Read now before it starts and before each batch.
	off atomic.Bool
	// beforeSNMPBatch, when set (tests only, export_test.go), runs as a batch starts, before it registers.
	beforeSNMPBatch func()
	// beforeBoxResume, when set (tests only), runs right before the box resumes a run that it read as waiting (resumeWaiting).
	beforeBoxResume func(id string)
	// beforeBackground, when set (tests only), runs as a heartbeat's pass is about to be registered with Close (workerReported).
	beforeBackground func()

	// prog is the last progress report of the worker's nmap, by run (runSink): the summaries of the running device runs read it.
	// progMu is its own lock: the Dispatcher reports under its lock, and nothing here calls the Dispatcher while holding progMu.
	// bg is the work started on a goroutine of its own (workerReported); closed refuses more of it once Close began. bgMu guards closed
	// and every bg.Add, so no pass is counted after Close's bg.Wait began.
	bg     sync.WaitGroup
	bgMu   sync.Mutex
	closed bool
	waking atomic.Bool // a workerReported pass is going on: another heartbeat meanwhile starts none
	// since is when this process started: a person's check waits personWaitMax for the scan worker from then at the earliest, since
	// the worker starts with it (resumePersonsChecks).
	since  time.Time
	progMu sync.Mutex
	prog   map[string]runProg
	// typical and typicalAt: how long a device check takes on this box and when that was read (typicalCheck), under mu.
	typical   time.Duration
	typicalAt time.Time
	// deviceTook is, by device, how long its own recent checks took and when that was read (deviceCheck), under mu.
	deviceTook map[string]tookAt

	mu      sync.Mutex
	cur     *running // the job holding runMu, for SettingsChanged
	snmpCur *snmpRun // the snmp batch holding snmpMu, for SettingsChanged, AssetChanged and Stop
	// allPortsHeld are the devices whose weekly run failed in the window that started at allPortsHeldIn: the round leaves them
	// to the next window.
	allPortsHeld   map[string]bool
	allPortsHeldIn time.Time
	// firstUntil is set while the first pass of a new box runs (firstPass): until then the window counts as open. Zero otherwise.
	firstUntil time.Time
	// personUntil is the end of the hour of a pass a person asked to go on now (Scan the LAN now on a pass that waited for the
	// window), by run: in memory, so a restart leaves the pass to the window.
	personUntil map[string]time.Time
	// yielded is the passes that wait only because they gave way to other work in the nmap lane: they go on once it is done
	// (resumeYielded, followPass); a pass that waits for anything else is resumed by the window's driver only.
	yielded map[string]bool
}

func (s *Service) setYielded(id string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.yielded == nil {
		s.yielded = map[string]bool{}
	}
	if on {
		s.yielded[id] = true
	} else {
		delete(s.yielded, id)
	}
}

// recoverYielded marks, at start, a person's pass that waits within its hour as one that gave way (a pass of a person can wait in
// its hour for nothing else but the lane, the worker or the settings): the end of the next run of the lane, or the window's driver,
// resumes it, as before the restart. The hour of a window's pass a person asked to go on now (personUntil) is not kept: that pass
// waits for the window after a restart.
func (s *Service) recoverYielded(ctx context.Context) {
	sw, err := s.liveRun(ctx, RunSweep)
	if err != nil || sw == nil || sw.Status != run.Waiting || !s.clock().Before(s.sweepUntil(*sw)) {
		return
	}
	s.setYielded(sw.ID, true)
}

func (s *Service) isYielded(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.yielded[id]
}

// firstPassFor bounds the first pass: it may run outside the window for at most this long; a sweep it did not finish goes on from
// its cursor in the next window.
const firstPassFor = time.Hour

// windowNow is the window rule of every automatic run (INV-3): whether the window is open now, and when it ends. Inside a window it
// is that window's own end, whatever else runs. Outside one it is open until firstUntil while the first pass of a new box runs,
// and, for the runs of a person's "Scan the LAN now" only (ctx marked by withManualUntil: the person's sweep and the checks of the
// devices it found), until the end of its hour (INV-21, #857): a manual run never opens or lengthens the window of the box's own
// runs (rounds, queue, SNMP).
func (s *Service) windowNow(ctx context.Context, st Settings) (end time.Time, ok bool) {
	if _, end, ok = st.window(s.local()); ok {
		return end, true
	}
	s.mu.Lock()
	until := s.firstUntil
	s.mu.Unlock()
	if m := manualUntil(ctx); m.After(until) {
		until = m
	}
	if s.clock().Before(until) {
		return until, true
	}
	return time.Time{}, false
}

type running struct {
	cancel context.CancelFunc
	// why is the first reason the run was stopped for while it ran (stopCur), nil when nothing stopped it: its run says that one reason,
	// and a person's check goes on after a reason it can survive (stopCause.again).
	why      error
	targets  []netip.Addr  // the run in progress, published before it is checked
	rate     int           // the packets per second of the run
	deadline time.Time     // when the run in progress stops by itself: the end of the window it was checked against, or maxRun
	asset    string        // the device a device run is for ("" for a sweep), set before its policy is read
	gentle   bool          // the run is the one gentle scan
	kind     nmapargv.Kind // the command shape of a device run (GentleTitles must stop when the device turns fragile)
	// picked: the identification of a device a person picked in Scan now (IdentifyDevice). Like the vulnerability scan
	// it is part of, it runs at once: the window does not apply (its deadline is maxRun). Every other rule does.
	picked bool
	// external: service identification on the box's own public IP for exposure (ScanExternal). Its consent is exposure's,
	// so the LAN settings, window and scope do not bind it; only Stop (the module turned off) and its own context end it.
	external bool
	// weekly: the weekly scan of every port of a device, with its -sV follow-up. A Scan now identification or an exposure
	// scan stops it (lockWithin); it stays due.
	weekly bool
	// pace and paceFrom: the rate of the weekly discovery and when it started, for the time it has left (allPortsEstimate).
	pace     int
	paceFrom time.Time
	started  time.Time // when it was registered (setCur), for Settings › Scanning
	// until: a run of a person's "Scan the LAN now" (INV-21): the window it is checked against is open until then too (windowNow).
	until time.Time
	// runID is the run whose work it is (core_run), for Settings › Scanning.
	runID string
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Inventory == nil || cfg.Observe == nil || cfg.Software == nil {
		return nil, errors.New("sensoractive: New needs DB, Inventory, Observe and Software")
	}
	s := &Service{pend: map[string]*pending{}, waits: map[string]chan outcome{}, db: cfg.DB, inv: cfg.Inventory, obs: cfg.Observe, sw: cfg.Software, svc: cfg.Services, events: cfg.Events, path: cfg.NmapPath, clock: cfg.Clock, log: cfg.Log, loc: cfg.Location, budget: capture.NewFloodBudgetLimits(sweepNewPerMinute, sweepNewPerHour)}
	if s.clock == nil {
		s.clock = time.Now
	}
	s.since = s.clock()
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.prober = cfg.Prober
	if s.prober == nil {
		p, err := NewLocalProber(s.log, cfg.NmapPath)
		if err != nil {
			return nil, err
		}
		s.prober = p
	}
	s.secrets, s.audit, s.snmp = cfg.Secrets, cfg.Audit, cfg.SNMP
	s.localNets = cfg.LocalPrefixes
	if r, ok := s.prober.(SNMPReader); ok && s.snmp == nil {
		s.snmp = r // the Dispatcher sends the reads to the scan worker too
	}
	s.runs = cfg.Runs
	if s.runs == nil {
		m, err := run.New(run.Config{DB: cfg.DB, Audit: cfg.Audit, Log: s.log, Clock: s.clock, Gate: moduleGate{s}})
		if err != nil {
			return nil, err
		}
		s.runs, s.ownRuns = m, true
	}
	if err := s.registerKinds(); err != nil {
		return nil, err
	}
	if r, ok := s.prober.(workerReporter); ok {
		r.OnReport(s.workerReported) // a person's check that waits for the scan worker starts when it reports
	}
	s.recoverYielded(context.Background())
	if s.ownRuns {
		if err := s.runs.Start(context.Background()); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// moduleGate is the module switch of a run manager of the service's own: on unless Stop ran (and no Resume since).
type moduleGate struct{ s *Service }

func (g moduleGate) Enabled(id string) bool { return id != ModuleID || !g.s.off.Load() }

// Close stops the run manager the service made itself (Config.Runs nil); a shared one is the box's to close.
func (s *Service) Close() {
	s.bgMu.Lock()
	s.closed = true
	s.bgMu.Unlock()
	s.bg.Wait()
	if s.ownRuns {
		s.runs.Close()
	}
}

// Runs is the run manager the service's runs are on.
func (s *Service) Runs() *run.Manager { return s.runs }

func (s *Service) now() string { return store.FormatTS(s.clock()) }

func (s *Service) zone() *time.Location {
	if s.loc != nil {
		if l := s.loc(); l != nil {
			return l
		}
	}
	return time.Local
}

func (s *Service) local() time.Time { return s.clock().In(s.zone()) }

func (s *Service) publish(ctx context.Context, name string, data any) {
	if s.events == nil {
		return
	}
	if err := s.events.Publish(ctx, Event{Name: name, Data: data}); err != nil {
		s.log.WarnContext(ctx, "sensoractive: publishing an event failed", "event", name, "error", err)
	}
}

// Health reports INV-6: nmap is the OS package, and without it the module has no way to work. It also names
// the time zone of the windows, and warns while a full sweep cannot fit in one window.
func (s *Service) Health(ctx context.Context) Health {
	h := Health{Status: "ok", Zone: s.zone().String()}
	if hp, remote := s.prober.(nmapHealther); remote {
		// nmap lives in the scan container: its worker's heartbeat says whether it can run.
		if msg := hp.NmapHealth(); msg != "" {
			h.Status, h.Message = "unavailable", msg
		}
	} else {
		fi, err := os.Stat(s.path)
		switch {
		case err != nil:
			h.Status, h.Message = "unavailable", "nmap is not installed at "+s.path+"; active discovery cannot run until it is installed"
		case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
			h.Status, h.Message = "unavailable", s.path+" is not an executable file; active discovery cannot run"
		}
	}
	if st, err := s.inv.Settings(ctx); err == nil {
		h.Warning = st.sweepWarning(s.localPrefixes(ctx))
		if h.Warning == "" && st.allowed() == nil && st.Rate < nmapargv.AllPortsMinRate {
			h.Warning = fmt.Sprintf("the weekly scan of every port of each device needs a scan rate of at least %d packets/s; at %d it does not run, so services on unusual ports are not found", nmapargv.AllPortsMinRate, st.Rate)
		}
	}
	return h
}

// localPrefixes is Config.LocalPrefixes, or none.
func (s *Service) localPrefixes(ctx context.Context) []netip.Prefix {
	if s.localNets == nil {
		return nil
	}
	return s.localNets(ctx)
}

// sweepWarning is set when a sweep of the scope does not fit one window: it then needs several days, resuming each day
// where the window cut it. An address on one of the local networks (the box's own segments) costs one ARP request;
// one behind a router costs nmapargv.SweepProbes packets, more when nmap sends a silent address another round, so the
// estimate is a floor.
func (st Settings) sweepWarning(local []netip.Prefix) string {
	if st.allowed() != nil || st.Rate < 1 {
		return ""
	}
	sc := newScope(st)
	n, near := sc.count(), sc.within(local).count()
	far := n - near
	need := time.Duration(near+far*nmapargv.SweepProbes) * time.Second / time.Duration(st.Rate)
	if have := st.windowLength(); have > 0 && need > have {
		return fmt.Sprintf("a sweep of about %d addresses (%d on the box's own networks at one packet each, %d behind a router at %d or more) at %d packets/s needs at least %s but a window lasts %s; one pass will take several days",
			n, near, far, nmapargv.SweepProbes, st.Rate, need.Round(time.Minute), have)
	}
	return ""
}

func (s *Service) available(ctx context.Context) error {
	if h := s.Health(ctx); h.Status != "ok" {
		return fmt.Errorf("%w: %s", ErrUnavailable, h.Message)
	}
	return nil
}

// workerAbsent says the scan worker has not reported yet (after a restart) or for 90 seconds: the scanner comes back by itself.
func (s *Service) workerAbsent() bool {
	w, ok := s.prober.(workerWaiter)
	return ok && w.WorkerAbsent()
}

// permit is the gate of every run (INV-2, INV-3, INV-6): the settings now, the window now, nmap present. It
// returns the settings it read.
func (s *Service) permit(ctx context.Context) (Settings, error) {
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := st.allowed(); err != nil {
		return st, err
	}
	if _, ok := s.windowNow(ctx, st); !ok {
		return st, ErrOutsideWindow
	}
	if err := s.available(ctx); err != nil {
		return st, err
	}
	return st, nil
}

// reasonOf is the text of sensor.scan.blocked for a refusal of INV-2.
func reasonOf(err error) string {
	switch {
	case errors.Is(err, ErrScanningOff):
		return "scanning_off"
	case errors.Is(err, ErrScopeNotConfirmed):
		return "scope_not_confirmed"
	}
	return "out_of_scope"
}

func (s *Service) blocked(ctx context.Context, assetID, reason string) {
	s.log.InfoContext(ctx, "sensoractive: scan blocked, no packet sent", "asset", assetID, "reason", reason)
	s.publish(ctx, EventScanBlocked, BlockedEvent{AssetID: assetID, Reason: reason})
}

// ---- jobs ----

// startJob says the work of ctx's run starts (sensor.scan.started) and returns the run's id: the run_id of its probes.
func (s *Service) startJob(ctx context.Context, kind, _ string, targets int) (string, error) {
	x := execOf(ctx)
	if x == nil {
		return "", errors.New("sensoractive: work outside a run")
	}
	s.publish(ctx, EventScanStarted, StartedEvent{JobID: x.ID(), Kind: kind, Targets: targets})
	return x.ID(), nil
}

// finishJob says the work of a run ended (sensor.scan.finished) and writes the line of its log; core/run records the run's end.
func (s *Service) finishJob(ctx context.Context, id, status string, targets, newDevices int, errText string) {
	if run.ShuttingDown(ctx) {
		errText = "" // Vedette is stopping: the next start says the restart stopped it ("Stopped: Vedette restarted")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	if x := execOf(ctx); x != nil && errText != "" {
		lvl := run.Warn
		if status == StatusFailed {
			lvl = run.Error
		}
		s.runWrite(ctx, "log", x.Log(ctx, lvl, clip(errText, 1000)))
	}
	s.publish(ctx, EventScanFinished, FinishedEvent{JobID: id, Targets: targets, NewDevices: newDevices, Status: status})
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// ---- the run of nmap ----

// errDeadline is ErrStopped for a run cut by its own deadline (the end of the window or maxRun), as opposed to
// a stop for a change of settings: the queue counts it as an attempt.
var errDeadline = fmt.Errorf("%w: its deadline passed", ErrStopped)

// probe runs one nmap command over targets and returns the hosts that answered. Order matters (INV-1, INV-2,
// INV-3): the run's targets are published first, so SettingsChanged can see them; then the settings, the
// window and the scope are read again for every target (and a sweep batch's protected list); only then the probe row is written (INV-9: no packet
// without a log line) and nmap started, unless a SettingsChanged arrived in between. The deadline is the
// window's end or maxRun; when it passes, or ctx is cancelled, exec kills the process group and the batch is
// dropped (PRE-3, POST-3).
func (s *Service) probe(ctx context.Context, jobID string, kind nmapargv.Kind, rate int, targets []netip.Addr, ports ...int) ([]host, error) {
	if _, err := nmapargv.BuildFor(kind, rate, ports, targets); err != nil {
		return nil, err
	}
	v0 := s.ver.Load()
	s.setTargets(targets, rate)
	defer s.setTargets(nil, 0)

	st, err := s.inv.Settings(ctx)
	if err == nil {
		err = st.allowed()
	}
	if err != nil {
		return nil, s.stopFor(err)
	}
	picked := s.isPicked()
	end, ok := s.windowNow(ctx, st)
	if !ok && !picked {
		return nil, ErrStopped
	}
	sc := newScope(st)
	if slices.ContainsFunc(targets, func(t netip.Addr) bool { return !sc.contains(t) }) {
		return nil, ErrStopped
	}
	// A device run: the device must still be at the address, read again after the targets were published (#882,
	// #881). Between two scans of one run (probeDevice's Extra run, the -sV of every-port scan) the targets are cleared, so checkRun
	// could not compare a move with them; a move before this read is seen here, one after it reaches checkRun.
	s.mu.Lock()
	var asset string
	if s.cur != nil {
		asset = s.cur.asset
	}
	s.mu.Unlock()
	if asset != "" {
		a, err := s.inv.Asset(ctx, asset)
		switch {
		case errors.Is(err, ErrNotFound):
			return nil, errDeviceGone
		case err == nil && !slices.Contains(targets, a.IP):
			return nil, errLeftAddress
		case err != nil && ctx.Err() != nil:
			return nil, ErrStopped
		case err != nil:
			return nil, err
		}
	}
	// A sweep batch: the protected list is read again now that the targets are published. A device changed after the batch was chosen
	// (its network scan turned off, set to never) and before this point sent its event while no batch was published, so nothing stopped
	// it; one changed after this read finds the targets published and stops the batch (checkSweep). A read that fails stops it too.
	if kind == nmapargv.Sweep {
		prot, err := s.inv.ProtectedIPs(ctx)
		if err != nil || slices.ContainsFunc(targets, func(t netip.Addr) bool {
			return slices.ContainsFunc(prot, func(p netip.Addr) bool { return p.Unmap() == t.Unmap() })
		}) {
			return nil, errBatchProtected
		}
	}
	rate = min(rate, st.Rate)
	args, err := nmapargv.BuildFor(kind, rate, ports, targets)
	if err != nil {
		return nil, err
	}
	timeout := maxRun // a picked identification is not bound to the window
	if !picked {
		timeout = min(end.Sub(s.clock()), maxRun)
	}
	if timeout <= 0 || ctx.Err() != nil {
		return nil, ErrStopped
	}
	s.setDeadline(s.clock().Add(timeout))
	probeID, err := s.insertProbe(ctx, jobID, kind, rate, targets, probeNote{}, ports...)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || s.ver.Load() != v0 {
		why := s.curWhy()
		if why == nil && ctx.Err() == nil {
			why = errSettingsMoved // the settings changed between their check and nmap: the run reads them again
		}
		s.finishProbe(ctx, probeID, stoppedLine(why))
		return nil, cmpErr(why, ErrStopped)
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, runErr := s.prober.Probe(rctx, args)
	all, result, err := runOutcome(ctx, rctx, res, runErr)
	if result == stoppedText && !errors.Is(err, errDeadline) {
		if why := s.curWhy(); why != nil {
			result, err = stoppedLine(why), why
		}
	}
	var hosts []host
	if err == nil {
		hosts = onlyTargets(all, targets)
		result = fmt.Sprintf("ok: %d hosts up", len(hosts))
	}
	s.finishProbe(ctx, probeID, result)
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

// runOutcome turns the end of one nmap run into every host nmap reported up (parseNmapXML: the caller keeps the ones it asked
// about), and, when the run failed, the result of its probe row and the error: a stop (ctx or rctx over), a failure of nmap or the
// worker, output over the limit, or output that is not valid (INV-7). It is shared by the LAN runs (probe) and the external one
// (ScanExternal); on success the caller writes the result.
func runOutcome(ctx, rctx context.Context, res Output, runErr error) (hosts []host, result string, err error) {
	switch {
	case rctx.Err() != nil || ctx.Err() != nil:
		result, err = stoppedText, ErrStopped
		if ctx.Err() == nil && errors.Is(rctx.Err(), context.DeadlineExceeded) {
			err = errDeadline
		}
	case runErr != nil:
		var ee *exec.ExitError
		switch {
		case errors.As(runErr, &ee):
			result = fmt.Sprintf("failed: nmap exited with code %d", ee.ExitCode)
		case errors.Is(runErr, errXMLTooBig):
			result = "failed: output over the size limit, discarded"
		case errors.Is(runErr, ErrWorkerUnavailable):
			result = "failed: worker_unavailable"
		case errors.Is(runErr, ErrNmapMissing):
			result = "failed: nmap_missing"
		case errors.Is(runErr, ErrWorkerLost):
			result = "failed: worker_lost"
		case errors.Is(runErr, ErrStoppedMidRun) && errors.Is(runErr, ErrNotOwnIP):
			result = "stopped: while nmap ran, the scan worker found the address is no longer the box's own public IP; output discarded"
		case errors.Is(runErr, ErrStoppedMidRun):
			result = "stopped: while nmap ran, the scan worker could no longer reach the public IP services to check the address; output discarded"
		case errors.Is(runErr, ErrNotOwnIP):
			result = "refused: the scan worker found the address is not the box's own public IP now; nmap did not run"
		case errors.Is(runErr, ErrEgressUnverified):
			result = "refused: the scan worker could not reach the public IP services to check the address; nmap did not run"
		case errors.Is(runErr, ErrPortsUnsupported):
			result = "refused: the scan worker is older and takes no port list; nmap did not run"
		case errors.Is(runErr, ErrFullUnsupported):
			result = "refused: the scan worker is older and runs no deep scan; nmap did not run"
		case errors.Is(runErr, ErrWorkerRefused):
			result = "failed: the worker refused the job"
		case errors.Is(runErr, ErrResultRejected):
			result = "failed: the worker's result was rejected"
		default:
			result = "failed: nmap could not run"
		}
		err = fmt.Errorf("sensoractive: %w", runErr)
	case res.Truncated:
		result, err = "failed: output over the size limit, discarded", errXMLTooBig
	default:
		if hosts, err = parseNmapXML(res.XML); err != nil {
			result = "failed: output not valid, discarded"
		}
	}
	return hosts, result, err
}

// Reasons of the inventory's ScanPolicy that are states of the box, not of the device.
const (
	reasonScanningOff       = "scanning_off"
	reasonScopeNotConfirmed = "scope_not_confirmed"
	// Reasons of a device that discovery leaves to the passive sensors after its one gentle scan; a pick in Scan now still
	// identifies it (pickedPlan).
	reasonFragilePassive      = "fragile_passive_only"
	reasonUnclassifiedPassive = "unclassified_passive_only"
	reasonNever               = "regular_scan_never"
	reasonBox                 = "box"
	reasonSNMPOff             = "snmp_off" // a person turned SNMP off for the device (SNMPPolicy only)
	reasonExcluded            = "excluded" // the address is on the exclusion list (SNMPPolicy only: SNMP is not bound by lan_ranges)
)

const stoppedText = "stopped: the window closed, the scope changed or the module was turned off"

// stopFor turns a refusal found while checking a run into the error of the caller: a read failure stays one,
// a settings refusal (scanning off, scope not confirmed, no ranges) is a stop.
func (s *Service) stopFor(err error) error {
	if errors.Is(err, ErrScanningOff) || errors.Is(err, ErrScopeNotConfirmed) || errors.Is(err, ErrNoRanges) {
		return ErrStopped
	}
	return err
}

func (s *Service) setTargets(t []netip.Addr, rate int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.targets, s.cur.rate = t, rate
	}
}

// Stop cancels the run in progress, whatever it is: the module was turned off (SYS-5). The scheduler stops the jobs it runs; an
// identification for Scan now runs on the scan module's goroutine, so only this reaches it.
func (s *Service) Stop() {
	s.stops.Add(1)
	s.off.Store(true) // before snmpCur is read under s.mu: a batch registering now either is seen here or sees off (snmpBatch)
	s.mu.Lock()
	cur, snmp := s.cur, s.snmpCur
	s.mu.Unlock()
	if cur != nil {
		s.stopCur(cur, errModuleOff)
	}
	// its runs that have not ended stop too: on the box core/run does it when the module switch moves; a manager of the service's own
	// (tests) has no switch board
	if s.ownRuns {
		s.runs.ModuleChanged(ModuleID, false)
	}
	if snmp != nil {
		snmp.cancel()
	}
}

// Resume is the module turned on again: SNMP reads may be sent again (Stop's off flag is cleared).
func (s *Service) Resume() {
	s.off.Store(false)
	if s.ownRuns { // its queued runs start again (on the box core/run hears the module switch itself)
		s.runs.ModuleChanged(ModuleID, true)
	}
}

// isPicked says the registered run is an identification a person asked for (running.picked).
func (s *Service) isPicked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur != nil && s.cur.picked
}

func (s *Service) setDeadline(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.deadline = t
	}
}

// compactTargets writes the addresses of a batch, in the order they were sent, as merged ranges: "a-b,c,d-e". A
// sweep batch has holes where it skipped protected devices, so only this says which addresses were probed. At
// most 64 addresses: at most 64 pieces of at most 15 characters, 1023 in all.
func compactTargets(ts []netip.Addr) string {
	var parts []string
	for i := 0; i < len(ts); {
		j := i
		for j+1 < len(ts) && ts[j+1] == ts[j].Next() {
			j++
		}
		if j == i {
			parts = append(parts, ts[i].String())
		} else {
			parts = append(parts, ts[i].String()+"-"+ts[j].String())
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

func (s *Service) insertProbe(ctx context.Context, runID string, kind nmapargv.Kind, rate int, targets []netip.Addr, note probeNote, ports ...int) (int64, error) {
	if kind.IsGentle() {
		rate = 1
	}
	flags, err := nmapargv.FlagsFor(kind, rate, ports)
	if err != nil {
		return 0, err
	}
	return s.insertProbeFlags(ctx, runID, kind, rate, targets, note, flags)
}

// insertProbeFlags is insertProbe with the flag part already built (an external -sV batch carries its host timeout).
func (s *Service) insertProbeFlags(ctx context.Context, runID string, kind nmapargv.Kind, rate int, targets []netip.Addr, note probeNote, flags []string) (int64, error) {
	var id int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			s.now(), nullable(runID), kind.Name(), rate, len(targets), strings.Join(append(flags, nmapargv.StatsFlags()...), " "), compactTargets(targets), note.with("started"))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("sensoractive: probe log: %w", err)
	}
	return id, nil
}

func (s *Service) finishProbe(ctx context.Context, id int64, result string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	result = clipRunes(result, maxProbeResult) // a result never fails its own CHECK and leaves the row "started"
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sa_probe SET result = ? WHERE id = ?`, result, id)
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sensoractive: updating the probe log failed", "probe", id, "error", err)
	}
}

// Probes returns the probe log from since on, oldest first, at most limit rows (INV-9). Argv is the flag part stored with the row, so
// history stays true when the templates change; Target is the merged ranges of the addresses probed.
func (s *Service) Probes(ctx context.Context, since time.Time, limit int) ([]Probe, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT time, shape, rate, flags, targets, result, COALESCE(run_id, '') FROM sa_probe WHERE time >= ? ORDER BY id LIMIT ?`, store.FormatTS(since), clamp(limit, 1, 100000))
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read probes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Probe
	for rows.Next() {
		var p Probe
		var flags string
		if err := rows.Scan(&p.Time, &p.Shape, &p.Rate, &flags, &p.Target, &p.Result, &p.JobID); err != nil {
			return nil, fmt.Errorf("sensoractive: read probes: %w", err)
		}
		p.Argv = append(strings.Fields(flags), "-oX", "-")
		out = append(out, p)
	}
	return out, rows.Err()
}

// ExportProbes is the "scan_probes" source of GET /core/logs/export (core INV-13): the probe log from through to, oldest
// first, as JSON lines, the columns of the table (argv is the stored flag part, targets the merged ranges). A zero time is open.
// It takes the database, not the Service, so it works on a box where nmap is missing and the service cannot be built.
func ExportProbes(ctx context.Context, db *store.DB, from, to time.Time, w io.Writer) error {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return logexport.Rows{SQL: `SELECT id, time, run_id, shape, rate, hosts, flags, targets, result FROM sa_probe
		WHERE (? = '' OR time >= ?) AND (? = '' OR time <= ?) ORDER BY id`, Args: []any{lo, lo, hi, hi}}.Write(ctx, db.Reader(), w)
}

// Prune deletes probe rows older than ProbeRetention and returns how many went (core/run prunes the runs).
func (s *Service) Prune(ctx context.Context) (int, error) {
	var n int64
	cutoff := store.FormatTS(s.clock().Add(-ProbeRetention))
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sa_probe WHERE time < ?`, cutoff)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return int(n), err
}

// ---- the sweep ----

// Result is what a finished run reports.
type Result struct {
	JobID      string
	Targets    int
	NewDevices int
	Status     string
}

// knownMACs reads the MAC of every device of the inventory (uncapped, lower case).
func (s *Service) knownMACs(ctx context.Context) (map[string]bool, error) {
	l, err := s.inv.KnownMACs(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(l))
	for _, x := range l {
		m[strings.ToLower(x)] = true
	}
	return m, nil
}

// recordSweep stores what a sweep batch found and returns how many of the hosts are new devices. A device is told by its MAC: one the
// inventory already has is free whatever its IP (DHCP churn), every other MAC is charged against the budget of new devices, even at
// an IP the inventory already has. Only the first entry for a target counts: one result can carry many for one address. known is the
// MACs of the inventory and gains the MACs recorded here.
func (s *Service) recordSweep(ctx context.Context, hosts []host, batch []netip.Addr, known map[string]bool) (map[netip.Addr]bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	var obs []observe.Observation
	var claims []capture.Claim // the MACs new to the inventory
	var claimObs [][]observe.Observation
	seen := map[netip.Addr]bool{}
	for _, h := range onlyTargets(hosts, batch) {
		if seen[h.addr] {
			continue
		}
		seen[h.addr] = true
		o := sweepObservations(h)
		if len(o) == 0 {
			continue
		}
		mk := strings.ToLower(h.mac)
		if known[mk] {
			obs = append(obs, o...)
			continue
		}
		claims = append(claims, capture.Claim{MAC: mk, IP: h.addr, Field: observe.MAC, Value: mk})
		claimObs = append(claimObs, o)
	}
	now := s.clock()
	verdicts := s.budget.Decide(claims, now)
	var admitted []capture.Claim
	var admittedV []capture.Verdict
	for i, c := range claims {
		if !verdicts[i].Admit {
			continue
		}
		obs = append(obs, claimObs[i]...)
		admitted, admittedV = append(admitted, c), append(admittedV, verdicts[i])
	}
	if n := len(claims) - len(admitted); n > 0 {
		s.log.WarnContext(ctx, "sensoractive: new devices over the budget were not recorded", "dropped", n)
	}
	if len(obs) == 0 {
		return nil, nil
	}
	if err := s.obs.Record(ctx, obs); err != nil {
		return nil, fmt.Errorf("sensoractive: recording hosts: %w", err) // the budget is not spent: the next try meets the same budget
	}
	s.budget.Commit(admitted, admittedV, now)
	fresh := map[netip.Addr]bool{}
	for _, c := range admitted {
		if !known[c.MAC] {
			known[c.MAC] = true
			fresh[c.IP] = true
		}
	}
	return fresh, nil
}

// setKind records the command shape of the device run in progress (and whether it is a gentle one).
func (s *Service) setKind(k nmapargv.Kind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.kind, s.cur.gentle = k, k.IsGentle()
	}
}

func (s *Service) setAsset(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.asset = id
	}
}

func (s *Service) setCur(r *running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r != nil && r.started.IsZero() {
		r.started = s.clock()
	}
	s.cur = r
}

// runIDOf is the id of ctx's run, "" outside one.
func runIDOf(ctx context.Context) string {
	if x := execOf(ctx); x != nil {
		return x.ID()
	}
	return ""
}

// ---- one device ----

// ScanDevice identifies one device with nmap (PRE-2): the inventory's ScanPolicy must allow it, the window
// must be open (even the one gentle scan of a device that is fragile or not yet classified waits for
// it), and the device's address must be in scope immediately before the command line is built (INV-1). The run
// is registered before the checks and its address published as soon as it is known, so a SettingsChanged that
// arrives while it is still checking reaches it. A refusal by policy or scope publishes
// sensor.scan.blocked and sends nothing. reason says why it was asked ("discovered", ...).
// Outside a run (a caller of its own) the check is a device_check run made for it, which it waits for.
func (s *Service) ScanDevice(ctx context.Context, assetID, reason string) error {
	if execOf(ctx) != nil {
		return s.scanDevice(ctx, assetID, reason, false)
	}
	if st, err := s.inv.Settings(ctx); err != nil { // nothing may run: no run is recorded
		return err
	} else if err := st.allowed(); err != nil {
		s.blocked(ctx, assetID, reasonOf(err))
		return err
	}
	if err := s.available(ctx); err != nil {
		return err
	}
	lbl := assetID // no read of the device before its checks: they read it in order (INV-1)
	words := reasonWords[reason]
	return s.doWork(ctx, run.Spec{Kind: RunCheck, Title: "Check of " + lbl, Trigger: run.Event, TriggerNote: words,
		Subject: &run.Subject{Kind: "device", ID: assetID, Label: lbl}, Steps: []run.StepPlan{{Name: lbl, Total: 1}}},
		func(ctx context.Context) error { return s.scanDevice(ctx, assetID, reason, false) },
		func(ctx context.Context, err error) run.Result {
			r := s.scanResult(ctx, err)
			if r.Status == run.Waiting { // its caller asks again: this run does not wait
				return run.Result{Status: run.Partial, Error: "Not done: it waits for " + r.WaitingFor}
			}
			return r
		}, 0, "")
}

// scanDevice is ScanDevice; all makes it the weekly scan of every port (nmapargv.AllPorts), which only a device that is not
// fragile, not of unknown kind and past its gentle scan gets (allPortsPlan): any other answer of the policy is ErrBlocked, nothing
// sent.
func (s *Service) scanDevice(ctx context.Context, assetID, reason string, all bool) error {
	s.lockRun(ctx)
	defer s.runMu.Unlock()
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The weekly run is registered with its kind before its policy is read, so a change of the device in between
	// reaches it.
	cur := &running{cancel: cancel, asset: assetID, weekly: all, until: manualUntil(ctx), runID: runIDOf(ctx)}
	if all {
		cur.kind = nmapargv.AllPorts
	}
	s.setCur(cur)
	defer s.setCur(nil)
	if all { // other work waits for the nmap lane (a person's check, a scan for exposure): it goes first
		if other, _, err := s.laneBusy(jctx, runIDOf(ctx)); err == nil && other != "" {
			return ErrStopped
		}
	}
	// A run stopped by a settings or device change while it checks is not a failure: whatever the storage
	// read then returns (context canceled), the caller sees ErrStopped and does not count an attempt.
	stopped := func(err error) error {
		if jctx.Err() != nil {
			return ErrStopped
		}
		return err
	}
	dec, err := s.inv.ScanPolicy(jctx, assetID)
	if err != nil {
		return stopped(err)
	}
	if !dec.Allowed {
		// scanning off and an unconfirmed scope are states of the box, not of the device: the device stays queued
		switch dec.Reason {
		case reasonScanningOff:
			s.blocked(ctx, assetID, dec.Reason)
			return ErrScanningOff
		case reasonScopeNotConfirmed:
			s.blocked(ctx, assetID, dec.Reason)
			return ErrScopeNotConfirmed
		}
		s.blocked(ctx, assetID, dec.Reason)
		return fmt.Errorf("%w: %s", ErrBlocked, dec.Reason)
	}
	st, err := s.permit(jctx)
	switch {
	case errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
		s.blocked(ctx, assetID, reasonOf(err))
		return err
	case err != nil:
		return stopped(err)
	}
	asset, err := s.inv.Asset(jctx, assetID)
	if err != nil {
		return stopped(err)
	}
	in := false
	if asset.IP.IsValid() {
		s.setTargets([]netip.Addr{asset.IP}, st.Rate)
		if in, err = s.inv.InScope(jctx, asset.IP); err != nil {
			return stopped(err)
		}
	}
	if !in {
		s.blocked(ctx, assetID, "out_of_scope")
		return fmt.Errorf("%w: out_of_scope", ErrBlocked)
	}
	// Defence in depth: the box's own addresses and its decoys are never scanned, whatever the policy of the row says.
	box, err := s.inv.BoxIPs(jctx)
	if err != nil {
		return stopped(err)
	}
	if slices.Contains(box, asset.IP) {
		s.blocked(ctx, assetID, reasonBox)
		return fmt.Errorf("%w: %s", ErrBlocked, reasonBox)
	}
	kind, rate := nmapargv.Normal, st.Rate
	if dec.Rate > 0 {
		rate = min(rate, dec.Rate)
	}
	normalRate := rate
	if dec.FirstGentle {
		kind, rate = gentleShape(dec), 1
	}
	if all {
		r, why := allPortsPlan(dec, st)
		if why != "" { // checked again here, under the lock: the device may have turned fragile since it was picked (FORBID-5)
			return fmt.Errorf("%w: %s", ErrBlocked, why)
		}
		kind, rate = nmapargv.AllPorts, r
	}
	s.setKind(kind)

	id, err := s.startJob(ctx, KindDevice, reason, 1)
	if err != nil {
		return err
	}
	var hosts []host
	recKind, extraFailed := kind, false
	if all {
		s.mu.Lock()
		cur.pace, cur.paceFrom = rate, s.clock()
		s.mu.Unlock()
		hosts, err = s.probeAllPorts(jctx, id, assetID, asset.IP, rate, normalRate)
		if err == nil {
			err = weeklyAnswered(hosts, asset.IP) // a device that never answered taught the scan nothing: it is not "done"
		}
	} else {
		hosts, recKind, extraFailed, err = s.probeDevice(jctx, id, kind, rate, asset.IP)
	}
	if err != nil {
		err = stopped(err) // a cancel (a person's scan, a change of the device or the settings) is a stop, never a failure
	}
	s.setAsset("") // nmap is done: a change of the device now has nothing to stop
	if err == nil {
		// nmap finished: the gentle scan happened, whatever becomes of recording its results
		var markErr error
		if dec.FirstGentle {
			markErr = s.inv.MarkFirstScan(context.WithoutCancel(ctx), assetID)
		}
		err = errors.Join(markErr, s.recordDevice(ctx, id, assetID, asset.IP, hosts, recKind, extraFailed))
	}
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, id, StatusStopped, 0, 0, stoppedLine(cmpErr(s.whyStopped(cur), err)))
	default:
		s.finishJob(ctx, id, StatusFailed, 0, 0, err.Error())
	}
	return err
}

// The weekly scan of every port that learned nothing about its device: it never answered on any port (off, or a firewall that drops
// every probe), or nmap's host timeout cut it before it printed a port table.
var (
	errNoAnswer      = errors.New("sensoractive: the device did not answer on any port")
	errHostTimedOut  = errors.New("sensoractive: the scan of every port did not finish within its time limit")
	weeklyNoAnswer   = "No answer from the device on any port: it may be off, or a firewall drops every probe."
	weeklyTimedOutAt = "The scan of every port did not finish within its %s limit, so nothing was recorded."
)

// What happens after a weekly scan of every port failed (failAllPorts): the first failure is tried once more in the next window, a
// second one in a row waits for the next week.
const (
	weeklyRetryNext = "It is tried again in the next window"
	weeklyRetryWeek = "It failed in its last try too, so it is tried again next week"
)

// weeklyAnswered is nil when the weekly discovery heard ip on at least one port, else why it learned nothing.
func weeklyAnswered(hosts []host, ip netip.Addr) error {
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	switch {
	case i < 0:
		return errNoAnswer
	case hosts[i].timedOut:
		return errHostTimedOut
	}
	return nil
}

// recordDevice stores what a service scan found about ip. A host that did not answer changes nothing. A host that hit the host
// timeout keeps its software and services: nmap printed no port table for it, so an empty list would wrongly remove them. Only a
// normal or versions scan (top 1000 ports and the extra ports, -sV) replaces the device's nmap services and software, only for the
// ports it looked at; the weekly scan of every port replaces the services of every port (it read no versions), then the services
// and the software of the ports its -sV follow-up read; a gentle scan (top 100, no -sV) and an Extra run that alone saw the device only add ports,
// and never wipe what a normal scan found.
func (s *Service) recordDevice(ctx context.Context, jobID, assetID string, ip netip.Addr, hosts []host, kind nmapargv.Kind, extraFailed bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 {
		return nil
	}
	h := hosts[i]
	// what this check found, in words for History and the device page, compared with what was known before it records
	prev := s.beforeRecord(ctx, assetID, jobID, ip)
	if err := s.recordHost(ctx, assetID, ip, h, kind); err != nil {
		return err
	}
	s.saveFound(ctx, assetID, ip, foundOf(h, kind, extraFailed, prev))
	return nil
}

// statedInstance names the readings of what a device states about its firmware in a gentle look with titles (statedSoftware).
const statedInstance = "stated"

// recordHost stores the result of h on the device (recordDevice).
func (s *Service) recordHost(ctx context.Context, assetID string, ip netip.Addr, h host, kind nmapargv.Kind) error {
	if obs := deviceObservations(h, kind); len(obs) > 0 {
		if err := s.obs.Record(ctx, obs); err != nil {
			return fmt.Errorf("sensoractive: recording observations: %w", err)
		}
	}
	if h.timedOut {
		return nil
	}
	full := kind == nmapargv.Normal || kind == nmapargv.Versions
	hint := observe.AssetHint{IP: ip}
	switch {
	case full: // both read nmap's top 1000 and nmapargv.ExtraPorts with -sV (probeDevice)
		// the readings of the ports the weekly follow-up read (observe.PortInstance) are not this scan's to replace, except on the
		// ports this scan found open and read itself: an older follow-up reading there must not stay next to this one
		scope := []string{"", statedInstance}
		for _, p := range tcpPorts(h.ports) {
			scope = append(scope, observe.PortInstance(p))
		}
		if err := s.sw.ReplaceSoftware(ctx, hint, observe.Nmap, scope, softwareOf(h)); err != nil {
			return fmt.Errorf("sensoractive: recording software: %w", err)
		}
	case kind == nmapargv.GentleTitles:
		// a gentle look with titles reads no product, but the scripts of nmapargv.TitleScripts may read what the device states about
		// its firmware (INV-25): that is recorded, the one thing such a scan says about software
		if sw := statedSoftware(h); len(sw) > 0 {
			for i := range sw { // only what such a look reads is replaced: the banners of the last normal scan stay
				sw[i].Instance = statedInstance
			}
			if err := s.sw.ReplaceSoftware(ctx, hint, observe.Nmap, []string{statedInstance}, sw); err != nil {
				return fmt.Errorf("sensoractive: recording software: %w", err)
			}
		}
	case kind == nmapargv.AllPorts:
		// the weekly run's follow-up read some ports with -sV: the products on those ports replace what was read on them before,
		// and the software of the other ports (this scan's or the normal scan's) stays
		if len(h.read) > 0 {
			if err := s.recordFollowUp(ctx, hint, h); err != nil {
				return err
			}
		}
	}
	if s.svc != nil {
		list := servicesOf(h)
		if kind.IsGentle() { // no -sV: a gentle look says nothing about products, so it never updates one (inventory INV-23)
			for i := range list {
				list[i].Product, list[i].Version = "", ""
			}
		}
		var err error
		switch {
		case full:
			// the ports this scan looked at are replaced; the open ports the last weekly scan of every port found outside them stay
			// until the next weekly scan, or 14 days after it at most
			err = s.svc.ReplaceServices(ctx, hint, observe.Nmap, scopeOf(h, allPortsKeep, false), tcpIn(list, h))
		case kind == nmapargv.AllPorts:
			// every port was looked at, none read with versions: a port that closed goes, the others keep what was read on them. A port
			// read with versions in the last week (a normal scan) that this run did not see stays: one try a port (--max-retries 1)
			// can miss a reply, and the next normal scan, or this run a week later, decides
			err = s.svc.ReplaceServices(ctx, hint, observe.Nmap, s.weeklyScope(ctx, assetID, h), tcpIn(list, h))
			if err == nil && len(h.read) > 0 {
				// then the follow-up is a version read of its own ports: their name, product and version are what it read (none
				// too) and their read time moves (inventory inv_service.read_at), so the next week's follow-up reads others first
				err = s.svc.ReplaceServices(ctx, hint, observe.Nmap, readScope(h.read), readIn(list, h.read))
			}
		default:
			err = s.svc.AddServices(ctx, hint, observe.Nmap, list) // a gentle look, or an Extra run that alone saw the device
		}
		if err != nil {
			return fmt.Errorf("sensoractive: recording services: %w", err)
		}
	}
	return nil
}

// scopeOf is the scope of a scan's list of open ports: the ports its run looked at (nmap's <scaninfo>). A run that printed none
// covers the ports it listed only, so it removes nothing.
func scopeOf(h host, keepFor time.Duration, noVersions bool) observe.ServiceScope {
	ports := slices.Clone(h.scanned)
	if len(ports) == 0 {
		ports = []observe.PortRange{}
		for _, p := range tcpPorts(h.ports) {
			ports = append(ports, observe.PortRange{From: p, To: p})
		}
	}
	return observe.ServiceScope{Ports: ports, NoVersions: noVersions, KeepFor: keepFor}
}

// weeklyScope is the scope of the weekly scan's list of open ports: every port it looked at, less the ports read with versions in
// the last allPortsEvery that it did not see open. When that takes more ranges than a scope holds, it covers the ports it listed
// only (it removes nothing).
func (s *Service) weeklyScope(ctx context.Context, assetID string, h host) observe.ServiceScope {
	sc := scopeOf(h, 0, true)
	open := tcpPorts(h.ports)
	since := s.clock().Add(-allPortsEvery)
	var keep []int
	for p, at := range s.readTimes(ctx, assetID) {
		if at.After(since) && !slices.Contains(open, p) {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		return sc
	}
	slices.Sort(keep)
	var out []observe.PortRange
	for _, r := range sc.Ports {
		from := r.From
		for _, p := range keep {
			if p < from || p > r.To {
				continue
			}
			if p > from {
				out = append(out, observe.PortRange{From: from, To: p - 1})
			}
			from = p + 1
		}
		if from <= r.To {
			out = append(out, observe.PortRange{From: from, To: r.To})
		}
	}
	if len(out) > maxScopeRanges {
		out = []observe.PortRange{}
		for _, p := range open {
			out = append(out, observe.PortRange{From: p, To: p})
		}
	}
	sc.Ports = out
	return sc
}

// maxScopeRanges is the inventory's bound on the ranges of one service scope (inventory INV-23).
const maxScopeRanges = 2000

// tcpIn keeps the TCP services of a list that lie inside the scope of h's scan.
func tcpIn(list []observe.Service, h host) []observe.Service {
	sc := scopeOf(h, 0, false)
	return slices.DeleteFunc(slices.Clone(list), func(sv observe.Service) bool {
		return sv.Proto != "tcp" || !slices.ContainsFunc(sc.Ports, func(r observe.PortRange) bool { return sv.Port >= r.From && sv.Port <= r.To })
	})
}

// readScope is the scope of the weekly follow-up: the ports it read with -sV, each a range of its own.
func readScope(read []int) observe.ServiceScope {
	ports := make([]observe.PortRange, len(read))
	for i, p := range read {
		ports[i] = observe.PortRange{From: p, To: p}
	}
	return observe.ServiceScope{Ports: ports}
}

// readIn keeps the TCP services of a list on the ports the follow-up read.
func readIn(list []observe.Service, read []int) []observe.Service {
	return slices.DeleteFunc(slices.Clone(list), func(sv observe.Service) bool { return sv.Proto != "tcp" || !slices.Contains(read, sv.Port) })
}

// tcpPorts are the TCP port numbers of a list of open ports.
func tcpPorts(ports []portInfo) []int {
	var out []int
	for _, p := range ports {
		if p.proto == "tcp" {
			out = append(out, p.number)
		}
	}
	return out
}

// probeDevice is the nmap work of one device scan: the run of kind, and after a normal or versions scan the Extra run over
// nmapargv.ExtraPorts (the surface list and the reviewed admin ports) at the same rate, merged into the same host: a service
// moved to 22222 or 11443 is identified like one on its usual port. Each run has its own probe row. When the Extra run fails or is
// stopped (except because the device left the address, #882: then the run is ErrStopped and nothing is recorded), the first run's
// result is kept (it finished; POST-3) and the reason logged. When only the Extra run saw the device up, the
// result is recorded as an Extra one (its ports added; services and software of the normal scan untouched): kind is
// what recordDevice should record.
func (s *Service) probeDevice(ctx context.Context, jobID string, kind nmapargv.Kind, rate int, ip netip.Addr) (hosts []host, rec nmapargv.Kind, extraFailed bool, err error) {
	passes := 1
	if kind == nmapargv.Normal || kind == nmapargv.Versions {
		passes = 2 // the extra ports follow
	}
	hosts, err = s.probe(withPass(ctx, 1, passes), jobID, kind, rate, []netip.Addr{ip})
	if err != nil || passes == 1 {
		return hosts, kind, false, err
	}
	extra, err := s.probe(withPass(ctx, 2, passes), jobID, nmapargv.Extra, rate, []netip.Addr{ip})
	if errors.Is(err, errLeftAddress) { // the first run is recorded by address: another device, or none, is there now
		return nil, kind, false, errLeftAddress
	}
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: the scan of the extra ports did not finish; the device keeps the top 1000 ports' result", "ip", ip.String(), "error", err)
		return hosts, kind, true, nil
	}
	if !slices.ContainsFunc(hosts, func(h host) bool { return h.addr == ip }) {
		return extra, nmapargv.Extra, false, nil
	}
	// The Extra run ended without an error but did not cover the device: its host discovery missed it, or nmap gave up on it at
	// the host timeout (no port table). The check then covered the top 1000 only, as when the run failed.
	j := slices.IndexFunc(extra, func(h host) bool { return h.addr == ip })
	if j < 0 || extra[j].timedOut {
		s.log.WarnContext(ctx, "sensoractive: the scan of the extra ports did not cover the device; the device keeps the top 1000 ports' result", "ip", ip.String())
		return mergeExtra(hosts, extra, ip), kind, true, nil
	}
	return mergeExtra(hosts, extra, ip), kind, false, nil
}

// mergeExtra adds to the device's host of the first run what the Extra run found: its open ports the first run did not list (with
// their scripts), and its NTLM answer when the first run had none. A first run that timed out keeps its meaning (no port table: the
// services are not replaced). A device the first run did not see is left as it is (probeDevice records the Extra run alone then).
func mergeExtra(hosts, extra []host, ip netip.Addr) []host {
	j := slices.IndexFunc(extra, func(h host) bool { return h.addr == ip })
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if j < 0 || i < 0 {
		return hosts
	}
	h, x := &hosts[i], extra[j]
	if h.timedOut {
		return hosts
	}
	for _, p := range x.ports {
		if slices.ContainsFunc(h.ports, func(q portInfo) bool { return q.number == p.number && q.proto == p.proto }) {
			continue
		}
		h.ports = append(h.ports, p)
		for _, sc := range x.scripts {
			if sc.port == p.number {
				h.scripts = append(h.scripts, sc)
			}
		}
	}
	if h.ntlm == (ntlmInfo{}) {
		h.ntlm = x.ntlm
	}
	h.scanned = append(slices.Clone(h.scanned), x.scanned...) // the two runs together looked at both lists
	return hosts
}

// ---- identification for Scan now ----

// Identification is what IdentifyDevice found: Found says in words what was recorded (type, operating system, software), Why says
// why no software was recorded ("" when some was). Without software a vulnerability scan has nothing to compare with the KEV list.
type Identification struct {
	Found []string
	Why   string // a Why* code, or the inventory's refusal reason
}

// gentleShape is the one gentle scan of a device: a device whose kind is still unknown and that nobody made fragile also reads
// the title and certificate of the web and TLS ports it finds open (GentleTitles), so a FortiGate's certificate or J-Web's
// title names it without a Scan now; a fragile device (by a person, or by a kind a sensor or person gave it) keeps Gentle exactly.
func gentleShape(dec Decision) nmapargv.Kind {
	if dec.Unclassified && !dec.Fragile {
		return nmapargv.GentleTitles
	}
	return nmapargv.Gentle
}

// pickedPlan is the scan a device a person picked in Scan now gets for identification, from the inventory's discovery
// policy: a device discovery may scan normally gets the normal scan at the policy's rate; a fragile one only the gentle scan;
// one whose kind is still unknown the versions scan (-sV, no -O) at a quarter of the rate, since the pick is the consent
// and only -sV can tell what runs on it, while OS detection is the riskiest probe for an OT stack;
// regular_scan=never is refused. why is the inventory's reason when nothing may run.
func pickedPlan(dec Decision, rate int) (kind nmapargv.Kind, r int, why string) {
	switch {
	case dec.Never: // "never scan" set by a person is absolute here too, even before its one gentle scan
		return 0, 0, reasonNever
	case dec.Allowed && !dec.FirstGentle:
		return nmapargv.Normal, dec.Rate, ""
	case dec.Fragile && (dec.FirstGentle || dec.Reason == reasonFragilePassive):
		return nmapargv.Gentle, 1, ""
	case dec.Unclassified && (dec.FirstGentle || dec.Reason == reasonUnclassifiedPassive):
		return nmapargv.Versions, max(1, rate/4), "" // -sV without -O: OS detection is the riskiest probe for an OT stack
	case dec.FirstGentle:
		return nmapargv.Gentle, 1, ""
	}
	return 0, 0, dec.Reason
}

// busyWait is how long an identification waits for discovery's nmap run to end: the scan of one device, or a small sweep, ends
// within it; between the devices of its queue, discovery lets go of the lock.
const busyWait = 2 * time.Minute

// lockRun takes runMu for a run of the window (a sweep or a queued device), waiting as long as it takes. A deep
// scan of the box's public IP for exposure (nmapargv.ExternalFull) holds the slot for up to an hour; the window's runs then wait
// for it and go on afterwards with the window and the settings checked again (permit, probe), and the log says why they started
// late. A Scan now of a device does not wait that long: IdentifyDevice says busy after busyWait.
func (s *Service) lockRun(ctx context.Context) {
	if s.runMu.TryLock() {
		return
	}
	s.mu.Lock()
	ext := s.cur != nil && s.cur.external
	s.mu.Unlock()
	if ext {
		s.log.InfoContext(ctx, "sensoractive: waiting for the nmap slot: an exposure scan of the box's public IP holds it (a deep scan takes up to an hour)")
	}
	s.runMu.Lock()
}

// stopWeekly cancels the weekly scan of every port that holds the slot, if one does.
func (s *Service) stopWeekly() {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur != nil && cur.weekly {
		s.stopCur(cur, errGaveWay)
	}
}

// identifyIn is the identification of one device a person asked for, inside its run (a device_check with trigger manual): the
// shape of pickedPlan, at once whatever the window, every other rule of a device scan (IdentifyDevice).
func (s *Service) identifyIn(ctx context.Context, assetID string) (Identification, error) {
	stops := s.stops.Load()
	s.lockRun(ctx)
	defer s.runMu.Unlock()
	for try := 1; ; try++ {
		if s.stops.Load() != stops || ctx.Err() != nil { // the module was turned off while it waited (#723)
			return Identification{}, ErrStopped
		}
		got, err := s.identifyOnce(ctx, assetID, try < maxIdentifyTries)
		// A person asked to check the device, not an address: a device that moved while it was checked, or settings that changed but
		// still allow the check, are checked again from the start (every rule read again), a few times at most.
		if errors.Is(err, ErrStopped) && canGoOn(err) && ctx.Err() == nil && try < maxIdentifyTries {
			s.dropProgress(runIDOf(ctx)) // the new try's nmap reports from its start: the cut one's last report no longer says where it is
			continue
		}
		return got, err
	}
}

// maxIdentifyTries bounds how often a person's check starts again after a stop it can go on after (canGoOn).
const maxIdentifyTries = 3

// identifyOnce is one try of identifyIn, under runMu; more says another try may follow it.
func (s *Service) identifyOnce(ctx context.Context, assetID string, more bool) (Identification, error) {
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cur := &running{cancel: cancel, asset: assetID, picked: true, runID: runIDOf(ctx)}
	s.setCur(cur)
	defer s.setCur(nil)
	stopped := func(err error) error {
		if jctx.Err() != nil {
			return cmpErr(s.whyStopped(cur), ErrStopped)
		}
		return err
	}
	refuse := func(why string) (Identification, error) {
		s.blocked(ctx, assetID, why)
		return Identification{Why: why}, nil
	}
	dec, err := s.inv.ScanPolicy(jctx, assetID)
	if err != nil {
		return Identification{}, stopped(err)
	}
	st, err := s.inv.Settings(jctx)
	if err != nil {
		return Identification{}, stopped(err)
	}
	switch err := st.allowed(); {
	case errors.Is(err, ErrScanningOff):
		return refuse(reasonScanningOff)
	case errors.Is(err, ErrScopeNotConfirmed):
		return refuse(reasonScopeNotConfirmed)
	case err != nil:
		return refuse("out_of_scope")
	}
	kind, rate, why := pickedPlan(dec, st.Rate)
	if why != "" {
		return refuse(why)
	}
	if err := s.available(jctx); err != nil {
		return Identification{Why: WhyUnavailable}, nil
	}
	asset, err := s.inv.Asset(jctx, assetID)
	if err != nil {
		return Identification{}, stopped(err)
	}
	if !asset.IP.IsValid() {
		return refuse("no_ip")
	}
	s.setTargets([]netip.Addr{asset.IP}, rate)
	if in, err := s.inv.InScope(jctx, asset.IP); err != nil {
		return Identification{}, stopped(err)
	} else if !in {
		return refuse("out_of_scope")
	}
	// The box's own addresses and its decoys are never probed, whatever the device row says (BoxIPs, as SNMP does: #857);
	// the passive-only exemption below is for the rest of ProtectedIPs.
	box, err := s.inv.BoxIPs(jctx)
	if err != nil {
		return Identification{}, stopped(err)
	}
	if slices.Contains(box, asset.IP) {
		return refuse(reasonBox)
	}
	// ProtectedIPs also holds devices discovery leaves to the passive sensors after their gentle scan, which a pick may identify: only
	// those are let through; the box itself was refused above.
	protected, err := s.inv.ProtectedIPs(jctx)
	if err != nil {
		return Identification{}, stopped(err)
	}
	if slices.Contains(protected, asset.IP) && dec.Reason != reasonFragilePassive && dec.Reason != reasonUnclassifiedPassive {
		return refuse(reasonBox)
	}
	s.setKind(kind)
	id, err := s.startJob(ctx, KindDevice, "scan_now", 1)
	if err != nil {
		return Identification{}, err
	}
	hosts, recKind, extraFailed, err := s.probeDevice(jctx, id, kind, rate, asset.IP)
	s.setAsset("")
	if err == nil {
		var markErr error
		if dec.FirstGentle && kind.IsGentle() {
			markErr = s.inv.MarkFirstScan(context.WithoutCancel(ctx), assetID)
		}
		err = errors.Join(markErr, s.recordDevice(ctx, id, assetID, asset.IP, hosts, recKind, extraFailed))
	}
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		why := cmpErr(s.whyStopped(cur), err)
		line := "Stopped: " + stopWords(why)
		if more && canGoOn(why) && ctx.Err() == nil {
			line += "; the device is checked again"
		}
		s.finishJob(ctx, id, StatusStopped, 0, 0, line)
		return Identification{}, why
	default:
		s.finishJob(ctx, id, StatusFailed, 0, 0, err.Error())
		if errors.Is(err, ErrUnavailable) {
			return Identification{Why: WhyUnavailable}, nil
		}
		return Identification{}, err
	}
	if recKind == nmapargv.Extra { // the identification scan (top 1000) did not see it; only its extra ports were added
		return Identification{Why: WhyHostDown}, nil
	}
	found, why := identified(hosts, asset.IP, kind)
	return Identification{Found: found, Why: why}, nil
}

// SettingsChanged reacts to inventory.settings.changed: it bumps the settings version (a run that has not
// started nmap yet sees it and stops), and if a run is registered and the settings no longer allow it (scanning
// off, scope unconfirmed, outside the window, a lower rate, an address of the run out of scope), it is stopped
// now. The next batch reads the new settings by itself.
func (s *Service) SettingsChanged(ctx context.Context) error {
	s.ver.Add(1)
	// A range added or changed, the window or the rate: the devices it now covers owe their first check, so the next window tick
	// looks at every device again (INV-27).
	s.owedQueued.Store(nil)
	s.mu.Lock()
	s.owedTried = nil
	s.mu.Unlock()
	s.snmpChanged(ctx, "")
	s.mu.Lock()
	cur := s.cur
	var targets []netip.Addr
	var rate int
	var deadline time.Time
	var picked, external bool
	var until time.Time
	if cur != nil {
		targets, rate, deadline, picked, external, until = slices.Clone(cur.targets), cur.rate, cur.deadline, cur.picked, cur.external, cur.until
	}
	s.mu.Unlock()
	if cur == nil || external { // an external run is not under the LAN settings
		return nil
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		s.stopCur(cur, errSettingsUnread) // fail closed
		return err
	}
	if err := st.allowed(); err != nil {
		s.stopCur(cur, settingsStop(err))
		return nil
	}
	// A window shortened under a run in progress ends it: the run's deadline came from the old end (INV-3). A picked
	// identification is not bound to the window; the rate and the scope still bind it.
	end, ok := s.windowNow(withManualUntil(ctx, until), st)
	switch {
	case (!ok && !picked) || (!picked && !deadline.IsZero() && end.Before(deadline)):
		s.stopCur(cur, errWindowClosed)
		return nil
	case st.Rate < rate:
		s.stopCur(cur, errRateLowered)
		return nil
	}
	sc := newScope(st)
	if slices.ContainsFunc(targets, func(t netip.Addr) bool { return !sc.contains(t) }) {
		s.stopCur(cur, errLeftScope)
		return nil
	}
	// the settings may have changed the device's own policy (fragile kinds, regular-scan kinds): check it as AssetChanged does
	s.mu.Lock()
	asset := cur.asset
	s.mu.Unlock()
	return s.checkRun(ctx, asset)
}

// AssetChanged reacts to inventory.asset.updated and .deleted: if the device being scanned now left the address the run probes
// (it moved, or another device took the address: #874) or no longer passes
// the inventory's policy (marked fragile, regular scan never, declared by hand, deleted, out of scope), or the
// run is heavier than the policy now allows, the run is stopped; that is not an attempt (the queue keeps it
// only if the policy still lets it be scanned later). Other devices are not the run's business.
func (s *Service) AssetChanged(ctx context.Context, assetID string) error {
	s.snmpChanged(ctx, assetID)
	s.dropRefused(ctx, assetID)
	return s.checkRun(ctx, assetID)
}

// checkSweep stops the sweep batch in progress when it probes the address of assetID and the device is protected now (its network scan
// turned off, set to never, made fragile after its gentle scan). A batch cannot drop one host while nmap runs, so
// the batch stops; its cursor stays where the last finished batch left it and the next pass reads the protected list again.
func (s *Service) checkSweep(ctx context.Context, cur *running, assetID string, targets []netip.Addr) error {
	a, err := s.inv.Asset(ctx, assetID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		s.stopCur(cur, errDeviceUnread) // fail closed
		return err
	}
	if !a.IP.IsValid() || !slices.Contains(targets, a.IP) {
		return nil
	}
	prot, err := s.inv.ProtectedIPs(ctx)
	if err != nil || slices.Contains(prot, a.IP) {
		s.stopCur(cur, errBatchProtected)
	}
	return err
}

// checkRun stops the device run in progress when it is assetID's and the inventory's policy no longer lets it run as it does
// (AssetChanged; SettingsChanged too, since a change of the fragile kinds or the regular-scan kinds changes devices without an
// event of their own).
func (s *Service) checkRun(ctx context.Context, assetID string) error {
	s.mu.Lock()
	cur := s.cur
	var gentle, picked, weekly bool
	var rate int
	var kind nmapargv.Kind
	var targets []netip.Addr
	match := cur != nil && cur.asset == assetID && assetID != ""
	sweep := cur != nil && cur.asset == "" && !cur.external && assetID != "" && len(cur.targets) > 0
	if match || sweep {
		gentle, rate, picked, kind, weekly, targets = cur.gentle, cur.rate, cur.picked, cur.kind, cur.weekly, cur.targets
	}
	s.mu.Unlock()
	if sweep {
		return s.checkSweep(ctx, cur, assetID, targets)
	}
	if !match {
		return nil
	}
	// The device left the address the run probes (it moved, or another device took the address: #874): the run would probe whatever
	// is there now.
	if len(targets) > 0 {
		a, err := s.inv.Asset(ctx, assetID)
		if err != nil || !slices.Contains(targets, a.IP) {
			why := errLeftAddress
			if err != nil && !errors.Is(err, ErrNotFound) {
				why = errDeviceUnread
			} else if errors.Is(err, ErrNotFound) {
				why = errDeviceGone
			}
			s.stopCur(cur, why) // fail closed
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			return nil
		}
	}
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if picked && err == nil { // a picked identification is held to its own plan: refused now, or gentler or slower than it runs
		st, serr := s.inv.Settings(ctx)
		kind, r, why := pickedPlan(dec, st.Rate)
		if serr != nil || why != "" || (kind.IsGentle() && !gentle) || r < rate {
			s.stopCur(cur, policyStop(dec, why))
		}
		return serr
	}
	// A gentle scan with titles stops when the device may no longer have them: made fragile, by a person or by a kind (FORBID-6).
	titlesGone := kind == nmapargv.GentleTitles && dec.Fragile
	// The weekly scan of every port stops when the device may no longer have it (fragile, kind unknown, never, a rate too low:
	// FORBID-5).
	allGone := false
	if weekly && err == nil {
		st, serr := s.inv.Settings(ctx)
		_, why := allPortsPlan(dec, st)
		allGone = serr != nil || why != ""
	}
	if err != nil || !dec.Allowed || (dec.FirstGentle && !gentle) || (dec.Rate > 0 && dec.Rate < rate) || titlesGone || allGone {
		why := policyStop(dec, dec.Reason)
		if errors.Is(err, ErrNotFound) {
			why = errDeviceGone
		} else if err != nil {
			why = errDeviceUnread
		}
		s.stopCur(cur, why) // fail closed
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// dropRefused takes a device the policy no longer lets be scanned (ignored, deleted, never scan, scanning off for it) out of the
// queue: a row left behind would only be refused at its turn. A device that becomes scannable again is queued again (INV-27).
func (s *Service) dropRefused(ctx context.Context, assetID string) {
	if assetID == "" {
		return
	}
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if err == nil && (dec.Allowed || (dec.Reason == reasonScanningOff || dec.Reason == reasonScopeNotConfirmed)) {
		return
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return
	}
	s.dropWaiting(context.WithoutCancel(ctx), assetID, "The device may no longer be checked")
}
