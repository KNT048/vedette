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

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

const (
	// The active sweep's own budget of new devices (L8, D-178): a fresh install without a passive sensor must find the design scale
	// (1,000 devices, ARCHITECTURE) in one pass, and a taken-over scan container still cannot mint 65k devices on a /16 in one night.
	sweepNewPerMinute = 1000
	sweepNewPerHour   = 1000
	// maxRun bounds one nmap run: the deadline is the end of the window or this, whichever comes first (D-84 (7)).
	maxRun = 2 * time.Hour
	// ProbeRetention is how long sa_probe rows are kept (INV-9 asks for at least 90 days; D-84 (9)).
	ProbeRetention = 365 * 24 * time.Hour
	// maxAttempts is how many times a queued device is tried after nmap failed before it is dropped.
	maxAttempts = 3
	// finishTimeout bounds the writes that must happen even when the run was cancelled.
	finishTimeout = 30 * time.Second
)

// Config is what New needs. Everything except Events and Log is required.
type Config struct {
	DB        *store.DB
	Inventory Inventory
	Observe   observe.Sink         // the inventory, through core/observe
	Software  observe.SoftwareSink // the inventory, through core/observe
	Services  observe.ServiceSink  // the inventory, through core/observe; nil: the open ports are not recorded
	Events    Publisher
	NmapPath  string // absolute path of the OS package's nmap; Health reads it, and the local Prober runs it
	// Prober runs the nmap command the module has already checked. Nil means the local one, core/exec around
	// NmapPath (NewLocalProber). The Dispatcher hands the job to the worker in the scan container (SP-3); then
	// NmapPath is not used and Health comes from the worker's heartbeat.
	Prober Prober
	Clock  func() time.Time
	Log    *slog.Logger
	// Location is the organization's time zone, the one the windows are read in (INV-3). Nil, or a nil result,
	// means the box's own zone (time.Local).
	Location func() *time.Location
}

// Service runs active discovery. Create it with New. It is the only writer of the sa_* tables.
type Service struct {
	db     *store.DB
	inv    Inventory
	obs    observe.Sink
	sw     observe.SoftwareSink
	svc    observe.ServiceSink // may be nil
	events Publisher
	path   string
	prober Prober
	clock  func() time.Time
	log    *slog.Logger
	loc    func() *time.Location
	// budget is core's budget of new devices (60 a minute, 200 an hour; L8): the scan container is a process that can be taken over,
	// and a sweep over a /16 with random MACs would otherwise mint 65k devices. In memory, like the passive sensor's.
	budget *capture.FloodBudget

	runMu sync.Mutex // one nmap job at a time on the box

	ver atomic.Uint64 // bumped by every SettingsChanged; a run that sees it move before nmap starts stops

	mu  sync.Mutex
	cur *running // the job holding runMu, for SettingsChanged
	// firstUntil is set while the first pass of a new box runs (firstPass, D-501): until then the window counts as open. Zero otherwise.
	firstUntil time.Time
}

// firstPassFor bounds the first pass: it may run outside the window for at most this long; a sweep it did not finish goes on from
// its cursor in the next window.
const firstPassFor = time.Hour

// windowNow is the window rule of every automatic run (INV-3): whether the window is open now, and when it ends. While the
// first pass of a new box runs it is open until firstUntil (D-501).
func (s *Service) windowNow(st Settings) (end time.Time, ok bool) {
	s.mu.Lock()
	until := s.firstUntil
	s.mu.Unlock()
	if s.clock().Before(until) {
		return until, true
	}
	_, end, ok = st.window(s.local())
	return end, ok
}

type running struct {
	cancel   context.CancelFunc
	targets  []netip.Addr // the run in progress, published before it is checked
	rate     int          // the packets per second of the run
	deadline time.Time    // when the run in progress stops by itself: the end of the window it was checked against, or maxRun
	asset    string       // the device a device run is for ("" for a sweep), set before its policy is read
	gentle   bool         // the run is the one gentle scan
	// picked: the identification of a device a person picked in Scan now (IdentifyDevice, D-501). Like the vulnerability scan
	// it is part of, it runs at once: the window does not apply (its deadline is maxRun). Every other rule does.
	picked bool
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Inventory == nil || cfg.Observe == nil || cfg.Software == nil {
		return nil, errors.New("sensoractive: New needs DB, Inventory, Observe and Software")
	}
	s := &Service{db: cfg.DB, inv: cfg.Inventory, obs: cfg.Observe, sw: cfg.Software, svc: cfg.Services, events: cfg.Events, path: cfg.NmapPath, clock: cfg.Clock, log: cfg.Log, loc: cfg.Location, budget: capture.NewFloodBudgetLimits(sweepNewPerMinute, sweepNewPerHour)}
	if s.clock == nil {
		s.clock = time.Now
	}
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
	return s, nil
}

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
		// nmap lives in the scan container: its worker's heartbeat says whether it can run (D-113 (6)).
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
		h.Warning = st.sweepWarning()
	}
	return h
}

// sweepWarning is set when the addresses of the scope divided by the rate take longer than one window: the
// sweep then needs several days, resuming each day where the window cut it (an estimate: one packet per
// address, while -sn sends up to four to a host outside the segment).
func (st Settings) sweepWarning() string {
	if st.allowed() != nil || st.Rate < 1 {
		return ""
	}
	n := newScope(st).count()
	need := time.Duration(n) * time.Second / time.Duration(st.Rate)
	if have := st.windowLength(); have > 0 && need > have {
		return fmt.Sprintf("a sweep of about %d addresses at %d packets/s needs about %s but a window lasts %s; one pass will take several days", n, st.Rate, need.Round(time.Minute), have)
	}
	return ""
}

func (s *Service) available(ctx context.Context) error {
	if h := s.Health(ctx); h.Status != "ok" {
		return fmt.Errorf("%w: %s", ErrUnavailable, h.Message)
	}
	return nil
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
	if _, ok := s.windowNow(st); !ok {
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

func (s *Service) startJob(ctx context.Context, kind, reason string, targets int) (string, error) {
	id := store.NewID("saj")
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_job (id, kind, reason, started_at, status, targets) VALUES (?, ?, ?, ?, 'running', ?)`, id, kind, nullable(reason), s.now(), targets)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("sensoractive: start job: %w", err)
	}
	s.publish(ctx, EventScanStarted, StartedEvent{JobID: id, Kind: kind, Targets: targets})
	return id, nil
}

// finishJob closes the job even when the run was cancelled, so it is never left "running".
func (s *Service) finishJob(ctx context.Context, id, status string, targets, newDevices int, errText string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sa_job SET finished_at = ?, status = ?, targets = ?, new_devices = ?, error = ? WHERE id = ?`,
			s.now(), status, targets, newDevices, nullable(clip(errText, 1000)), id)
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sensoractive: closing a job failed", "job", id, "error", err)
		return
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

// failInterrupted closes jobs a restart left "running" (nothing runs now: the caller holds runMu). It writes
// only when there is something to close, since Tick calls it every minute.
func (s *Service) failInterrupted(ctx context.Context) error {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_job WHERE status = 'running'`).Scan(&n); err != nil {
		return fmt.Errorf("sensoractive: read jobs: %w", err)
	}
	if n == 0 {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sa_job SET status = 'stopped', finished_at = ?, error = 'interrupted by a restart' WHERE status = 'running'`, s.now())
		return err
	})
}

// ---- the run of nmap ----

// errDeadline is ErrStopped for a run cut by its own deadline (the end of the window or maxRun), as opposed to
// a stop for a change of settings: the queue counts it as an attempt (M4).
var errDeadline = fmt.Errorf("%w: its deadline passed", ErrStopped)

// probe runs one nmap command over targets and returns the hosts that answered. Order matters (INV-1, INV-2,
// INV-3): the run's targets are published first, so SettingsChanged can see them; then the settings, the
// window and the scope are read again for every target; only then the probe row is written (INV-9: no packet
// without a log line) and nmap started, unless a SettingsChanged arrived in between. The deadline is the
// window's end or maxRun; when it passes, or ctx is cancelled, exec kills the process group and the batch is
// dropped (PRE-3, POST-3).
func (s *Service) probe(ctx context.Context, jobID string, kind nmapargv.Kind, rate int, targets []netip.Addr) ([]host, error) {
	if _, err := nmapargv.Build(kind, rate, targets); err != nil {
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
	end, ok := s.windowNow(st)
	if !ok && !picked {
		return nil, ErrStopped
	}
	sc := newScope(st)
	if slices.ContainsFunc(targets, func(t netip.Addr) bool { return !sc.contains(t) }) {
		return nil, ErrStopped
	}
	rate = min(rate, st.Rate)
	args, err := nmapargv.Build(kind, rate, targets)
	if err != nil {
		return nil, err
	}
	timeout := maxRun // a picked identification is not bound to the window (D-501)
	if !picked {
		timeout = min(end.Sub(s.clock()), maxRun)
	}
	if timeout <= 0 || ctx.Err() != nil {
		return nil, ErrStopped
	}
	s.setDeadline(s.clock().Add(timeout))
	probeID, err := s.insertProbe(ctx, jobID, kind, rate, targets)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || s.ver.Load() != v0 {
		s.finishProbe(ctx, probeID, stoppedText)
		return nil, ErrStopped
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, runErr := s.prober.Probe(rctx, args)

	var hosts []host
	var result string
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
		var all []host
		if all, err = parseNmapXML(res.XML); err != nil {
			result = "failed: output not valid, discarded"
		} else {
			hosts = onlyTargets(all, targets)
			result = fmt.Sprintf("ok: %d hosts up", len(hosts))
		}
	}
	s.finishProbe(ctx, probeID, result)
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

// Reasons of the inventory's ScanPolicy that are states of the box, not of the device.
const (
	reasonScanningOff       = "scanning_off"
	reasonScopeNotConfirmed = "scope_not_confirmed"
	// Reasons of a device that discovery leaves to the passive sensors after its one gentle scan; a pick in Scan now still
	// identifies it (pickedPlan, D-501).
	reasonFragilePassive      = "fragile_passive_only"
	reasonUnclassifiedPassive = "unclassified_passive_only"
	reasonNever               = "regular_scan_never"
	reasonBox                 = "box"
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
// identification for Scan now runs on the scan module's goroutine, so only this reaches it (D-501, review L3).
func (s *Service) Stop() {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur != nil {
		cur.cancel()
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

func (s *Service) insertProbe(ctx context.Context, jobID string, kind nmapargv.Kind, rate int, targets []netip.Addr) (int64, error) {
	if kind.IsGentle() {
		rate = 1
	}
	flags, err := nmapargv.Flags(kind, rate)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES (?, ?, ?, ?, ?, ?, ?, 'started')`,
			s.now(), jobID, kind.Name(), rate, len(targets), strings.Join(flags, " "), compactTargets(targets))
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
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT time, shape, rate, flags, targets, result, job_id FROM sa_probe WHERE time >= ? ORDER BY id LIMIT ?`, store.FormatTS(since), clamp(limit, 1, 100000))
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
	return logexport.Rows{SQL: `SELECT id, time, job_id, shape, rate, hosts, flags, targets, result FROM sa_probe
		WHERE (? = '' OR time >= ?) AND (? = '' OR time <= ?) ORDER BY id`, Args: []any{lo, lo, hi, hi}}.Write(ctx, db.Reader(), w)
}

// Prune deletes probe rows older than ProbeRetention and the jobs that no longer have any probe row, and
// returns how many probe rows went (D-84 (9)).
func (s *Service) Prune(ctx context.Context) (int, error) {
	var n int64
	cutoff := store.FormatTS(s.clock().Add(-ProbeRetention))
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sa_probe WHERE time < ?`, cutoff)
		if err != nil {
			return err
		}
		if n, err = res.RowsAffected(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sa_job WHERE started_at < ? AND status <> 'running' AND id NOT IN (SELECT job_id FROM sa_probe)`, cutoff)
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

// nextBatch takes up to MaxBatch addresses from w that the settings snapshot st puts in scope and the
// inventory does not protect (INV-1; a device declared by hand, set to never, fragile after its gentle scan, or
// the box itself). The test is made in memory against st, so an address costs no storage read. It returns
// fewer only when the ranges are used up.
func (s *Service) nextBatch(ctx context.Context, st Settings, w *walker) ([]netip.Addr, error) {
	prot, err := s.inv.ProtectedIPs(ctx)
	if err != nil {
		return nil, err
	}
	skip := make(map[netip.Addr]bool, len(prot))
	for _, a := range prot {
		skip[a.Unmap()] = true
	}
	sc := newScope(st)
	var batch []netip.Addr
	for len(batch) < MaxBatch {
		a, ok := w.next()
		if !ok {
			break
		}
		if sc.contains(a) && !skip[a] {
			batch = append(batch, a)
		}
	}
	return batch, nil
}

func rangeSize(ps []netip.Prefix) int {
	n := 0
	for _, p := range mergePrefixes(ps) {
		n += prefixSize(p)
	}
	return n
}

// cursor reads where the current sweep pass stands (invalid: no pass in progress).
func (s *Service) cursor(ctx context.Context) (netip.Addr, error) {
	var c sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT cursor FROM sa_sweep WHERE id = 1`).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, nil
	}
	if err != nil {
		return netip.Addr{}, fmt.Errorf("sensoractive: read sweep cursor: %w", err)
	}
	a, _ := netip.ParseAddr(c.String) // NULL or junk: start the pass over
	return a, nil
}

// setCursor stores the last address of a finished batch; the zero Addr ends the pass.
func (s *Service) setCursor(ctx context.Context, a netip.Addr) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	var v any
	if a.IsValid() {
		v = a.String()
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_sweep (id, cursor, updated_at) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at`, v, s.now())
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: storing the sweep cursor failed; the batch may be probed again", "error", err)
	}
}

// DiscoverRanges continues the sweep of the confirmed ranges with nmap host discovery (PRE-1). A pass probes
// every address of lan_ranges outside the exclusions and the protected devices at most once, in ascending
// order and in batches of MaxBatch; the cursor of the pass is stored after every batch, so a window that
// cuts it is continued the next day where it stopped, and only a pass that reached the end is followed by a
// new one. The settings are read again before every batch (and again inside probe), and SettingsChanged stops
// the batch in progress. A batch cut off by the window or a stop is dropped, finished batches stay stored,
// and the job is "stopped" (POST-3). Hosts found are recorded in the inventory by MAC; devices that are new
// there reach the queue through inventory.asset.discovered.
func (s *Service) DiscoverRanges(ctx context.Context) (Result, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel})
	defer s.setCur(nil)
	st, err := s.permit(jctx)
	if err != nil {
		return Result{}, err
	}
	macs, err := s.knownMACs(ctx)
	if err != nil {
		return Result{}, err
	}
	after, err := s.cursor(ctx)
	if err != nil {
		return Result{}, err
	}
	if w := st.sweepWarning(); w != "" {
		s.log.WarnContext(ctx, "sensoractive: a full sweep does not fit one window", "estimate", w)
	}

	ps := prefixes(st.LANRanges)
	id, err := s.startJob(ctx, KindSweep, "", rangeSize(ps))
	if err != nil {
		return Result{}, err
	}
	res := Result{JobID: id}
	var failed int
	var firstErr string
	status := StatusDone
	w := newWalker(ps, after)
loop:
	for {
		if st, err = s.inv.Settings(jctx); err == nil {
			err = st.allowed()
		}
		if err != nil {
			status, firstErr = StatusStopped, "stopped: "+err.Error()
			break
		}
		if _, ok := s.windowNow(st); !ok {
			status, firstErr = StatusStopped, "stopped: the window closed"
			break
		}
		batch, err := s.nextBatch(jctx, st, w)
		if err != nil {
			status, firstErr = StatusFailed, "reading the scope failed"
			if jctx.Err() != nil {
				status, firstErr = StatusStopped, "stopped"
			}
			break
		}
		if len(batch) == 0 {
			s.setCursor(ctx, netip.Addr{}) // the pass reached the end of the ranges
			break
		}
		hosts, err := s.probe(jctx, id, nmapargv.Sweep, st.Rate, batch)
		switch {
		case errors.Is(err, ErrStopped):
			status, firstErr = StatusStopped, stoppedText
			break loop
		case errors.Is(err, ErrUnavailable):
			// The worker is gone (or nmap is): the batches that are left would each fail the same way and burn a probe row.
			// Stop without moving the cursor; a stopped sweep is run again by a later Tick, from the cursor.
			status, firstErr = StatusStopped, "stopped: "+err.Error()
			break loop
		case err == nil:
			var n int
			if n, err = s.recordSweep(ctx, hosts, batch, macs); err == nil {
				res.Targets += len(batch)
				res.NewDevices += n
				s.setCursor(ctx, batch[len(batch)-1])
				continue
			}
			fallthrough
		default:
			failed++
			if firstErr == "" {
				firstErr = err.Error()
			}
			s.setCursor(ctx, batch[len(batch)-1])
			s.log.WarnContext(ctx, "sensoractive: a sweep batch failed", "job", id, "error", err)
		}
	}
	if status == StatusDone && failed > 0 {
		status, firstErr = StatusFailed, fmt.Sprintf("%d batches failed; first: %s", failed, firstErr)
	} else if status == StatusDone {
		firstErr = ""
	}
	res.Status = status
	s.finishJob(ctx, id, status, res.Targets, res.NewDevices, firstErr)
	if status == StatusStopped {
		return res, ErrStopped
	}
	return res, nil
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
// inventory already has is free whatever its IP (DHCP churn), every other MAC is charged against the budget of new devices (L8), even at
// an IP the inventory already has. Only the first entry for a target counts: one result can carry many for one address. known is the
// MACs of the inventory and gains the MACs recorded here.
func (s *Service) recordSweep(ctx context.Context, hosts []host, batch []netip.Addr, known map[string]bool) (int, error) {
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
		return 0, nil
	}
	if err := s.obs.Record(ctx, obs); err != nil {
		return 0, fmt.Errorf("sensoractive: recording hosts: %w", err) // the budget is not spent: the next try meets the same budget
	}
	s.budget.Commit(admitted, admittedV, now)
	fresh := 0
	for _, c := range admitted {
		if !known[c.MAC] {
			known[c.MAC] = true
			fresh++
		}
	}
	return fresh, nil
}

func (s *Service) setGentle(g bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.gentle = g
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
	s.cur = r
}

// ---- one device ----

// ScanDevice identifies one device with nmap (PRE-2): the inventory's ScanPolicy must allow it, the window
// must be open (D-84 (1): even the one gentle scan of a device that is fragile or not yet classified waits for
// it), and the device's address must be in scope immediately before the command line is built (INV-1). The run
// is registered before the checks and its address published as soon as it is known, so a SettingsChanged that
// arrives while it is still checking reaches it (H2). A refusal by policy or scope publishes
// sensor.scan.blocked and sends nothing. reason says why it was asked ("discovered", ...).
func (s *Service) ScanDevice(ctx context.Context, assetID, reason string) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel, asset: assetID})
	defer s.setCur(nil)
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
	kind, rate := nmapargv.Normal, st.Rate
	if dec.Rate > 0 {
		rate = min(rate, dec.Rate)
	}
	if dec.FirstGentle {
		kind, rate = gentleShape(dec), 1
	}
	s.setGentle(kind.IsGentle())

	id, err := s.startJob(ctx, KindDevice, reason, 1)
	if err != nil {
		return err
	}
	hosts, err := s.probe(jctx, id, kind, rate, []netip.Addr{asset.IP})
	s.setAsset("") // nmap is done: a change of the device now has nothing to stop
	if err == nil {
		// nmap finished: the gentle scan happened, whatever becomes of recording its results (D-45, L2)
		var markErr error
		if dec.FirstGentle {
			markErr = s.inv.MarkFirstScan(context.WithoutCancel(ctx), assetID)
		}
		err = errors.Join(markErr, s.recordDevice(ctx, asset.IP, hosts, kind))
	}
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, id, StatusStopped, 0, 0, stoppedText)
	default:
		s.finishJob(ctx, id, StatusFailed, 0, 0, err.Error())
	}
	return err
}

// recordDevice stores what a service scan found about ip. A host that did not answer changes nothing. A host that hit the host
// timeout keeps its software and services: nmap printed no port table for it, so an empty list would wrongly remove them. Only a
// normal scan (top 1000 ports, -sV) replaces the device's nmap services and software; a gentle one (top 100, no -sV) only adds the
// ports it saw and leaves the software alone, so it never wipes what a normal scan found (D-350 (5), D-501).
func (s *Service) recordDevice(ctx context.Context, ip netip.Addr, hosts []host, kind nmapargv.Kind) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 {
		return nil
	}
	h := hosts[i]
	if obs := deviceObservations(h, kind); len(obs) > 0 {
		if err := s.obs.Record(ctx, obs); err != nil {
			return fmt.Errorf("sensoractive: recording observations: %w", err)
		}
	}
	if h.timedOut {
		return nil
	}
	// A gentle scan has no -sV and no -O, so it says nothing about software: replacing the list with its empty one would remove what
	// a normal scan found, an OS that findings were matched on among them (D-501).
	if !kind.IsGentle() {
		if err := s.sw.ReplaceSoftware(ctx, observe.AssetHint{IP: ip}, observe.Nmap, softwareOf(h)); err != nil {
			return fmt.Errorf("sensoractive: recording software: %w", err)
		}
	}
	if s.svc != nil {
		write := s.svc.AddServices
		if kind == nmapargv.Normal || kind == nmapargv.Versions { // both read the top 1000 ports with -sV
			write = s.svc.ReplaceServices
		}
		if err := write(ctx, observe.AssetHint{IP: ip}, observe.Nmap, servicesOf(h)); err != nil {
			return fmt.Errorf("sensoractive: recording services: %w", err)
		}
	}
	return nil
}

// ---- identification for Scan now (D-501) ----

// Identification is what IdentifyDevice found: Found says in words what was recorded (type, operating system, software), Why says
// why no software was recorded ("" when some was). Without software a vulnerability scan has nothing to compare with the KEV list.
type Identification struct {
	Found []string
	Why   string // a Why* code, or the inventory's refusal reason
}

// gentleShape is the one gentle scan of a device (D-45): a device whose kind is still unknown and that nobody made fragile also reads
// the title and certificate of the web and TLS ports it finds open (GentleTitles, D-511), so a FortiGate's certificate or J-Web's
// title names it without a Scan now; a fragile device (by a person, or by a kind a sensor or person gave it) keeps Gentle exactly.
func gentleShape(dec Decision) nmapargv.Kind {
	if dec.Unclassified && !dec.Fragile {
		return nmapargv.GentleTitles
	}
	return nmapargv.Gentle
}

// pickedPlan is the scan a device a person picked in Scan now gets for identification (D-501), from the inventory's discovery
// policy: a device discovery may scan normally gets the normal scan at the policy's rate; a fragile one only the gentle scan
// (D-45); one whose kind is still unknown the versions scan (-sV, no -O) at a quarter of the rate, since the pick is the consent
// (D-126 (2)) and only -sV can tell what runs on it, while OS detection is the riskiest probe for an OT stack (review M4);
// regular_scan=never is refused (review M1). why is the inventory's reason when nothing may run.
func pickedPlan(dec Decision, rate int) (kind nmapargv.Kind, r int, why string) {
	switch {
	case dec.Never: // "never scan" set by a person is absolute here too (D-126 (1)), even before its one gentle scan
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

// lockWithin takes runMu, trying every half second for at most d; false when it could not (or ctx ended).
func (s *Service) lockWithin(ctx context.Context, d time.Duration) bool {
	if s.runMu.TryLock() {
		return true
	}
	give := time.NewTimer(d)
	defer give.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-give.C:
			return s.runMu.TryLock()
		case <-tick.C:
			if s.runMu.TryLock() {
				return true
			}
		}
	}
}

// IdentifyDevice identifies one device for the vulnerability scan a person started with Scan now (D-501): the same nmap device
// scan and recording as ScanDevice, with the scan shape of pickedPlan, and at once (the window does not apply, as for Scan now
// itself). Every other rule of a device scan holds: scanning on, scope confirmed, the device's address in scope right before the
// command line is built (INV-1), the probe log (INV-9), one nmap at a time, the stop on a change of settings or of the device.
// A refusal publishes sensor.scan.blocked and sends nothing. The result says what was recorded, or why nothing was; err is
// ErrStopped when the run was stopped, ErrNotFound for an unknown device, or a failure of nmap, the worker or storage.
func (s *Service) IdentifyDevice(ctx context.Context, assetID string) (Identification, error) {
	if !s.lockWithin(ctx, busyWait) { // discovery is running nmap: Scan now does not wait for a sweep that may last the whole window
		if ctx.Err() != nil {
			return Identification{}, ErrStopped
		}
		return Identification{Why: WhyBusy}, nil
	}
	defer s.runMu.Unlock()
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel, asset: assetID, picked: true})
	defer s.setCur(nil)
	stopped := func(err error) error {
		if jctx.Err() != nil {
			return ErrStopped
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
	// The box's own addresses and its decoys are never probed (review L1). The list also holds devices discovery leaves to the
	// passive sensors after their gentle scan, which a pick may identify: only those are let through.
	protected, err := s.inv.ProtectedIPs(jctx)
	if err != nil {
		return Identification{}, stopped(err)
	}
	if slices.Contains(protected, asset.IP) && dec.Reason != reasonFragilePassive && dec.Reason != reasonUnclassifiedPassive {
		return refuse(reasonBox)
	}
	s.setGentle(kind.IsGentle())
	id, err := s.startJob(ctx, KindDevice, "scan_now", 1)
	if err != nil {
		return Identification{}, err
	}
	hosts, err := s.probe(jctx, id, kind, rate, []netip.Addr{asset.IP})
	s.setAsset("")
	if err == nil {
		var markErr error
		if dec.FirstGentle && kind.IsGentle() {
			markErr = s.inv.MarkFirstScan(context.WithoutCancel(ctx), assetID)
		}
		err = errors.Join(markErr, s.recordDevice(ctx, asset.IP, hosts, kind))
	}
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, id, StatusStopped, 0, 0, stoppedText)
		return Identification{}, ErrStopped
	default:
		s.finishJob(ctx, id, StatusFailed, 0, 0, err.Error())
		if errors.Is(err, ErrUnavailable) {
			return Identification{Why: WhyUnavailable}, nil
		}
		return Identification{}, err
	}
	found, why := identified(hosts, asset.IP, kind)
	return Identification{Found: found, Why: why}, nil
}

// ---- the queue and the schedule ----

// Enqueue remembers a device for its scan inside a window (a device another sensor saw first). It survives a
// restart; queueing a device twice keeps one row.
func (s *Service) Enqueue(ctx context.Context, assetID, reason string) error {
	if l := len(assetID); l < 1 || l > 96 {
		return errors.New("sensoractive: bad device id")
	}
	if reason == "" || len(reason) > 64 {
		reason = "queued"
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sa_queue (asset_id, queued_at, reason) VALUES (?, ?, ?)`, assetID, s.now(), reason)
		return err
	})
}

type queued struct {
	id, reason string
	attempts   int
}

func (s *Service) queue(ctx context.Context) ([]queued, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT asset_id, reason, attempts FROM sa_queue ORDER BY queued_at, asset_id LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []queued
	for rows.Next() {
		var q queued
		if err := rows.Scan(&q.id, &q.reason, &q.attempts); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// QueueLen is the number of devices waiting for a scan.
func (s *Service) QueueLen(ctx context.Context) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_queue`).Scan(&n)
	return n, err
}

// leave takes a device out of the queue; failed counts an attempt and, if the device has attempts left, moves
// it to the back of the queue so one device that cannot finish never blocks the ones behind it (M4).
func (s *Service) leave(ctx context.Context, id string, failed bool) {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if failed {
			if _, err := tx.ExecContext(ctx, `UPDATE sa_queue SET attempts = attempts + 1, queued_at = ? WHERE asset_id = ?`, s.now(), id); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `DELETE FROM sa_queue WHERE asset_id = ? AND attempts >= ?`, id, maxAttempts)
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sa_queue WHERE asset_id = ?`, id)
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "sensoractive: updating the queue failed", "asset", id, "error", err)
	}
}

// Tick is the window job, run every minute: while a window is open it starts the day's sweep (once per
// window, also when the module or scanning is turned on inside an open window) and then scans the queued
// devices one by one. Outside a window, or with scanning off, it does nothing.
func (s *Service) Tick(ctx context.Context) error {
	if s.runMu.TryLock() {
		err := s.failInterrupted(ctx)
		s.runMu.Unlock()
		if err != nil {
			return err
		}
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return err
	}
	if st.allowed() != nil {
		return nil
	}
	start, _, ok := st.window(s.local())
	if !ok {
		due, err := s.firstPassDue(ctx)
		if err != nil || !due {
			return err
		}
		return s.firstPass(ctx)
	}
	if err := s.available(ctx); err != nil {
		return err
	}
	var done int
	err = s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_job WHERE kind = 'sweep' AND status IN ('running', 'done', 'failed') AND started_at >= ?`, store.FormatTS(start)).Scan(&done)
	if err != nil {
		return fmt.Errorf("sensoractive: read jobs: %w", err)
	}
	if done == 0 {
		if _, err := s.DiscoverRanges(ctx); err != nil && !errors.Is(err, ErrStopped) && !errors.Is(err, ErrOutsideWindow) {
			s.log.WarnContext(ctx, "sensoractive: the sweep did not run", "error", err)
		}
	}
	return s.drain(ctx)
}

// firstPassDue says the first pass has never started (no sa_first_pass row) and no sweep ever finished on this box (a box from
// before D-501 that has swept has had its first look). It runs exactly once: a pass that was stopped or cut by its deadline is not
// run again; its sweep goes on from the cursor in the next window.
func (s *Service) firstPassDue(ctx context.Context) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sa_first_pass) + (SELECT count(*) FROM sa_job WHERE kind = 'sweep' AND status IN ('done', 'failed'))`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sensoractive: read the first pass: %w", err)
	}
	return n == 0, nil
}

// markFirstPass records that the first pass starts; false when another call recorded it first.
func (s *Service) markFirstPass(ctx context.Context) (bool, error) {
	var n int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sa_first_pass (id, started_at) VALUES (1, ?)`, s.now())
		if err != nil {
			return err
		}
		n, err = r.RowsAffected()
		return err
	})
	if err != nil {
		return false, fmt.Errorf("sensoractive: record the first pass: %w", err)
	}
	return n == 1, nil
}

// firstPass is the one discovery pass of a box that has never swept, run at once instead of at the next window (D-501, walk 1
// W1-6: a box set up at 11:00 identified nothing until 23:00). It is the window's own work, a sweep and then the queued devices'
// scans (gentle first for fragile and unclassified ones, D-84 (1)), with the window counted open for at most firstPassFor. Every
// other rule holds: scanning on, scope confirmed, exclusions, rate, the probe log, the stop on a change of settings. It runs once:
// sa_first_pass is written before the sweep starts.
func (s *Service) firstPass(ctx context.Context) error {
	if err := s.available(ctx); err != nil {
		return err // not started: the next Tick tries again
	}
	if first, err := s.markFirstPass(ctx); err != nil || !first {
		return err
	}
	s.mu.Lock()
	s.firstUntil = s.clock().Add(firstPassFor)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.firstUntil = time.Time{}
		s.mu.Unlock()
	}()
	s.log.InfoContext(ctx, "sensoractive: first pass of a new box, outside the window", "for", firstPassFor.String())
	if _, err := s.DiscoverRanges(ctx); err != nil && !errors.Is(err, ErrStopped) && !errors.Is(err, ErrOutsideWindow) {
		s.log.WarnContext(ctx, "sensoractive: the first sweep did not run", "error", err)
	}
	return s.drain(ctx)
}

// drain scans the queued devices in order while the window is open.
func (s *Service) drain(ctx context.Context) error {
	list, err := s.queue(ctx)
	if err != nil {
		return err
	}
	for _, q := range list {
		if ctx.Err() != nil {
			return nil
		}
		err := s.ScanDevice(ctx, q.id, q.reason)
		switch {
		case err == nil, errors.Is(err, ErrBlocked), errors.Is(err, ErrNotFound):
			s.leave(ctx, q.id, false)
		case errors.Is(err, errDeadline):
			s.leave(ctx, q.id, true) // an attempt, and to the back; the next device finds the window closed itself
		case errors.Is(err, ErrOutsideWindow), errors.Is(err, ErrStopped), errors.Is(err, ErrUnavailable),
			errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
			return nil // the rest waits for the next window
		default:
			s.log.WarnContext(ctx, "sensoractive: a device scan failed", "asset", q.id, "error", err)
			s.leave(ctx, q.id, true)
		}
	}
	return nil
}

// SettingsChanged reacts to inventory.settings.changed: it bumps the settings version (a run that has not
// started nmap yet sees it and stops), and if a run is registered and the settings no longer allow it (scanning
// off, scope unconfirmed, outside the window, a lower rate, an address of the run out of scope), it is stopped
// now. The next batch reads the new settings by itself.
func (s *Service) SettingsChanged(ctx context.Context) error {
	s.ver.Add(1)
	s.mu.Lock()
	cur := s.cur
	var targets []netip.Addr
	var rate int
	var deadline time.Time
	var picked bool
	if cur != nil {
		targets, rate, deadline, picked = slices.Clone(cur.targets), cur.rate, cur.deadline, cur.picked
	}
	s.mu.Unlock()
	if cur == nil {
		return nil
	}
	st, err := s.inv.Settings(ctx)
	if err != nil || st.allowed() != nil {
		cur.cancel() // fail closed
		return err
	}
	// A window shortened under a run in progress ends it: the run's deadline came from the old end (INV-3). A picked
	// identification is not bound to the window (D-501); the rate and the scope still bind it.
	end, ok := s.windowNow(st)
	if (!ok && !picked) || st.Rate < rate || (!picked && !deadline.IsZero() && end.Before(deadline)) {
		cur.cancel()
		return nil
	}
	sc := newScope(st)
	if slices.ContainsFunc(targets, func(t netip.Addr) bool { return !sc.contains(t) }) {
		cur.cancel()
	}
	return nil
}

// AssetChanged reacts to inventory.asset.updated and .deleted: if the device being scanned now no longer passes
// the inventory's policy (marked fragile, regular scan never, declared by hand, deleted, out of scope), or the
// run is heavier than the policy now allows, the run is stopped; that is not an attempt (the queue keeps it
// only if the policy still lets it be scanned later). Other devices are not the run's business.
func (s *Service) AssetChanged(ctx context.Context, assetID string) error {
	s.mu.Lock()
	cur := s.cur
	var gentle, picked bool
	var rate int
	match := cur != nil && cur.asset == assetID
	if match {
		gentle, rate, picked = cur.gentle, cur.rate, cur.picked
	}
	s.mu.Unlock()
	if !match {
		return nil
	}
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if picked && err == nil { // a picked identification is held to its own plan (D-501): refused now, or gentler or slower than it runs
		st, serr := s.inv.Settings(ctx)
		kind, r, why := pickedPlan(dec, st.Rate)
		if serr != nil || why != "" || (kind.IsGentle() && !gentle) || r < rate {
			cur.cancel()
		}
		return serr
	}
	if err != nil || !dec.Allowed || (dec.FirstGentle && !gentle) || (dec.Rate > 0 && dec.Rate < rate) {
		cur.cancel() // fail closed
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}
