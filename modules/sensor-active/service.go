package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

const (
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
	Events    Publisher
	NmapPath  string // absolute path of the OS package's nmap; Health reads it, and the local Prober runs it
	// Prober runs the nmap command the module has already checked. Nil means the local one, core/exec around
	// NmapPath (NewLocalProber); SP-3 adds the one that hands the job to a worker.
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
	events Publisher
	path   string
	prober Prober
	clock  func() time.Time
	log    *slog.Logger
	loc    func() *time.Location

	runMu sync.Mutex // one nmap job at a time on the box

	ver atomic.Uint64 // bumped by every SettingsChanged; a run that sees it move before nmap starts stops

	mu  sync.Mutex
	cur *running // the job holding runMu, for SettingsChanged
}

type running struct {
	cancel   context.CancelFunc
	targets  []netip.Addr // the run in progress, published before it is checked
	rate     int          // the packets per second of the run
	deadline time.Time    // when the run in progress stops by itself: the end of the window it was checked against, or maxRun
	asset    string       // the device a device run is for ("" for a sweep), set before its policy is read
	gentle   bool         // the run is the one gentle scan
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Inventory == nil || cfg.Observe == nil || cfg.Software == nil {
		return nil, errors.New("sensoractive: New needs DB, Inventory, Observe and Software")
	}
	s := &Service{db: cfg.DB, inv: cfg.Inventory, obs: cfg.Observe, sw: cfg.Software, events: cfg.Events, path: cfg.NmapPath, clock: cfg.Clock, log: cfg.Log, loc: cfg.Location}
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
	fi, err := os.Stat(s.path)
	switch {
	case err != nil:
		h.Status, h.Message = "unavailable", "nmap is not installed at "+s.path+"; active discovery cannot run until it is installed"
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
		h.Status, h.Message = "unavailable", s.path+" is not an executable file; active discovery cannot run"
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
	if _, _, ok := st.window(s.local()); !ok {
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
	_, end, ok := st.window(s.local())
	if !ok {
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
	timeout := min(end.Sub(s.clock()), maxRun)
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
		if errors.As(runErr, &ee) {
			result = fmt.Sprintf("failed: nmap exited with code %d", ee.ExitCode)
		} else {
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
	if kind == nmapargv.Gentle {
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

// Probes returns the probe log from since on, oldest first, at most limit rows (INV-9). The future
// scan_probes export category of /core/logs/export reads it. Argv is the flag part stored with the row, so
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
	known, err := s.inv.Addresses(ctx)
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
		if _, _, ok := st.window(s.local()); !ok {
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
		case err == nil:
			var n int
			if n, err = s.recordSweep(ctx, hosts, batch, known); err == nil {
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

// recordSweep stores what a sweep batch found and returns how many of the hosts are new to the inventory.
func (s *Service) recordSweep(ctx context.Context, hosts []host, batch []netip.Addr, known map[netip.Addr]string) (int, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	var obs []observe.Observation
	var fresh []netip.Addr
	for _, h := range onlyTargets(hosts, batch) {
		o := sweepObservations(h)
		if len(o) == 0 {
			continue
		}
		obs = append(obs, o...)
		if _, had := known[h.addr]; !had {
			fresh = append(fresh, h.addr)
		}
	}
	if len(obs) == 0 {
		return 0, nil
	}
	if err := s.obs.Record(ctx, obs); err != nil {
		return 0, fmt.Errorf("sensoractive: recording hosts: %w", err)
	}
	for _, a := range fresh {
		known[a] = ""
	}
	return len(fresh), nil
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
		kind, rate = nmapargv.Gentle, 1
	}
	s.setGentle(kind == nmapargv.Gentle)

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
		err = errors.Join(markErr, s.recordDevice(ctx, asset.IP, hosts))
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

// recordDevice stores what a service scan found about ip. A host that did not answer changes nothing.
func (s *Service) recordDevice(ctx context.Context, ip netip.Addr, hosts []host) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	i := slices.IndexFunc(hosts, func(h host) bool { return h.addr == ip })
	if i < 0 {
		return nil
	}
	h := hosts[i]
	if obs := deviceObservations(h); len(obs) > 0 {
		if err := s.obs.Record(ctx, obs); err != nil {
			return fmt.Errorf("sensoractive: recording observations: %w", err)
		}
	}
	if err := s.sw.ReplaceSoftware(ctx, observe.AssetHint{IP: ip}, observe.Nmap, softwareOf(h)); err != nil {
		return fmt.Errorf("sensoractive: recording software: %w", err)
	}
	return nil
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
	start, _, ok := st.window(s.local())
	if st.allowed() != nil || !ok {
		return nil
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
	if cur != nil {
		targets, rate, deadline = slices.Clone(cur.targets), cur.rate, cur.deadline
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
	// A window shortened under a run in progress ends it: the run's deadline came from the old end (INV-3).
	_, end, ok := st.window(s.local())
	if !ok || st.Rate < rate || (!deadline.IsZero() && end.Before(deadline)) {
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
	var gentle bool
	var rate int
	match := cur != nil && cur.asset == assetID
	if match {
		gentle, rate = cur.gentle, cur.rate
	}
	s.mu.Unlock()
	if !match {
		return nil
	}
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if err != nil || !dec.Allowed || (dec.FirstGentle && !gentle) || (dec.Rate > 0 && dec.Rate < rate) {
		cur.cancel() // fail closed
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}
