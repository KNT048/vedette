package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
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
	NmapPath  string // absolute path of the OS package's nmap; the module builds its own core/exec Runner around it
	Clock     func() time.Time
	Log       *slog.Logger
}

// Service runs active discovery. Create it with New. It is the only writer of the sa_* tables.
type Service struct {
	db     *store.DB
	inv    Inventory
	obs    observe.Sink
	sw     observe.SoftwareSink
	events Publisher
	path   string
	runner *exec.Runner
	clock  func() time.Time
	log    *slog.Logger

	runMu sync.Mutex // one nmap job at a time on the box

	mu  sync.Mutex
	cur *running // the job holding runMu, for SettingsChanged
}

type running struct {
	cancel  context.CancelFunc
	targets []netip.Addr // the run in progress
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Inventory == nil || cfg.Observe == nil || cfg.Software == nil {
		return nil, errors.New("sensoractive: New needs DB, Inventory, Observe and Software")
	}
	s := &Service{db: cfg.DB, inv: cfg.Inventory, obs: cfg.Observe, sw: cfg.Software, events: cfg.Events, path: cfg.NmapPath, clock: cfg.Clock, log: cfg.Log}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	r, err := exec.NewRunner(s.log, NmapBinary(cfg.NmapPath))
	if err != nil {
		return nil, fmt.Errorf("sensoractive: %w", err)
	}
	s.runner = r
	return s, nil
}

func (s *Service) now() string      { return store.FormatTS(s.clock()) }
func (s *Service) local() time.Time { return s.clock().In(time.Local) }

func (s *Service) publish(ctx context.Context, name string, data any) {
	if s.events == nil {
		return
	}
	if err := s.events.Publish(ctx, Event{Name: name, Data: data}); err != nil {
		s.log.WarnContext(ctx, "sensoractive: publishing an event failed", "event", name, "error", err)
	}
}

// Health reports INV-6: nmap is the OS package, and without it the module has no way to work.
func (s *Service) Health(context.Context) Health {
	fi, err := os.Stat(s.path)
	switch {
	case err != nil:
		return Health{Status: "unavailable", Message: "nmap is not installed at " + s.path + "; active discovery cannot run until it is installed"}
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
		return Health{Status: "unavailable", Message: s.path + " is not an executable file; active discovery cannot run"}
	}
	return Health{Status: "ok"}
}

func (s *Service) available(ctx context.Context) error {
	if h := s.Health(ctx); h.Status != "ok" {
		return fmt.Errorf("%w: %s", ErrUnavailable, h.Message)
	}
	return nil
}

// permit is the gate of every run (INV-2, INV-3, INV-6): the settings now, the window now, nmap present. It
// returns the settings and the end of the current window.
func (s *Service) permit(ctx context.Context) (Settings, time.Time, error) {
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return Settings{}, time.Time{}, err
	}
	if err := st.allowed(); err != nil {
		return st, time.Time{}, err
	}
	_, end, ok := st.window(s.local())
	if !ok {
		return st, time.Time{}, ErrOutsideWindow
	}
	if err := s.available(ctx); err != nil {
		return st, time.Time{}, err
	}
	return st, end, nil
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

// failInterrupted closes jobs a restart left "running" (nothing runs now: the caller holds runMu).
func (s *Service) failInterrupted(ctx context.Context) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sa_job SET status = 'stopped', finished_at = ?, error = 'interrupted by a restart' WHERE status = 'running'`, s.now())
		return err
	})
}

// ---- the run of nmap ----

// probe runs one nmap command over targets and returns the hosts that answered. It writes the probe row
// before the process starts (INV-9: no packet without a log line) and its result after. The deadline is the
// window's end or maxRun; when it passes, or ctx is cancelled, exec kills the process group and the batch is
// dropped (PRE-3, POST-3).
func (s *Service) probe(ctx context.Context, jobID string, kind scanKind, rate int, targets []netip.Addr, end time.Time) ([]host, error) {
	args, err := buildNmapArgs(kind, rate, targets)
	if err != nil {
		return nil, err
	}
	timeout := min(end.Sub(s.clock()), maxRun)
	if timeout <= 0 {
		return nil, ErrStopped
	}
	probeID, err := s.insertProbe(ctx, jobID, targets, args)
	if err != nil {
		return nil, err
	}
	s.setTargets(targets)
	defer s.setTargets(nil)

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, runErr := s.runner.Run(rctx, nmapName, args, nil)

	var hosts []host
	var result string
	switch {
	case rctx.Err() != nil || ctx.Err() != nil:
		result, err = "stopped: the window closed, the scope changed or the module was turned off", ErrStopped
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
		if all, err = parseNmapXML(res.Stdout); err != nil {
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

func (s *Service) setTargets(t []netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.targets = t
	}
}

func targetText(t []netip.Addr) string {
	if len(t) == 1 {
		return t[0].String()
	}
	return fmt.Sprintf("%s..%s (%d hosts)", t[0], t[len(t)-1], len(t))
}

func (s *Service) insertProbe(ctx context.Context, jobID string, targets []netip.Addr, args []string) (int64, error) {
	argv, err := json.Marshal(args)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO sa_probe (time, target, argv, result, job_id) VALUES (?, ?, ?, 'started', ?)`, s.now(), targetText(targets), string(argv), jobID)
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
// scan_probes export category of /core/logs/export reads it.
func (s *Service) Probes(ctx context.Context, since time.Time, limit int) ([]Probe, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT time, target, argv, result, job_id FROM sa_probe WHERE time >= ? ORDER BY id LIMIT ?`, store.FormatTS(since), clamp(limit, 1, 100000))
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read probes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Probe
	for rows.Next() {
		var p Probe
		var argv string
		if err := rows.Scan(&p.Time, &p.Target, &argv, &p.Result, &p.JobID); err != nil {
			return nil, fmt.Errorf("sensoractive: read probes: %w", err)
		}
		if err := json.Unmarshal([]byte(argv), &p.Argv); err != nil {
			return nil, fmt.Errorf("sensoractive: read probes: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Prune deletes probe rows older than ProbeRetention and returns how many (D-84 (9)).
func (s *Service) Prune(ctx context.Context) (int, error) {
	var n int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sa_probe WHERE time < ?`, store.FormatTS(s.clock().Add(-ProbeRetention)))
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

// nextBatch takes up to MaxBatch addresses from w, each checked with the inventory's InScope immediately
// before it is accepted (INV-1). It returns fewer only when the ranges are used up.
func (s *Service) nextBatch(ctx context.Context, w *walker) ([]netip.Addr, error) {
	var batch []netip.Addr
	for len(batch) < MaxBatch {
		a, ok := w.next()
		if !ok {
			break
		}
		in, err := s.inv.InScope(ctx, a)
		if err != nil {
			return nil, err
		}
		if in {
			batch = append(batch, a)
		}
	}
	return batch, nil
}

func rangeSize(ps []netip.Prefix) int {
	n := 0
	for _, p := range ps {
		n += 1 << (32 - p.Bits())
	}
	return n
}

// DiscoverRanges sweeps the confirmed ranges once with nmap host discovery (PRE-1): every address of
// lan_ranges outside the exclusions is probed at most once, in batches of MaxBatch. The settings and the window
// are read again before every batch, so a change takes effect at the next one (and SettingsChanged stops the
// batch in progress). A batch cut off by the window or a stop is dropped, finished batches stay stored, and the
// job is "stopped" (POST-3). Hosts found are recorded in the inventory by MAC; devices that are new there
// reach the queue through inventory.asset.discovered.
func (s *Service) DiscoverRanges(ctx context.Context) (Result, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	st, _, err := s.permit(ctx)
	if err != nil {
		return Result{}, err
	}
	known, err := s.inv.Addresses(ctx)
	if err != nil {
		return Result{}, err
	}
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel})
	defer s.setCur(nil)

	ps := prefixes(st.LANRanges)
	id, err := s.startJob(ctx, KindSweep, "", rangeSize(ps))
	if err != nil {
		return Result{}, err
	}
	res := Result{JobID: id}
	var end time.Time // the end of the window, read again before every batch
	var failed int
	var firstErr string
	status := StatusDone
	w := newWalker(ps)
loop:
	for {
		if st, err = s.inv.Settings(jctx); err == nil {
			err = st.allowed()
		}
		if err != nil {
			status, firstErr = StatusStopped, "stopped: "+err.Error()
			break
		}
		var ok bool
		if _, end, ok = st.window(s.local()); !ok {
			status, firstErr = StatusStopped, "stopped: the window closed"
			break
		}
		batch, err := s.nextBatch(jctx, w)
		if err != nil {
			status, firstErr = StatusFailed, "reading the scope failed"
			if jctx.Err() != nil {
				status, firstErr = StatusStopped, "stopped"
			}
			break
		}
		if len(batch) == 0 {
			break
		}
		hosts, err := s.probe(jctx, id, kindSweep, st.Rate, batch, end)
		switch {
		case errors.Is(err, ErrStopped):
			status, firstErr = StatusStopped, "stopped: the window closed, the scope changed or the module was turned off"
			break loop
		case err == nil:
			var n int
			if n, err = s.recordSweep(ctx, hosts, batch, known); err == nil {
				res.Targets += len(batch)
				res.NewDevices += n
				continue
			}
			fallthrough
		default:
			failed++
			if firstErr == "" {
				firstErr = err.Error()
			}
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

func (s *Service) setCur(r *running) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = r
}

// ---- one device ----

// ScanDevice identifies one device with nmap (PRE-2): the inventory's ScanPolicy must allow it, the window
// must be open (D-84 (1): even the one gentle scan of a fragile device waits for it), and the device's address
// must be in scope immediately before the command line is built (INV-1). A refusal by policy or scope
// publishes sensor.scan.blocked and sends nothing. reason says why it was asked ("discovered", ...).
func (s *Service) ScanDevice(ctx context.Context, assetID, reason string) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	dec, err := s.inv.ScanPolicy(ctx, assetID)
	if err != nil {
		return err
	}
	if !dec.Allowed {
		s.blocked(ctx, assetID, dec.Reason)
		return fmt.Errorf("%w: %s", ErrBlocked, dec.Reason)
	}
	st, end, err := s.permit(ctx)
	switch {
	case errors.Is(err, ErrScanningOff), errors.Is(err, ErrScopeNotConfirmed), errors.Is(err, ErrNoRanges):
		s.blocked(ctx, assetID, reasonOf(err))
		return err
	case err != nil:
		return err
	}
	asset, err := s.inv.Asset(ctx, assetID)
	if err != nil {
		return err
	}
	in := false
	if asset.IP.IsValid() {
		if in, err = s.inv.InScope(ctx, asset.IP); err != nil {
			return err
		}
	}
	if !in {
		s.blocked(ctx, assetID, "out_of_scope")
		return fmt.Errorf("%w: out_of_scope", ErrBlocked)
	}
	kind, rate := kindNormal, st.Rate
	if dec.Rate > 0 {
		rate = min(rate, dec.Rate)
	}
	if dec.FirstGentle {
		kind, rate = kindGentle, 1
	}

	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel})
	defer s.setCur(nil)
	id, err := s.startJob(ctx, KindDevice, reason, 1)
	if err != nil {
		return err
	}
	hosts, err := s.probe(jctx, id, kind, rate, []netip.Addr{asset.IP}, end)
	if err == nil {
		err = s.recordDevice(ctx, asset.IP, hosts)
	}
	if err == nil && dec.FirstGentle {
		err = s.inv.MarkFirstScan(context.WithoutCancel(ctx), assetID)
	}
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, id, StatusStopped, 0, 0, "stopped: the window closed, the scope changed or the module was turned off")
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

func (s *Service) leave(ctx context.Context, id string, failed bool) {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if failed {
			if _, err := tx.ExecContext(ctx, `UPDATE sa_queue SET attempts = attempts + 1 WHERE asset_id = ?`, id); err != nil {
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

// SettingsChanged reacts to inventory.settings.changed: if a run is in progress and the settings no longer
// allow it (scanning off, scope unconfirmed, outside the window, the run's addresses out of scope), it is
// stopped now. The next batch reads the new settings by itself.
func (s *Service) SettingsChanged(ctx context.Context) error {
	s.mu.Lock()
	cur := s.cur
	var targets []netip.Addr
	if cur != nil {
		targets = slices.Clone(cur.targets)
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
	if _, _, ok := st.window(s.local()); !ok {
		cur.cancel()
		return nil
	}
	for _, t := range targets {
		if in, err := s.inv.InScope(ctx, t); err != nil || !in {
			cur.cancel()
			return err
		}
	}
	return nil
}
