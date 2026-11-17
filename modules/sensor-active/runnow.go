package sensoractive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/store"
)

// ---- Scan the LAN now and Check this device now (#850, INV-21) ----

// ErrManualBusy says a run a person started is still going; ErrSlotBusy that the window's sweep, a queued device's scan or a Scan now
// identification holds nmap now (review #857 L5: a check is refused, not skipped later).
var (
	ErrManualBusy = errors.New("sensoractive: a run is already going")
	ErrSlotBusy   = errors.New("sensoractive: discovery is running nmap now")
)

// TargetError is why one target of a manual run may not be checked; nothing was started. Reason is one of the Refuse* values.
type TargetError struct {
	Target string
	Reason string
	Detail string // the inventory's reason (regular_scan_never, declared_by_hand, no_ip, box, ...) behind Reason
}

func (e *TargetError) Error() string {
	return "sensoractive: target " + e.Target + " refused: " + e.Reason + " (" + e.Detail + ")"
}

// Reasons of TargetError.
const (
	RefuseUnknown    = "unknown_device" // no device has this address or id
	RefuseOutOfScope = "out_of_scope"   // outside lan_ranges, excluded, or the box itself
	RefuseNotAllowed = "not_scannable"  // the device's own safety rules refuse a check (never scan, declared by hand, no address)
)

// MaxManualTargets bounds the devices of one Check now.
const MaxManualTargets = 64

// manualFor bounds a manual sweep: the window counts as open for it, and for the scans of the devices it queued, for this long.
const manualFor = time.Hour

// ManualRun is a run a person started (#850): a sweep of the whole scope now (Assets empty) or the identification of the chosen
// devices now. It lives in memory while it runs; its nmap jobs are sa_job rows like any other.
type ManualRun struct {
	ID        string
	Assets    []string   // the device ids checked, in order; empty for a sweep
	IP        netip.Addr // the address of the device when there is one; invalid otherwise
	Ranges    []string   // the scope a sweep covers
	StartedAt time.Time
	Until     time.Time // its end at the latest: manualFor after its start (the sweep, its queue and every device check)
	Progress  *progress.View
}

type manualRun struct {
	ManualRun
	cancel context.CancelFunc
	tr     *progress.Tracker
	done   chan struct{} // closed when the run has ended
}

// Manual is the manual run going on now, nil when none.
func (s *Service) Manual() *ManualRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manual == nil {
		return nil
	}
	m := s.manual.ManualRun
	m.Progress = s.manual.tr.View()
	return &m
}

// StartManual checks a manual run, records it and starts it in the background (INV-21): no targets sweeps the whole scope now and then
// scans the devices the sweep queued, with the window counted open for manualFor ("Scan the LAN now"); targets (IPv4 addresses of
// devices or device ids, at most MaxManualTargets) identify those devices one after the other as IdentifyDevice does, all within
// manualFor ("Check this device now"). Every rule but the window holds and is checked before anything starts: the module on (ErrStopped
// once Stop ran), active scanning on (ErrScanningOff), the scope confirmed (ErrScopeNotConfirmed, ErrNoRanges), nmap present
// (ErrUnavailable), one manual run at a time (ErrManualBusy), no LAN run holding nmap now (ErrSlotBusy: the window's sweep or a device
// scan; never a check skipped later without a word), no sweep started in the last SweepGap (a *TooSoonError), and per target the device
// exists, is inside the scope and outside the exclusions and the box, and its policy lets a person check it (a *TargetError).
// record is called once the run is claimed and before anything is sent (the person's consent, review #857 M2): its error refuses the
// run and nothing starts. The run goes on after ctx ends; Stop (the module turned off) and SettingsChanged end it as any other run.
func (s *Service) StartManual(ctx context.Context, targets []string, record func(ManualRun) error) (ManualRun, error) {
	stops := s.stops.Load()
	if s.off.Load() {
		return ManualRun{}, ErrStopped
	}
	if len(targets) > MaxManualTargets {
		return ManualRun{}, &TargetError{Target: targets[MaxManualTargets], Reason: RefuseNotAllowed, Detail: "too_many"}
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return ManualRun{}, err
	}
	if err := st.allowed(); err != nil {
		return ManualRun{}, err
	}
	if err := s.available(ctx); err != nil {
		return ManualRun{}, err
	}
	ids, ip, err := s.checkTargets(ctx, st, targets)
	if err != nil {
		return ManualRun{}, err
	}
	if len(ids) == 0 {
		if err := s.sweepGap(ctx); err != nil {
			return ManualRun{}, err
		}
	}
	tr := progress.NewTracker(s.clock)
	rctx, cancel := context.WithCancel(withManual(progress.WithSink(context.WithoutCancel(ctx), tr)))
	now := s.clock()
	m := &manualRun{ManualRun: ManualRun{ID: store.NewID("sar"), Assets: ids, IP: ip, Ranges: slices.Clone(st.LANRanges), StartedAt: now, Until: now.Add(manualFor)},
		cancel: cancel, tr: tr, done: make(chan struct{})}
	s.mu.Lock()
	var refused error
	switch {
	case s.off.Load() || s.stops.Load() != stops: // the module was turned off since the checks (review #857 L1)
		refused = ErrStopped
	case s.manual != nil:
		refused = ErrManualBusy
	case s.cur != nil && !s.cur.external:
		refused = ErrSlotBusy
	default:
		s.manual = m
		if len(ids) == 0 {
			s.manualUntil = m.Until
		}
	}
	s.mu.Unlock()
	if refused != nil {
		cancel()
		return ManualRun{}, refused
	}
	if record != nil {
		if err := record(m.ManualRun); err != nil {
			s.unclaim(m)
			cancel()
			return ManualRun{}, err
		}
	}
	if len(ids) == 0 {
		tr.Report(progress.Update{Phase: progress.PhaseDiscovery, Percent: -1, NewPass: true})
	} else {
		tr.Report(progress.Phase(progress.PhaseDiscovery, ""))
	}
	go s.runManual(rctx, m)
	out := m.ManualRun
	out.Progress = tr.View()
	return out, nil
}

// SweepGap is the least time between two sweeps a person starts, or a person's and the window's (INV-21, review #857 L4): the window
// stays the rule, a sweep on demand the exception.
const SweepGap = 10 * time.Minute

// TooSoonError refuses a sweep that would start within SweepGap of the last one; RetryAfter is how long until it may.
type TooSoonError struct{ RetryAfter time.Duration }

func (e *TooSoonError) Error() string {
	return "sensoractive: a sweep ran less than " + SweepGap.String() + " ago"
}

// sweepGap refuses a sweep within SweepGap of the newest sweep's start.
func (s *Service) sweepGap(ctx context.Context) error {
	var last sql.NullString
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT max(started_at) FROM sa_job WHERE kind = 'sweep'`).Scan(&last); err != nil {
		return fmt.Errorf("sensoractive: read the last sweep: %w", err)
	}
	if !last.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, last.String)
	if err != nil {
		return fmt.Errorf("sensoractive: read the last sweep: %w", err)
	}
	if wait := t.Add(SweepGap).Sub(s.clock()); wait > 0 {
		return &TooSoonError{RetryAfter: wait}
	}
	return nil
}

// unclaim forgets a claimed run that did not start.
func (s *Service) unclaim(m *manualRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manual == m {
		s.manual = nil
		s.manualUntil = time.Time{}
	}
	close(m.done)
}

type manualKey struct{}

// withManual marks ctx as a run of a person's "Scan the LAN now": windowNow lets it run until manualUntil.
func withManual(ctx context.Context) context.Context {
	return context.WithValue(ctx, manualKey{}, true)
}

func isManual(ctx context.Context) bool { v, _ := ctx.Value(manualKey{}).(bool); return v }

// checkTargets resolves the targets to devices and refuses the first one a person may not check now; ip is the address of the only
// device when there is one.
func (s *Service) checkTargets(ctx context.Context, st Settings, targets []string) (ids []string, ip netip.Addr, err error) {
	if len(targets) == 0 {
		return nil, netip.Addr{}, nil
	}
	addrs, err := s.inv.Addresses(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	protected, err := s.inv.ProtectedIPs(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	box, err := s.inv.BoxIPs(ctx) // the box and its decoys: never, whatever the device row says (review #857 L3)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	sc := newScope(st)
	for _, t := range targets {
		id := t
		if a, perr := netip.ParseAddr(t); perr == nil {
			if id = addrs[a.Unmap()]; id == "" {
				return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseUnknown, Detail: "no_device"}
			}
		}
		asset, aerr := s.inv.Asset(ctx, id)
		if errors.Is(aerr, ErrNotFound) {
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseUnknown, Detail: "no_device"}
		}
		if aerr != nil {
			return nil, netip.Addr{}, aerr
		}
		dec, perr := s.inv.ScanPolicy(ctx, asset.ID)
		if perr != nil {
			return nil, netip.Addr{}, perr
		}
		_, _, why := pickedPlan(dec, st.Rate)
		switch {
		case why == "out_of_scope" || why == reasonBox:
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseOutOfScope, Detail: why}
		case why != "":
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseNotAllowed, Detail: why}
		case !asset.IP.IsValid():
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseNotAllowed, Detail: "no_ip"}
		case slices.Contains(box, asset.IP):
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseOutOfScope, Detail: reasonBox}
		case !sc.contains(asset.IP):
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseOutOfScope, Detail: "out_of_scope"}
		case slices.Contains(protected, asset.IP) && dec.Reason != reasonFragilePassive && dec.Reason != reasonUnclassifiedPassive:
			return nil, netip.Addr{}, &TargetError{Target: t, Reason: RefuseOutOfScope, Detail: reasonBox}
		}
		if !slices.Contains(ids, asset.ID) {
			ids = append(ids, asset.ID)
			ip = asset.IP
		}
	}
	if len(ids) != 1 {
		ip = netip.Addr{}
	}
	return ids, ip, nil
}

// runManual runs m and forgets it when it ends.
func (s *Service) runManual(ctx context.Context, m *manualRun) {
	defer func() {
		m.cancel()
		s.mu.Lock()
		if s.manual == m {
			s.manual = nil
			s.manualUntil = time.Time{}
		}
		s.mu.Unlock()
		close(m.done)
	}()
	if len(m.Assets) == 0 {
		s.manualSweep(ctx)
		return
	}
	for i, id := range m.Assets {
		left := m.Until.Sub(s.clock())
		if ctx.Err() != nil || s.off.Load() {
			return
		}
		if left <= 0 { // the run's hour is over: the rest wait for the window (review #857 L4)
			s.queueRest(ctx, m.Assets[i:], "the check a person started ran out of time")
			return
		}
		dctx, cancel := context.WithTimeout(ctx, left)
		res, err := s.IdentifyDevice(dctx, id)
		cancel()
		switch {
		case errors.Is(err, ErrStopped):
			if ctx.Err() == nil && s.clock().Before(m.Until) && !s.off.Load() {
				continue // stopped for this device alone (it changed); the next one is checked
			}
			if !s.off.Load() && ctx.Err() == nil {
				s.queueRest(ctx, m.Assets[i:], "the check a person started ran out of time")
			}
			return
		case err != nil:
			s.log.WarnContext(ctx, "sensoractive: a device check a person started failed", "asset", id, "error", err)
		case res.Why == reasonScanningOff || res.Why == reasonScopeNotConfirmed: // discovery turned off, or the scope, since it started
			return
		case res.Why == WhyBusy: // another run kept nmap (an exposure scan): the window's queue takes it, never a silent skip (L5)
			s.queueRest(ctx, []string{id}, "nmap was busy")
		case res.Why != "":
			s.log.InfoContext(ctx, "sensoractive: a device check a person started found nothing to record", "asset", id, "why", res.Why)
		}
	}
}

// queueRest puts the devices a manual check could not reach in the window's queue, and says so in the log.
func (s *Service) queueRest(ctx context.Context, ids []string, why string) {
	ctx = context.WithoutCancel(ctx)
	for _, id := range ids {
		if err := s.Enqueue(ctx, id, "check_now"); err != nil {
			s.log.WarnContext(ctx, "sensoractive: queueing a device a person asked to check failed", "asset", id, "error", err)
		}
	}
	s.log.WarnContext(ctx, "sensoractive: devices a person asked to check wait for the next window", "devices", len(ids), "why", why)
}

// manualSweep is "Scan the LAN now": the sweep from the first address of the scope, then the scans of the devices it queued (the
// gentle scan first for fragile and unclassified ones), with the window counted open for at most manualFor. Every other
// rule holds; a change of settings stops it as it stops the window's runs.
func (s *Service) manualSweep(ctx context.Context) {
	s.setCursor(ctx, netip.Addr{}) // the whole scope, not the rest of a pass the window cut
	s.log.InfoContext(ctx, "sensoractive: a sweep a person started, outside the window", "for", manualFor.String())
	if _, err := s.DiscoverRanges(ctx); err != nil && !errors.Is(err, ErrStopped) && !errors.Is(err, ErrOutsideWindow) {
		s.log.WarnContext(ctx, "sensoractive: the sweep a person started did not run", "error", err)
	}
	if ctx.Err() != nil {
		return
	}
	if err := s.drain(ctx); err != nil {
		s.log.WarnContext(ctx, "sensoractive: scanning the queued devices after a sweep a person started failed", "error", err)
	}
}

// WaitManual returns once no manual run goes on, or with ctx's error: for a shutdown that must not leave nmap running, and tests.
func (s *Service) WaitManual(ctx context.Context) error {
	s.mu.Lock()
	m := s.manual
	s.mu.Unlock()
	if m == nil {
		return nil
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopManual ends the manual run, if one runs (Stop).
func (s *Service) stopManual() {
	s.mu.Lock()
	m := s.manual
	s.mu.Unlock()
	if m != nil {
		m.cancel()
	}
}

// ---- the engine cards of Settings › Scanning (#850) ----

// JobHead is an sa_job row.
type JobHead struct {
	ID, Kind, Status string
	Reason           string // "" when none (a window's run); scan_now for an identification a person asked for
	StartedAt        string
	FinishedAt       *string
	Targets          int
	NewDevices       int
	Error            string
}

// Current is the LAN job holding the nmap slot now: a sweep (Asset "") or the scan of one device. External runs (exposure) are not
// listed: their own module shows them.
type Current struct {
	JobID     string // its sa_job row; "" before the row is written
	Kind      string // sweep or device
	Asset     string
	Targets   []netip.Addr
	Manual    bool // part of the manual run
	StartedAt time.Time
}

// EngineView is what Settings › Scanning shows of active discovery, the version scans and the SNMP rounds.
type EngineView struct {
	Health     Health
	NextWindow *time.Time         // the next time a window opens; nil when the settings have none
	Open       bool               // a window is open now
	Last       map[string]JobHead // the newest job that ended, by kind (sweep, device, snmp)
	Current    *Current
	SNMP       *JobHead // the SNMP batch running now (its sa_job row), nil when none
	Manual     *ManualRun
}

// Engine reads EngineView.
func (s *Service) Engine(ctx context.Context) (EngineView, error) {
	v := EngineView{Health: s.Health(ctx), Last: map[string]JobHead{}, Manual: s.Manual()}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return EngineView{}, err
	}
	now := s.local()
	_, _, v.Open = st.window(now)
	v.NextWindow = st.nextOpening(now)
	for _, k := range []string{KindSweep, KindDevice, KindSNMP} {
		var h JobHead
		var reason, errText sql.NullString
		err := s.db.Reader().QueryRowContext(ctx, `SELECT id, kind, status, reason, started_at, finished_at, targets, new_devices, error FROM sa_job
WHERE kind = ? AND status <> 'running' ORDER BY started_at DESC, rowid DESC LIMIT 1`, k).Scan(&h.ID, &h.Kind, &h.Status, &reason, &h.StartedAt, &h.FinishedAt, &h.Targets, &h.NewDevices, &errText)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return EngineView{}, fmt.Errorf("sensoractive: read the newest %s job: %w", k, err)
		}
		h.Reason, h.Error = reason.String, errText.String
		v.Last[k] = h
	}
	s.mu.Lock()
	if c := s.cur; c != nil && !c.external {
		kind := KindDevice
		if c.asset == "" && !c.picked {
			kind = KindSweep
		}
		v.Current = &Current{Kind: kind, Asset: c.asset, Targets: slices.Clone(c.targets), Manual: s.manual != nil, StartedAt: c.started}
	}
	snmpBusy := s.snmpCur != nil
	s.mu.Unlock()
	// The rows of the runs in memory (a row still "running" with nothing in memory is one a restart cut; Tick closes it).
	if v.Current != nil {
		if h, err := s.runningJob(ctx, v.Current.Kind); err != nil {
			return EngineView{}, err
		} else if h != nil {
			v.Current.JobID = h.ID
		}
	}
	if snmpBusy {
		h, err := s.runningJob(ctx, KindSNMP)
		if err != nil {
			return EngineView{}, err
		}
		v.SNMP = h
	}
	return v, nil
}

// runningJob is the newest sa_job row of kind still running; nil when none.
func (s *Service) runningJob(ctx context.Context, kind string) (*JobHead, error) {
	h := JobHead{Kind: kind, Status: StatusRunning}
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id, started_at, targets FROM sa_job WHERE kind = ? AND status = 'running' ORDER BY started_at DESC, rowid DESC LIMIT 1`, kind).
		Scan(&h.ID, &h.StartedAt, &h.Targets)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // none
	}
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read the running %s job: %w", kind, err)
	}
	return &h, nil
}

// nextOpening is the first start of a window after t (in t's location), within the next eight days; nil when there is none.
func (st Settings) nextOpening(t time.Time) *time.Time {
	from, ok1 := minutes(st.From)
	to, ok2 := minutes(st.To)
	if !ok1 || !ok2 || from == to || len(st.Days) == 0 {
		return nil
	}
	for ahead := range 8 {
		d := t.AddDate(0, 0, ahead)
		wd := int(d.Weekday())
		if wd == 0 {
			wd = 7
		}
		start := time.Date(d.Year(), d.Month(), d.Day(), from/60, from%60, 0, 0, t.Location())
		if slices.Contains(st.Days, wd) && start.After(t) {
			return &start
		}
	}
	return nil
}

// JobRow is an sa_job row for a list of past runs, with every probe it sent (read only): a sweep runs in batches, an SNMP
// read records "ok: n of m answered", so what the run found is in its probes, never only in the row's target count.
type JobRow struct {
	JobHead
	Probes []JobProbe // in the order they were sent; empty when it sent none
}

// JobProbe is one probe of a job: its targets (an address, or the ranges of a sweep batch) and its result as recorded ("ok: 3 hosts
// up", "ok: 2 of 3 answered", "failed: …"; "" while it runs).
type JobProbe struct{ Targets, Result string }

// Jobs lists the newest sa_job rows of the LAN (sweep, device, snmp; external runs are part of exposure's scans), newest first, at
// most limit (1..500), each with its probes. Read only: Settings › Scanning › History. One indexed read per kind
// (sa_job (kind, started_at)), then the probes of the listed jobs in one read (sa_probe (job_id)).
func (s *Service) Jobs(ctx context.Context, limit int) ([]JobRow, error) {
	limit = clamp(limit, 1, 500)
	out := []JobRow{}
	for _, kind := range []string{KindSweep, KindDevice, KindSNMP} {
		rows, err := s.jobHeads(ctx, `WHERE kind = ? ORDER BY started_at DESC, rowid DESC LIMIT ?`, kind, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	slices.SortStableFunc(out, func(a, b JobRow) int { return strings.Compare(b.StartedAt, a.StartedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, s.jobProbes(ctx, out)
}

// snmpReadsScanned is how many of the newest SNMP reads JobsAt looks through: a read keeps its addresses as a compact list with
// ranges, which SQL cannot match, so they are matched here. An older read of the address is not found (the contract says so).
const snmpReadsScanned = 1000

// JobsAt lists the LAN jobs that reached addr (the device page's Last checks), newest first, at most limit (1..500) of
// each kind: the identifications of that address (kind device: Check this device now, the window's queue, the first step of a
// vulnerability check) and the SNMP reads that asked it (rounds, Read now, a credential Test) among the newest snmpReadsScanned
// reads. No sweep: it reaches every address of the scope and identifies nothing. Read only; the probes, and so the jobs, are kept
// ProbeRetention. Two jobs started in the same millisecond come newest row first.
func (s *Service) JobsAt(ctx context.Context, addr netip.Addr, limit int) ([]JobRow, error) {
	limit = clamp(limit, 1, 500)
	out, err := s.jobHeads(ctx, `j WHERE kind = ? AND EXISTS (SELECT 1 FROM sa_probe p WHERE p.job_id = j.id AND p.targets = ?)
ORDER BY j.started_at DESC, j.rowid DESC LIMIT ?`, KindDevice, addr.String(), limit)
	if err != nil {
		return nil, err
	}
	if err := s.jobProbes(ctx, out); err != nil {
		return nil, err
	}
	reads, err := s.jobHeads(ctx, `WHERE kind = ? ORDER BY started_at DESC, rowid DESC LIMIT ?`, KindSNMP, snmpReadsScanned)
	if err != nil {
		return nil, err
	}
	if err := s.jobProbes(ctx, reads); err != nil {
		return nil, err
	}
	n := 0
	for _, r := range reads {
		if n == limit {
			break
		}
		if slices.ContainsFunc(r.Probes, func(p JobProbe) bool { return targetsHave(p.Targets, addr) }) {
			out = append(out, r)
			n++
		}
	}
	slices.SortStableFunc(out, func(a, b JobRow) int { return strings.Compare(b.StartedAt, a.StartedAt) })
	return out, nil
}

// targetsHave tells whether a probe's compact target list ("192.168.18.1-192.168.18.4,192.168.18.9", compactTargets) names addr.
func targetsHave(list string, addr netip.Addr) bool {
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := netip.ParseAddr(lo)
		if err != nil {
			continue
		}
		if !isRange {
			if a == addr {
				return true
			}
			continue
		}
		if b, err := netip.ParseAddr(hi); err == nil && a.Compare(addr) <= 0 && addr.Compare(b) <= 0 {
			return true
		}
	}
	return false
}

// jobHeads reads sa_job rows: where is the rest of the statement after FROM sa_job (an alias, WHERE, ORDER BY and LIMIT).
func (s *Service) jobHeads(ctx context.Context, where string, args ...any) ([]JobRow, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, kind, status, reason, started_at, finished_at, targets, new_devices, error FROM sa_job `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []JobRow
	for rows.Next() {
		var r JobRow
		var reason, errText sql.NullString
		if err := rows.Scan(&r.ID, &r.Kind, &r.Status, &reason, &r.StartedAt, &r.FinishedAt, &r.Targets, &r.NewDevices, &errText); err != nil {
			return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
		}
		r.Reason, r.Error = reason.String, errText.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
	}
	return out, nil
}

// jobProbes fills the probes of these jobs, in the order they were sent, in one read (sa_probe (job_id)).
func (s *Service) jobProbes(ctx context.Context, out []JobRow) error {
	if len(out) == 0 {
		return nil
	}
	at := make(map[string]int, len(out))
	ids := make([]string, len(out))
	for i, r := range out {
		at[r.ID], ids[i] = i, r.ID
	}
	list, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("sensoractive: list job probes: %w", err)
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT job_id, targets, result FROM sa_probe WHERE job_id IN (SELECT value FROM json_each(?)) ORDER BY id`, string(list))
	if err != nil {
		return fmt.Errorf("sensoractive: list job probes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var p JobProbe
		if err := rows.Scan(&id, &p.Targets, &p.Result); err != nil {
			return fmt.Errorf("sensoractive: list job probes: %w", err)
		}
		if i, ok := at[id]; ok {
			out[i].Probes = append(out[i].Probes, p)
		}
	}
	return rows.Err()
}
