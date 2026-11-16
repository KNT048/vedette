package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/store"
)

// ---- Scan the LAN now and Check this device now (#850, INV-21) ----

// ErrManualBusy says a run a person started is still going, or (for a sweep) the window's own sweep or a device scan holds the nmap slot.
var ErrManualBusy = errors.New("sensoractive: a run is already going")

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
	StartedAt time.Time  //
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

// StartManual checks a manual run and starts it in the background (INV-21): no targets sweeps the whole scope now and then scans the
// devices the sweep queued, with the window counted open for manualFor ("Scan the LAN now"); targets (IPv4 addresses of devices or
// device ids, at most MaxManualTargets) identify those devices one after the other as IdentifyDevice does ("Check this device now").
// Every rule but the window holds and is checked before anything starts: active scanning on (ErrScanningOff), the scope confirmed
// (ErrScopeNotConfirmed, ErrNoRanges), nmap present (ErrUnavailable), one manual run at a time (ErrManualBusy), and per target the device
// exists, is inside the scope and outside the exclusions and the box, and its policy lets a person check it (a *TargetError).
// The run goes on after ctx ends; Stop (the module turned off) and SettingsChanged end it as any other run.
func (s *Service) StartManual(ctx context.Context, targets []string) (ManualRun, error) {
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
	s.mu.Lock()
	busy := s.manual != nil || (len(ids) == 0 && s.cur != nil && !s.cur.external)
	s.mu.Unlock()
	if busy {
		return ManualRun{}, ErrManualBusy
	}
	tr := progress.NewTracker(s.clock)
	rctx, cancel := context.WithCancel(progress.WithSink(context.WithoutCancel(ctx), tr))
	m := &manualRun{ManualRun: ManualRun{ID: store.NewID("sar"), Assets: ids, IP: ip, Ranges: slices.Clone(st.LANRanges), StartedAt: s.clock()}, cancel: cancel, tr: tr, done: make(chan struct{})}
	s.mu.Lock()
	if s.manual != nil {
		s.mu.Unlock()
		cancel()
		return ManualRun{}, ErrManualBusy
	}
	s.manual = m
	s.mu.Unlock()
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
		}
		s.mu.Unlock()
		close(m.done)
	}()
	if len(m.Assets) == 0 {
		s.manualSweep(ctx)
		return
	}
	for _, id := range m.Assets {
		if ctx.Err() != nil {
			return
		}
		res, err := s.IdentifyDevice(ctx, id)
		switch {
		case errors.Is(err, ErrStopped):
			return
		case err != nil:
			s.log.WarnContext(ctx, "sensoractive: a device check a person started failed", "asset", id, "error", err)
		case res.Why != "":
			s.log.InfoContext(ctx, "sensoractive: a device check a person started found nothing to record", "asset", id, "why", res.Why)
		}
	}
}

// manualSweep is "Scan the LAN now": the sweep from the first address of the scope, then the scans of the devices it queued (the
// gentle scan first for fragile and unclassified ones, D-84 (1)), with the window counted open for at most manualFor. Every other
// rule holds; a change of settings stops it as it stops the window's runs.
func (s *Service) manualSweep(ctx context.Context) {
	s.mu.Lock()
	s.manualUntil = s.clock().Add(manualFor)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.manualUntil = time.Time{}
		s.mu.Unlock()
	}()
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
