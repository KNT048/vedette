package sensoractive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/run"
)

// ---- Scan the LAN now and Check this device now (#850, INV-21) ----

// ErrSlotBusy says a sweep is going now: a second sweep is refused (the one going is the person's answer); a person's check is
// queued behind it instead and says so.
var ErrSlotBusy = errors.New("sensoractive: discovery is running nmap now")

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

// manualFor bounds a manual sweep: the window counts as open for it, and for the checks of the devices it found, for this long.
const manualFor = time.Hour

// ManualRun is a run a person started (#850, INV-21): a sweep of the whole scope now (Assets empty), or the checks of the chosen
// devices now, one device_check run each (ID is the first). Its record is core_run.
type ManualRun struct {
	ID        string
	Runs      []string   // every run it queued: the sweep, or one check per device in the order of Assets
	Assets    []string   // the device ids checked, in order; empty for a sweep
	IP        netip.Addr // the address of the device when there is one; invalid otherwise
	Ranges    []string   // the scope a sweep covers
	StartedAt time.Time
	Until     time.Time // a sweep's end outside the window at the latest: manualFor after its start
	Progress  *progress.View
}

// sweepUntil is when the window stops counting as open for pass r: a person's sweep, or a pass a person asked to go on now, runs
// outside the window for manualFor from the moment it was asked; zero for every other pass.
func (s *Service) sweepUntil(r run.Run) time.Time {
	var until time.Time
	if r.Trigger == run.Manual && r.StartedAt != nil {
		if t, err := time.Parse(time.RFC3339Nano, *r.StartedAt); err == nil {
			until = t.Add(manualFor)
		}
	}
	s.mu.Lock()
	if t := s.personUntil[r.ID]; t.After(until) {
		until = t
	}
	s.mu.Unlock()
	return until
}

type manualKey struct{}

// withManualUntil marks ctx as the work of a person's "Scan the LAN now" whose hour ends at t: windowNow lets it run until then.
// A zero t marks nothing.
func withManualUntil(ctx context.Context, t time.Time) context.Context {
	if t.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, manualKey{}, t)
}

func manualUntil(ctx context.Context) time.Time { t, _ := ctx.Value(manualKey{}).(time.Time); return t }

// Manual is the newest run a person started that is queued or going now, nil when none.
func (s *Service) Manual(ctx context.Context) *ManualRun {
	r, err := s.manualLive(ctx)
	if err != nil || r == nil {
		return nil
	}
	return s.manualOf(ctx, *r)
}

// Persons is every run a person started that is queued or going now, oldest first (the order they run in): each one says what
// it waits for. A pass a person asked to go on now counts while it goes on within their hour.
func (s *Service) Persons(ctx context.Context) []ManualRun {
	ids, err := s.personRunIDs(ctx)
	if err != nil {
		return nil
	}
	var out []ManualRun
	for _, id := range ids {
		r, err := s.runs.Read(ctx, id)
		if err != nil || r.Status.Ended() {
			continue
		}
		out = append(out, *s.manualOf(ctx, r))
	}
	if sw, err := s.liveRun(ctx, RunSweep); err == nil && sw != nil && sw.Trigger != run.Manual && (sw.Status.Live() || sw.Status == run.Queued) &&
		s.clock().Before(s.sweepUntil(*sw)) {
		out = append(out, *s.manualOf(ctx, *sw))
	}
	return out
}

// personRunIDs are the runs of the nmap lane a person started (not steps of another module's run) that have not ended, oldest first.
func (s *Service) personRunIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM core_run WHERE module = ? AND lane = ? AND trigger = 'manual' AND parent_id IS NULL
		AND status IN ('queued', 'running', 'stopping') ORDER BY queued_at, rowid LIMIT ?`, ModuleID, laneNmap, MaxManualTargets*2)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read the runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// manualOf is run r as a person's run.
func (s *Service) manualOf(ctx context.Context, r run.Run) *ManualRun {
	m := &ManualRun{ID: r.ID, Runs: []string{r.ID}}
	if r.StartedAt != nil {
		m.StartedAt, _ = time.Parse(time.RFC3339Nano, *r.StartedAt)
	} else {
		m.StartedAt, _ = time.Parse(time.RFC3339Nano, r.QueuedAt)
	}
	switch {
	case r.Kind == RunSweep && r.Subject != nil:
		m.Ranges = strings.Split(r.Subject.Label, ", ")
		m.Until = m.StartedAt.Add(manualFor)
	case r.Subject != nil:
		m.Assets = []string{r.Subject.ID}
		if a, err := s.inv.Asset(ctx, r.Subject.ID); err == nil {
			m.IP = a.IP
		}
	}
	m.Progress = runView(r)
	return m
}

// manualLive is the newest run of the nmap lane a person started (not a step of another module's run) that has not ended.
func (s *Service) manualLive(ctx context.Context) (*run.Run, error) {
	var id string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM core_run WHERE module = ? AND lane = ? AND trigger = 'manual' AND parent_id IS NULL
		AND status IN ('queued', 'running', 'stopping') ORDER BY queued_at DESC, rowid DESC LIMIT 1`, ModuleID, laneNmap).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) { // a pass a person asked to go on now is theirs while it goes on within their hour
		sw, err := s.liveRun(ctx, RunSweep)
		if err != nil || sw == nil || !sw.Status.Live() && sw.Status != run.Queued || !s.clock().Before(s.sweepUntil(*sw)) {
			return nil, err
		}
		return sw, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read the runs: %w", err)
	}
	r, err := s.runs.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// StartManual checks a person's run and queues it (INV-21): no targets sweeps the whole scope now, with the window counted open for
// manualFor, and then checks the devices the sweep found ("Scan the LAN now"); targets (IPv4 addresses of devices or device ids, at
// most MaxManualTargets) queue one check per device, run at once whatever the window ("Check this device now"). Every rule but the
// window holds and is checked before anything is queued: the module on (ErrStopped once Stop ran), active scanning on
// (ErrScanningOff), the scope confirmed (ErrScopeNotConfirmed, ErrNoRanges), nmap present (ErrUnavailable), no sweep going now for a
// sweep (ErrSlotBusy), no sweep started in the last SweepGap (a *TooSoonError), and per target the device exists, is inside the scope
// and outside the exclusions and the box, and its policy lets a person check it (a *TargetError). Whatever else holds the scanner, a
// person's run is queued behind it and says so (INV-28): another person's run, the window's checks, the weekly scan of every port
// (which gives the lane up at once); a sweep gives way to it between two batches. A device that already has a person's check queued
// or going keeps that one (its run is answered, nothing new is queued or recorded). record writes the person's consent (the audit
// row) in the transaction that queues the runs: its error refuses the run and nothing is queued. by is the person.
func (s *Service) StartManual(ctx context.Context, by string, targets []string, record func(tx *sql.Tx, m ManualRun) error) (ManualRun, error) {
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
	now := s.clock()
	m := ManualRun{Assets: ids, IP: ip, Ranges: slices.Clone(st.LANRanges), StartedAt: now, Until: now.Add(manualFor)}
	if len(ids) == 0 {
		if err := s.sweepGap(ctx); err != nil {
			return ManualRun{}, err
		}
		sw, err := s.liveRun(ctx, RunSweep)
		if err != nil {
			return ManualRun{}, err
		}
		if sw != nil && sw.Status != run.Waiting {
			return ManualRun{}, ErrSlotBusy
		}
		if sw != nil { // the pass that waits for the window goes on now from its cursor, under the person's hour: never a second pass
			err := s.db.Write(ctx, func(tx *sql.Tx) error {
				m.ID, m.Runs = sw.ID, []string{sw.ID}
				if record == nil {
					return nil
				}
				return record(tx, m)
			})
			if err != nil {
				return ManualRun{}, err
			}
			s.mu.Lock()
			if s.personUntil == nil {
				s.personUntil = map[string]time.Time{}
			}
			s.personUntil[sw.ID] = m.Until
			s.mu.Unlock()
			s.expect(sw.ID)
			if err := s.runs.Resume(ctx, sw.ID, by); err != nil {
				return ManualRun{}, err
			}
			s.stopWeekly()
			m.Progress = s.viewOfRun(ctx, sw.ID)
			return m, nil
		}
		id, err := s.newSweep(ctx, st, run.Spec{Trigger: run.Manual, RequestedBy: by}, func(tx *sql.Tx, id string) error {
			m.ID, m.Runs = id, []string{id}
			if record == nil {
				return nil
			}
			return record(tx, m)
		})
		if err != nil {
			return ManualRun{}, err
		}
		m.ID, m.Runs = id, []string{id}
		s.stopWeekly() // the weekly scan of every port gives the lane up to the person's pass
		m.Progress = s.viewOfRun(ctx, id)
		return m, nil
	}
	m.Until = time.Time{}
	// A device that already has a person's check queued or going keeps that one: asking again shows it, never a second check.
	have, err := s.personChecks(ctx)
	if err != nil {
		return ManualRun{}, err
	}
	labels := make([]string, len(ids))
	for i, id := range ids {
		labels[i] = s.deviceLabel(ctx, id)
	}
	var created []string
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		m.Runs, created = m.Runs[:0], created[:0]
		for i, id := range ids {
			if rid := have[id]; rid != "" {
				m.Runs = append(m.Runs, rid)
				continue
			}
			lbl := labels[i]
			rid, err := s.runs.CreateTx(ctx, tx, run.Spec{Module: ModuleID, Kind: RunCheck, Title: "Check of " + lbl, Trigger: run.Manual,
				RequestedBy: by, Subject: &run.Subject{Kind: "device", ID: id, Label: lbl}, Steps: []run.StepPlan{{Name: lbl, Total: 1}}})
			if err != nil {
				return err
			}
			m.Runs, created = append(m.Runs, rid), append(created, id)
		}
		m.ID = m.Runs[0]
		if record == nil || len(created) == 0 { // nothing new was queued: nothing new is consented to
			return nil
		}
		return record(tx, m)
	})
	if err != nil {
		return ManualRun{}, err
	}
	if len(created) > 0 {
		s.stopWeekly() // the weekly scan of every port gives the lane up to the person's checks
	}
	for _, id := range created { // the window's own row of the device: checked now, it waits for nothing
		s.dropWaiting(ctx, id, "Checked now at a person's request")
	}
	m.Progress = s.viewOfRun(ctx, m.ID)
	return m, nil
}

// personChecks is, by device, the person's check of it that is queued or going now.
func (s *Service) personChecks(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT subject_id, id FROM core_run WHERE module = ? AND kind = ? AND trigger = 'manual'
		AND parent_id IS NULL AND subject_kind = 'device' AND status IN ('queued', 'running', 'stopping')`, ModuleID, RunCheck)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: read the runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var dev, id string
		if err := rows.Scan(&dev, &id); err != nil {
			return nil, err
		}
		out[dev] = id
	}
	return out, rows.Err()
}

// runView is the progress of a run as the engine cards show it: its phase, its count and its line of words.
func runView(r run.Run) *progress.View {
	msg := r.Summary
	at := derefOr(r.StartedAt, r.QueuedAt)
	v := &progress.View{Phase: progress.PhaseDiscovery, StartedAt: at, PhaseStartedAt: at, UpdatedAt: r.UpdatedAt, Message: &msg}
	if r.Total > 0 {
		done, total, unit := int64(r.Done), int64(r.Total), progress.UnitHosts
		v.Done, v.Total, v.Unit = &done, &total, &unit
	}
	return v
}

// viewOfRun is runView of run id as stored now; a bare view when it cannot be read.
func (s *Service) viewOfRun(ctx context.Context, id string) *progress.View {
	r, err := s.runs.Read(ctx, id)
	if err != nil {
		now := s.now()
		return &progress.View{Phase: progress.PhaseDiscovery, StartedAt: now, PhaseStartedAt: now, UpdatedAt: now}
	}
	return runView(r)
}

// SweepGap is the least time between two sweeps a person starts, or a person's and the window's (INV-21, review #857 L4): the window
// stays the rule, a sweep on demand the exception.
const SweepGap = 10 * time.Minute

// TooSoonError refuses a sweep that would start within SweepGap of the last one; RetryAfter is how long until it may.
type TooSoonError struct{ RetryAfter time.Duration }

func (e *TooSoonError) Error() string {
	return "sensoractive: a sweep ran less than " + SweepGap.String() + " ago"
}

// sweepGap refuses a sweep within SweepGap of the newest sweep's start (one queued that never started does not count: a live one is
// refused as going on, ErrSlotBusy).
func (s *Service) sweepGap(ctx context.Context) error {
	var last sql.NullString
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT max(started_at) FROM core_run WHERE module = ? AND kind = ? AND started_at IS NOT NULL`, ModuleID, RunSweep).Scan(&last); err != nil {
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

// ---- the engine cards of Settings › Scanning (#850) ----

// JobHead is a run of the module as Settings › Scanning and the history list it (core_run).
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
	JobID     string // its run
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
	SNMP       *JobHead // the SNMP read running now, nil when none
	Manual     *ManualRun
	Persons    []ManualRun // every run a person started that is queued or going, oldest first (Persons)
}

// Engine reads EngineView.
func (s *Service) Engine(ctx context.Context) (EngineView, error) {
	v := EngineView{Health: s.Health(ctx), Last: map[string]JobHead{}, Manual: s.Manual(ctx), Persons: s.Persons(ctx)}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return EngineView{}, err
	}
	now := s.local()
	_, _, v.Open = st.window(now)
	v.NextWindow = st.nextOpening(now)
	for _, k := range []string{RunSweep, RunCheck, RunSNMP} {
		rows, err := s.jobHeads(ctx, `WHERE r.module = ? AND r.kind = ? AND r.status IN ('done', 'partial', 'failed', 'stopped') ORDER BY r.queued_at DESC, r.rowid DESC LIMIT 1`, ModuleID, k)
		if err != nil {
			return EngineView{}, err
		}
		if len(rows) == 1 {
			v.Last[rows[0].Kind] = rows[0].JobHead
		}
	}
	s.mu.Lock()
	if c := s.cur; c != nil && !c.external {
		kind := KindDevice
		if c.asset == "" && !c.picked {
			kind = KindSweep
		}
		v.Current = &Current{JobID: c.runID, Kind: kind, Asset: c.asset, Targets: slices.Clone(c.targets), Manual: v.Manual != nil, StartedAt: c.started}
	}
	s.mu.Unlock()
	if r, err := s.liveRun(ctx, RunSNMP); err != nil {
		return EngineView{}, err
	} else if r != nil && r.Status == run.Running {
		v.SNMP = &JobHead{ID: r.ID, Kind: KindSNMP, Status: StatusRunning, StartedAt: derefOr(r.StartedAt, r.QueuedAt), Targets: r.Total}
	}
	return v, nil
}

func derefOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// JobRow is a run of the module for a list of past runs, with every probe it sent (read only): a sweep runs in batches, an SNMP
// read records "ok: n of m answered", so what the run found is in its probes, never only in the row's target count.
type JobRow struct {
	JobHead
	Probes []JobProbe // in the order they were sent; empty when it sent none
	// Found is what a device check found (its items): nil for the other kinds, a check that found nothing it could record (the
	// device did not answer, nmap failed or was stopped) and the checks stored before it was kept.
	Found *DeviceFound
	// AssetID is the device a device check was for (the run's subject); "" for the other kinds.
	AssetID string
	// Own is, in JobsOf only, how the device's own read went in this SNMP read (sa_snmp_device.last_status of the read that
	// stored it: ok, no_answer, auth_failed, unknown_user, error); "" when it is not known (an older read of the device).
	Own string
}

// JobProbe is one probe of a job: its targets (an address, or the ranges of a sweep batch) and its result as recorded ("ok: 3 hosts
// up", "ok: 2 of 3 answered", "failed: …"; "" while it runs).
type JobProbe struct{ Targets, Result string }

// Jobs lists the newest runs of the LAN (sweeps, device checks, SNMP reads, scans of every port), newest first, at most limit
// (1..500), each with its probes. Read only: the history of Settings › Scanning.
func (s *Service) Jobs(ctx context.Context, limit int) ([]JobRow, error) {
	limit = clamp(limit, 1, 500)
	out, err := s.jobHeads(ctx, `WHERE r.module = ? AND r.kind IN (?, ?, ?, ?) ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ?`,
		ModuleID, RunSweep, RunCheck, RunSNMP, RunAllPorts, limit)
	if err != nil {
		return nil, err
	}
	return out, s.jobProbes(ctx, out)
}

// snmpReadsScanned is how many of the newest SNMP reads JobsOf looks through: a read keeps its addresses as a compact list with
// ranges, which SQL cannot match, so they are matched here. An older read of the address is not found (the contract says so).
const snmpReadsScanned = 1000

// JobsOf lists the LAN runs of device id (the device page's Last checks), newest first, at most limit (1..500) of each kind: its
// checks (the window's, a person's, Scan now's identification, the weekly scan of every port: the runs whose subject it is), and the
// SNMP reads that asked the read address of its SNMP settings, among the newest snmpReadsScanned reads. A device without SNMP set up
// has no SNMP read. No sweep: it reaches every address of the scope and identifies nothing. addr is kept for the callers; the runs
// name their device.
func (s *Service) JobsOf(ctx context.Context, id string, _ netip.Addr, limit int) ([]JobRow, error) {
	limit = clamp(limit, 1, 500)
	out, err := s.jobHeads(ctx, `WHERE r.module = ? AND r.kind IN (?, ?) AND r.subject_kind = 'device' AND r.subject_id = ?
ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ?`, ModuleID, RunCheck, RunAllPorts, id, limit)
	if err != nil {
		return nil, err
	}
	if err := s.jobProbes(ctx, out); err != nil {
		return nil, err
	}
	var from string
	var checked, status sql.NullString // the device's own last read: when, and how it went
	switch err := s.db.Reader().QueryRowContext(ctx, `SELECT read_from, last_checked_at, last_status FROM sa_snmp_device WHERE asset_id = ?`, id).Scan(&from, &checked, &status); {
	case errors.Is(err, sql.ErrNoRows):
		return out, nil
	case err != nil:
		return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
	}
	readAt, err := netip.ParseAddr(from)
	if err != nil {
		return out, nil //nolint:nilerr // a read address that is not one was never asked
	}
	reads, err := s.jobHeads(ctx, `WHERE r.module = ? AND r.kind = ? ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ?`, ModuleID, RunSNMP, snmpReadsScanned)
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
		if slices.ContainsFunc(r.Probes, func(p JobProbe) bool { return targetsHave(p.Targets, readAt) }) {
			// the device's own result is kept for its last read only: the read during which it was stored
			if checked.Valid && status.Valid && r.StartedAt <= checked.String && (r.FinishedAt == nil || checked.String <= *r.FinishedAt) {
				r.Own = status.String
			}
			out = append(out, r)
			n++
		}
	}
	slices.SortStableFunc(out, func(a, b JobRow) int { return strings.Compare(b.StartedAt, a.StartedAt) })
	return out, nil
}

// targetsHave tells whether a probe's compact target list ("192.168.142.1-192.168.142.4,192.168.142.9", compactTargets) names addr.
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

// jobKinds maps a kind of run to the kind of the history (KindSweep, KindDevice, KindSNMP).
var jobKinds = map[string]string{RunSweep: KindSweep, RunCheck: KindDevice, RunAllPorts: KindDevice, RunSNMP: KindSNMP}

// jobStatus maps a run's state to the history's: a run that has not ended is running, one that ended partly failed (a batch or a
// device did not answer).
func jobStatus(st run.Status) string {
	switch st {
	case run.Done:
		return StatusDone
	case run.Stopped:
		return StatusStopped
	case run.Failed, run.Partial:
		return StatusFailed
	}
	return StatusRunning
}

// jobHeads reads runs of the module as history rows: where is the rest of the statement after FROM core_run r (WHERE, ORDER BY and
// LIMIT). A device check's Found is read back from its items.
func (s *Service) jobHeads(ctx context.Context, where string, args ...any) ([]JobRow, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT r.id, r.kind, r.status, r.trigger, COALESCE(r.trigger_note, ''), COALESCE(r.started_at, r.queued_at),
		r.ended_at, r.total, r.done, COALESCE(r.error, r.stop_reason, r.waiting_for, ''), COALESCE(r.subject_id, ''), COALESCE(r.subject_kind, ''),
		(SELECT count(*) FROM core_run_item i WHERE i.run_id = r.id AND i.outcome = 'new')
		FROM core_run r `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
	}
	var out []JobRow
	for rows.Next() {
		var r JobRow
		var kind, status, trigger, note, subID, subKind string
		var total, done int
		if err := rows.Scan(&r.ID, &kind, &status, &trigger, &note, &r.StartedAt, &r.FinishedAt, &total, &done, &r.Error, &subID, &subKind, &r.NewDevices); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
		}
		r.Kind, r.Status, r.Targets = jobKinds[kind], jobStatus(run.Status(status)), total
		if kind == RunSweep {
			r.Targets = done
		}
		switch {
		case kind == RunAllPorts:
			r.Reason = "all_ports"
		case kind == RunCheck && trigger == string(run.Manual):
			r.Reason = "scan_now"
		case kind == RunSNMP && trigger == string(run.Manual):
			r.Reason = snmpReasonTest
		}
		if subKind == "device" {
			r.AssetID = subID
		}
		if run.Status(status) == run.Done {
			r.Error = ""
		}
		out = append(out, r)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("sensoractive: list jobs: %w", err)
	}
	for i := range out {
		if out[i].Kind == KindDevice {
			if f, ok, err := s.loadFound(ctx, out[i].ID); err != nil {
				return nil, err
			} else if ok {
				out[i].Found = &f
			}
		}
	}
	return out, nil
}

// jobProbes fills the probes of these runs, in the order they were sent, in one read (sa_probe (run_id)).
func (s *Service) jobProbes(ctx context.Context, out []JobRow) error {
	if len(out) == 0 {
		return nil
	}
	at := make(map[string]int, len(out))
	for i, r := range out {
		at[r.ID] = i
	}
	for start := 0; start < len(out); start += 400 {
		chunk := out[start:min(start+400, len(out))]
		marks := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, len(chunk))
		for i, r := range chunk {
			args[i] = r.ID
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT run_id, targets, result FROM sa_probe WHERE run_id IN (`+marks+`) ORDER BY id`, args...)
		if err != nil {
			return fmt.Errorf("sensoractive: list job probes: %w", err)
		}
		for rows.Next() {
			var id string
			var p JobProbe
			if err := rows.Scan(&id, &p.Targets, &p.Result); err != nil {
				_ = rows.Close()
				return fmt.Errorf("sensoractive: list job probes: %w", err)
			}
			if i, ok := at[id]; ok {
				out[i].Probes = append(out[i].Probes, p)
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("sensoractive: list job probes: %w", err)
		}
	}
	return nil
}

// WaitManual returns once no run a person started is queued or going, or with ctx's error (tests, and a shutdown that must not
// leave nmap running).
func (s *Service) WaitManual(ctx context.Context) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := s.manualLive(ctx)
		if err != nil || r == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
