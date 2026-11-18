package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// againStates are the OpenVAS states of a scan whose OpenVAS step may run again on its own: it started and did not finish (a stop,
// a restart of the box, a failure, OpenVAS ending the task). A step cut by a restart still reads "running" until the next start. A
// step with rows (OpenVAS ended it after it had found some) is not one: its findings stay until a new deep scan replaces them, so a
// run again that is stopped or refused never loses them (againable).
var againStates = []string{GBRunStopped, GBRunFailed, GBRunEnded, GBRunRunning}

// AgainWithin is how old a scan may be for its OpenVAS step to run again on its own: OpenVAS checks the ports that scan found open,
// and its findings are named by that scan's start, so an older scan needs a new deep scan instead.
const AgainWithin = 24 * time.Hour

// againable says whether the OpenVAS step of snap may run again on its own now (the state, its rows, its age), and why not.
func (s *Service) againable(snap Snapshot) error {
	if !slices.Contains(againStates, snap.GreenboneRun.State) || len(snap.Greenbone) > 0 {
		return ErrNothingAgain
	}
	start, err := parseTS(snap.StartedAt)
	if err != nil || s.clock().Sub(start) > AgainWithin {
		return apiErr(409, "nothing_to_rerun", "This scan started on %s, more than 24 hours ago, so OpenVAS does not run again on the ports it found then. Run a deep scan to check the ports open now.", s.momentText(start))
	}
	return nil
}

// The answers of POST …/openvas that a scan does not have.
var (
	// ErrAgainDomain: a domain's OpenVAS step scans the addresses its deep scan reached in that run, which only a deep scan finds again.
	ErrAgainDomain = apiErr(400, "bad_value", "OpenVAS runs again on its own only on a public IP of this box. For a domain, run its deep scan again.")
	// ErrNothingAgain: the newest scan's OpenVAS step finished, did not start, or there is no scan.
	ErrNothingAgain = apiErr(409, "nothing_to_rerun", "The newest scan of this target has no OpenVAS step that was stopped or did not finish, so there is nothing to run again. Run a deep scan instead.")
)

// StartOpenVAS is POST /exposure/targets/{id}/openvas (INV-25, INV-1): OpenVAS again, on its own, for the newest scan of a public IP of
// the box whose OpenVAS step started and did not finish. It checks the open TCP ports that scan found, and its outcome replaces that
// step in the same snapshot (the other results are kept as they are). The same gate as Scan now runs first (ownership, the IP still
// the box's, the commitment: an existing one only, the shared safety block), then the box's one scan slot (409 busy) and the 10 minutes
// between two scans of a target (429); OpenVAS must be ready (503 scanner_unavailable). It answers at once with the run (202), whose
// phase is greenbone from the start. Every attempt is audited as exposure.scan.
func (s *Service) StartOpenVAS(ctx context.Context, who Actor, id string) (ScanRun, error) {
	t, reason, err := s.gate(ctx, who.Email, id)
	if err != nil {
		return ScanRun{}, fmt.Errorf("exposure: running OpenVAS again: %w", err)
	}
	snap, ports, err := s.againPlan(ctx, t, reason)
	if err == nil {
		var run *scanRun
		if run, err = s.begin(ctx, who.Email, t, "", &again{snap: snap, ports: ports}); err == nil {
			return s.runView(run), nil
		}
	}
	s.auditScanRow(ctx, who.Email, t.Value, "OpenVAS again: "+strings.TrimPrefix(failedDetail(err), "failed: "))
	return ScanRun{}, fmt.Errorf("exposure: running OpenVAS again on %s: %w", t.Value, err)
}

// again is what a run of OpenVAS again scans: the snapshot whose step it replaces and the open TCP ports that scan found.
type again struct {
	snap  Snapshot
	ports []int
}

// againPlan checks, before the run is registered, that OpenVAS may run again on t now and returns the snapshot and the ports.
func (s *Service) againPlan(ctx context.Context, t Target, reason BlockedReason) (Snapshot, []int, error) {
	if reason != "" {
		return Snapshot{}, nil, s.refusal(t, reason, s.clock())
	}
	if err := s.checkSafety(ctx, t); err != nil {
		return Snapshot{}, nil, err
	}
	if t.Kind != KindIP {
		return Snapshot{}, nil, ErrAgainDomain
	}
	ip, err := netip.ParseAddr(t.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return Snapshot{}, nil, fmt.Errorf("exposure: reading the address %q: %w", t.Value, err)
	}
	if s.busy() { // OpenVAS (or a scan) runs now: busy, not "nothing to run again"
		return Snapshot{}, nil, ErrScanBusy
	}
	db := s.cfg.DB.Reader()
	metas, err := listSnapshotMetas(ctx, db, t.ID)
	if err != nil {
		return Snapshot{}, nil, err
	}
	if len(metas) == 0 {
		return Snapshot{}, nil, ErrNothingAgain
	}
	snap, ok, err := loadSnapshot(ctx, db, t.ID, metas[0].Date)
	if err != nil {
		return Snapshot{}, nil, err
	}
	if !ok {
		return Snapshot{}, nil, ErrNothingAgain
	}
	if snap.ID == s.gbLive() {
		return Snapshot{}, nil, ErrScanBusy
	}
	if err := s.againable(snap); err != nil {
		return Snapshot{}, nil, err
	}
	ports := gbPorts(snap.Ports, ip)
	if line := gbPortsLine(ports); line != "" { // never reached for a step that started: it had ports to check
		return Snapshot{}, nil, apiErr(409, "nothing_to_rerun", "%s", strings.Replace(line, "OpenVAS did not scan: ", "OpenVAS cannot run again: ", 1))
	}
	if err := s.againReady(ctx, t); err != nil {
		return Snapshot{}, nil, err
	}
	return snap, ports, nil
}

// busy says whether a run (a scan, or OpenVAS again) holds the box's one scan slot now.
func (s *Service) busy() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.run != nil && s.run.view.Status == RunRunning
}

// againReady is greenbonePlan as an answer: nil when OpenVAS may scan t now, else 503 scanner_unavailable with its reason.
func (s *Service) againReady(ctx context.Context, t Target) error {
	ok, line, err := s.greenbonePlan(ctx, ScanTarget{ID: t.ID, Kind: t.Kind, Value: t.Value, Mode: t.mode(), Typed: t.Typed})
	if err != nil || ok {
		return err
	}
	if why, ok := strings.CutPrefix(line, "OpenVAS did not scan: "); ok {
		return apiErr(503, "scanner_unavailable", "OpenVAS cannot run now: %s", why)
	}
	return apiErr(503, "scanner_unavailable", "OpenVAS cannot run now. %s", line)
}

// executeAgain is the background half of a run of OpenVAS again: the step is reset to "running" in its snapshot, then it runs as the
// last step of a scan does (openVASPart), and the run ends with one final state (finish).
func (s *Service) executeAgain(ctx context.Context, run *scanRun, user string, t Target, a again) {
	defer run.cancel(nil)
	defer func() {
		if p := recover(); p != nil {
			s.cfg.Log.ErrorContext(ctx, "running OpenVAS again panicked", "target", t.Value, "panic", p, "stack", string(debug.Stack()))
			s.finish(ctx, run, user, t, fmt.Errorf("%w: %v", errScanPanicked, p))
		}
	}()
	st := ScanTarget{ID: t.ID, Kind: t.Kind, Value: t.Value, User: user, Mode: run.mode, Typed: t.Typed}
	err := s.againReady(ctx, t) // the terms may have changed between the answer and now
	if err == nil {
		err = s.resetOpenVAS(ctx, run, user, t, a)
	}
	if err == nil {
		err = s.openVASPart(ctx, run, user, t, func() (gbOutcome, error) { return s.greenboneStep(ctx, st, a.ports) })
	}
	if err != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		err = context.Cause(ctx)
	}
	s.finish(ctx, run, user, t, err)
}

// resetOpenVAS stores the snapshot's OpenVAS step as running again: its earlier lines, check and rows are removed, its start is now,
// and the scan has no end until the step ends. From here run.snap is the snapshot, so a stop keeps it. The exposure.scan row says what
// is sent.
func (s *Service) resetOpenVAS(ctx context.Context, run *scanRun, user string, t Target, a again) error {
	snap := a.snap
	now := store.FormatTS(s.clock())
	snap.GreenboneRun = GreenboneRun{State: GBRunRunning, StartedAt: &now, Again: true}
	snap.FinishedAt = nil
	c := snap.Content
	c.NotChecked = slices.DeleteFunc(slices.Clone(c.NotChecked), func(n NotCheckedRow) bool { return n.Kind == "greenbone" })
	c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "greenbone", Text: gbPending})
	c.Checks = slices.DeleteFunc(slices.Clone(c.Checks), func(k CheckRow) bool { return k.Kind == "greenbone" })
	c.Greenbone = []GreenboneRow{}
	snap.Content = c
	gbRun, err := snapshotRunDoc(snap.GreenboneRun)
	if err != nil {
		return err
	}
	s.runMu.Lock() // its "running" is live from the moment it is stored, never read as cut off
	run.gbSnap = snap.ID
	s.runMu.Unlock()
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		if _, err := loadTarget(ctx, tx, t.ID); err != nil { // deleted meanwhile
			return err
		}
		d, err := snapshotDocs(c, snap.Counts)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE exp_snapshot SET checks = ?, not_checked = ?, greenbone = ?, greenbone_run = ?, finished_at = NULL WHERE id = ? AND target_id = ?`,
			d[6], d[7], d[9], gbRun, snap.ID, t.ID)
		if err != nil {
			return fmt.Errorf("storing OpenVAS as running again: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 { // replaced by a scan meanwhile
			return ErrNothingAgain
		}
		return s.audit(ctx, tx, user, "exposure.scan", t.Value, fmt.Sprintf("OpenVAS again, on %s the scan of %s found open", gbPortsText(a.ports), snap.Date))
	})
	if err != nil {
		return err
	}
	run.snap = snap
	return nil
}

// snapshotRunDoc is the stored JSON of an OpenVAS state.
func snapshotRunDoc(r GreenboneRun) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encoding OpenVAS's state: %w", err)
	}
	return string(b), nil
}

// failedDetail is the audit detail of an attempt that err refused or ended (auditFailedScan's words).
func failedDetail(err error) string {
	var ae *APIError
	var sb *stoppedBy
	switch {
	case errors.As(err, &sb):
		return "stopped by " + sb.by
	case errors.As(err, &ae):
		return "not done: " + ae.Code + ": " + clipText(ae.Message, 300)
	case err == nil:
		return "not done"
	}
	return "failed: the scan stopped (" + clipText(err.Error(), 200) + ")"
}
