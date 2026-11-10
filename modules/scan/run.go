package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
)

// Limits of a run.
const (
	MaxRunTargets = 200              // INV-3
	keepRuns      = 100              // GET /scans/runs lists the newest runs (the mock keeps 100)
	deviceTimeout = 15 * time.Minute // one device's job; nuclei's own per-request timeout is 10 s
	// stopGrace is how long a stopped run waits for the engine to confirm before it is shown stopped anyway: Stop
	// now takes effect within 5 seconds (INV-6). The engine's lease still kills nuclei (D-113 (4)).
	stopGrace = 4 * time.Second
	// finishTimeout bounds the writes that must happen after the run's context is gone.
	finishTimeout = 30 * time.Second
)

// Event names published by this module (CONTRACT, Events).
const (
	EventRunStarted       = "scan.run.started"
	EventRunFinished      = "scan.run.finished"
	EventRunStopped       = "scan.run.stopped"
	EventFindingConfirmed = "scan.finding.confirmed"
)

// RunEvent is the payload of scan.run.*.
type RunEvent struct {
	RunID   string `json:"run_id"`
	Status  string `json:"status"`
	Matched int    `json:"matched"`
}

// FindingConfirmedEvent is the payload of scan.finding.confirmed. findings is told directly (ConfirmFromScan); the
// event is for everyone else.
type FindingConfirmedEvent struct {
	AssetID  string `json:"asset_id"`
	CVE      string `json:"cve"`
	Template string `json:"template"`
	Evidence string `json:"evidence"` // the summary
}

// Notes of result rows and stop reasons: the mock's words.
const (
	noteSkipped    = "Not scanned because the scan was stopped. This device was not touched."
	noteNoResp     = "No response; scanning stopped so the device is not hung."
	noteNoRespGoOn = "The device did not respond within the timeout; skipped."
	noteStoppedMid = "Stopped while this device was being scanned: no result. The requests on their way are in the probe log as stopped."
	noteNoApply    = "No scan template applies to the software on this device."
	noteEngine     = "The scanner could not finish this device, so nothing was concluded. Try again later."
	stopNow        = "You pressed Stop now."
	stopShutdown   = "Vedette was shut down during this scan."
	stopRestart    = "Vedette restarted during this scan, so it was stopped."
)

// RunRow is contract.ts RunResultRow.
type RunRow struct {
	TargetID  string  `json:"target_id"`
	Label     string  `json:"label"`
	IP        string  `json:"ip"`
	Template  *string `json:"template"`
	Result    string  `json:"result"` // matched | not_matched | not_applicable | no_template | no_response | skipped
	FindingID *string `json:"finding_id"`
	Note      string  `json:"note"`
}

// Current is the device a running scan is on.
type Current struct {
	Label string `json:"label"`
	IP    string `json:"ip"`
}

// RunView is contract.ts ScanRun.
type RunView struct {
	ID          string   `json:"id"`
	Trigger     string   `json:"trigger"`
	TriggerNote *string  `json:"trigger_note"`
	StartedAt   string   `json:"started_at"`
	StartedBy   string   `json:"started_by"`
	EndedAt     *string  `json:"ended_at"`
	Status      string   `json:"status"`
	Total       int      `json:"total"`
	Done        int      `json:"done"`
	Current     *Current `json:"current"`
	Results     []RunRow `json:"results"`
	Matched     int      `json:"matched"`
	StopReason  *string  `json:"stop_reason"`
}

// live is the run this process is executing.
type live struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	errCommitment = apiErr(400, "commitment_required", "Vedette does not scan until the scope commitment is ticked. Do it under Devices, Scope and sensors.")
	errNoTargets  = apiErr(400, "no_targets", "Choose at least one device to scan.")
	errTooMany    = apiErr(400, "too_many", "A scan can include at most 200 devices.")
	errRunning    = apiErr(409, "already_running", "A scan is already running. Wait for it to finish or press Stop now.")
	errNotRunning = apiErr(409, "not_running", "This scan has already ended, so there is nothing to stop.")
	errNoRun      = apiErr(404, "not_found", "No such item.")
)

// ready is INV-2's scanner half: an Engine that answers Ready, and a template pack to choose from.
func (s *Service) scannerReady(ctx context.Context) bool { return s.cfg.Pack != nil && s.ready(ctx) }

// StartRun starts a scan of the targets a person picked in Scan now (PRE-1, POST-1): the commitment, 1..200 known
// targets that can be picked (INV-1..INV-3), the scanner ready. The pick is the consent of D-126 for each device;
// it is audited with the person and the ids.
func (s *Service) StartRun(ctx context.Context, user string, ids []string) (RunView, error) {
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return RunView{}, fmt.Errorf("scan: reading the scope: %w", err)
	}
	if sc.ConfirmedAt == "" {
		return RunView{}, errCommitment
	}
	if len(ids) == 0 {
		return RunView{}, errNoTargets
	}
	if len(ids) > MaxRunTargets {
		return RunView{}, errTooMany
	}
	if err := s.reapOrphan(ctx); err != nil {
		return RunView{}, err
	}
	if s.liveRun() != "" {
		return RunView{}, errRunning
	}
	all, err := s.Targets(ctx)
	if err != nil {
		return RunView{}, err
	}
	var chosen, picked []string
	var first Current
	for _, id := range ids {
		if slices.Contains(chosen, id) {
			continue
		}
		i := slices.IndexFunc(all, func(t TargetView) bool { return t.ID == id })
		if i < 0 {
			return RunView{}, unknownTarget(id)
		}
		if !all[i].Selectable {
			return RunView{}, refusal(all[i])
		}
		if len(chosen) == 0 {
			first = Current{Label: all[i].Label, IP: all[i].IP}
		}
		chosen = append(chosen, id)
		if all[i].PickOnly { // M1: the pick is the consent of this device only, as it stood now
			picked = append(picked, id)
		}
	}
	if !s.scannerReady(ctx) {
		return RunView{}, ErrScannerUnavailable
	}
	return s.start(ctx, runSpec{trigger: "manual", user: user, ids: chosen, picked: picked, first: first})
}

// runSpec is what a run is started with.
type runSpec struct {
	trigger  string // manual | schedule | new_kev
	note     *string
	user     string
	ids      []string
	picked   []string  // the ids picked by a person that needed the pick (D-126 (2)); empty for schedules and KEV rescans
	first    Current   // the device the run begins with: shown as current from the start (POST-1)
	onlyCVEs []string  // nil: every CVE of the devices' findings; else only these (the KEV rescan, INV-9; a backlog in one run, S4b)
	end      time.Time // zero: none; else the run stops by itself then (the end of the window of a scheduled run)
	// inTx, when set, runs in the transaction that writes the run row: what the run is for (the schedule slot, the
	// KEV event) is recorded with it or not at all (#164 review L4).
	inTx func(ctx context.Context, tx *sql.Tx, runID string) error
}

// start writes the run row and its audit row, then runs it in the background.
func (s *Service) start(ctx context.Context, sp runSpec) (RunView, error) {
	id := store.NewID("run")
	base := context.WithoutCancel(ctx)
	rctx, cancel := context.WithCancel(base)
	if !sp.end.IsZero() { // by the injected clock, so a test can put the end close
		cancel()
		rctx, cancel = context.WithTimeout(base, sp.end.Sub(s.now()))
	}
	l := &live{id: id, cancel: cancel, done: make(chan struct{})}
	// The slot is taken before the row is written, so reapOrphan never mistakes this run for one a restart left behind.
	s.mu.Lock()
	if s.live != nil || s.engineBusy() {
		s.mu.Unlock()
		cancel()
		return RunView{}, errRunning
	}
	s.live = l
	s.mu.Unlock()
	free := func() { s.mu.Lock(); s.live = nil; s.mu.Unlock(); cancel() }
	now := store.FormatTS(s.now())
	tids, err := json.Marshal(sp.ids)
	if err != nil {
		free()
		return RunView{}, fmt.Errorf("scan: encoding the targets: %w", err)
	}
	pk, err := json.Marshal(append([]string{}, sp.picked...))
	if err != nil {
		free()
		return RunView{}, fmt.Errorf("scan: encoding the picks: %w", err)
	}
	cur, err := json.Marshal(sp.first)
	if err != nil {
		free()
		return RunView{}, fmt.Errorf("scan: encoding the current device: %w", err)
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_run (id, trigger, trigger_note, started_at, started_by, status, picked, target_ids, total, current)
VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)`, id, sp.trigger, sp.note, now, sp.user, string(pk), string(tids), len(sp.ids), string(cur)); err != nil {
			if store.IsUniqueViolation(err) {
				return errRunning
			}
			return fmt.Errorf("scan: writing the run: %w", err)
		}
		// Review L2: the start counts and hashes the whole list; each pick, the consent of D-126 (2), is a row of its own.
		sum := sha256.Sum256([]byte(strings.Join(sp.ids, ",")))
		detail := fmt.Sprintf("%d targets, %d picked by hand, sha256 %s", len(sp.ids), len(sp.picked), hex.EncodeToString(sum[:8]))
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: sp.user, Action: "scan.start", Target: id, Detail: detail}); err != nil {
			return err
		}
		for _, p := range sp.picked {
			if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: sp.user, Action: "scan.pick", Target: p, Detail: "run " + id}); err != nil {
				return err
			}
		}
		if sp.inTx != nil {
			return sp.inTx(ctx, tx, id)
		}
		return nil
	})
	if err != nil {
		free()
		return RunView{}, err
	}
	s.publish(ctx, EventRunStarted, RunEvent{RunID: id, Status: "running"})
	go func() {
		defer close(l.done)
		defer cancel()
		s.execute(rctx, id, sp)
		s.mu.Lock()
		s.live = nil
		s.mu.Unlock()
	}()
	return s.Run(ctx, id)
}

// engineBusy says an Engine.Run call has not returned yet (review M2).
func (s *Service) engineBusy() bool { return s.busy.Load() > 0 }

func (s *Service) liveRun() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil {
		return ""
	}
	return s.live.id
}

// reapOrphan closes a run the database says is running while this process runs none: Vedette restarted during it.
// Its open probe rows become stopped (INV-7: the log keeps what was on its way).
func (s *Service) reapOrphan(ctx context.Context) error {
	if s.liveRun() != "" {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if s.liveRun() != "" { // again inside the writer: a start in between has taken the slot
			return nil
		}
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM scan_run WHERE status IN ('running', 'stopping')`).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return fmt.Errorf("scan: reading the live run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = 'stopped' WHERE run_id = ? AND result IS NULL`, id); err != nil {
			return fmt.Errorf("scan: closing the probe log: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE scan_run SET status = 'stopped', ended_at = ?, current = NULL, stop_reason = ? WHERE id = ?`, store.FormatTS(s.now()), stopRestart, id)
		return err
	})
}

// StopRun is Stop now (PRE-2, POST-2, INV-6): the run becomes stopping, no new request leaves, and it is stopped
// within 5 seconds. Stopping a run that is already stopping is not an error.
func (s *Service) StopRun(ctx context.Context, user, id string) (RunView, error) {
	v, err := s.Run(ctx, id)
	if err != nil {
		return RunView{}, err
	}
	if v.Status != "running" && v.Status != "stopping" {
		return RunView{}, errNotRunning
	}
	if v.Status == "running" {
		err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			r, err := tx.ExecContext(ctx, `UPDATE scan_run SET status = 'stopping', stop_requested_at = ? WHERE id = ? AND status = 'running'`, store.FormatTS(s.now()), id)
			if err != nil {
				return fmt.Errorf("scan: stopping the run: %w", err)
			}
			if n, _ := r.RowsAffected(); n == 0 {
				return nil
			}
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "scan.stop", Target: id, Detail: fmt.Sprintf("scanned %d/%d", v.Done, v.Total)})
		})
		if err != nil {
			return RunView{}, err
		}
	}
	s.mu.Lock()
	l := s.live
	s.mu.Unlock()
	if l != nil && l.id == id {
		l.cancel()
	} else if err := s.reapOrphan(ctx); err != nil {
		return RunView{}, err
	}
	return s.Run(ctx, id)
}

// ---- executing a run ----

// execute scans the targets one device at a time. Every device is checked again right before its job leaves core
// (INV-1); a person's Stop now or an unresponsive device (INV-6) ends the run, and the devices not reached are not
// touched.
// sp.picked are the ids whose pick is their consent (M1): each other device is checked as for an automatic run.
func (s *Service) execute(ctx context.Context, runID string, sp runSpec) {
	ids := sp.ids
	var rows []RunRow
	status, reason := "done", ""
	done, next := 0, len(ids) // devices finished; first device not touched
	for i, id := range ids {
		if ctx.Err() != nil {
			status, reason, next = "stopped", s.stopReason(ctx), i
			break
		}
		got, end := s.scanTarget(ctx, runID, id, i, sp)
		rows = append(rows, got...)
		if end == "stopped" {
			status, reason, next = "stopped", s.stopReason(ctx), i+1
			break
		}
		if end != "" {
			status, reason, next = "auto_stopped", end, i+1
			break
		}
		done++
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	devs, _ := s.devicesByID(fctx) // for the labels of the rows below; a failed read leaves dashes
	for _, id := range ids[next:] {
		d := devs[id]
		rows = append(rows, RunRow{TargetID: id, Label: orDash(d.Label), IP: orDash(d.IP), Result: "skipped", Note: noteSkipped})
	}
	s.finish(fctx, runID, status, reason, rows, done)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (s *Service) devicesByID(ctx context.Context) (map[string]Device, error) {
	all, err := s.cfg.Inventory.Devices(ctx)
	out := make(map[string]Device, len(all))
	for _, d := range all {
		out[d.ID] = d
	}
	return out, err
}

// scanTarget scans one device. end is "" to go on, "stopped" after Stop now, or the stop reason of an
// unresponsive device when stop_on_unresponsive is set.
func (s *Service) scanTarget(ctx context.Context, runID, id string, index int, sp runSpec) (rows []RunRow, end string) {
	explicit := slices.Contains(sp.picked, id) // M1: the pick is per device
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return s.failed(ctx, id, err), ""
	}
	devs, err := s.devicesByID(ctx)
	if err != nil {
		return s.failed(ctx, id, err), ""
	}
	d, ok := devs[id]
	if !ok {
		return []RunRow{{TargetID: id, Label: "—", IP: "—", Result: "skipped", Note: skipNote["gone"]}}, ""
	}
	if err := s.setCurrent(ctx, runID, index, d); err != nil {
		return s.failed(ctx, id, err), ""
	}
	sc, err := s.cfg.Inventory.Scope(ctx)
	if err != nil {
		return s.failed(ctx, id, err), ""
	}
	if sc.ConfirmedAt == "" {
		return []RunRow{s.skip(d, reasonNoScope)}, ""
	}
	why, careful, err := s.consent(ctx, st, d, explicit)
	if err != nil {
		return s.failed(ctx, id, err), ""
	}
	if why != "" {
		return []RunRow{s.skip(d, why)}, ""
	}
	rate := st.Rate
	if careful {
		rate = max(1, st.Rate/4) // D-126 (2): fragile and unclassified devices at a quarter of the speed
	}
	return s.scanDevice(ctx, runID, d, st, rate, sp.onlyCVEs)
}

func (s *Service) skip(d Device, why string) RunRow {
	note := skipNote[why]
	if note == "" {
		note = skipNote["out_of_scope"]
	}
	return RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: note}
}

func (s *Service) failed(ctx context.Context, id string, err error) []RunRow {
	s.cfg.Log.ErrorContext(ctx, "scan: a device could not be scanned", "asset", id, "error", err)
	return []RunRow{{TargetID: id, Label: "—", IP: "—", Result: "skipped", Note: noteEngine}}
}

func (s *Service) setCurrent(ctx context.Context, runID string, done int, d Device) error {
	cur, err := json.Marshal(Current{Label: d.Label, IP: d.IP})
	if err != nil {
		return fmt.Errorf("scan: encoding the current device: %w", err)
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE scan_run SET done = ?, current = ? WHERE id = ? AND status IN ('running', 'stopping')`, done, string(cur), runID)
		return err
	})
}

// check is one CVE of a device and the templates that confirm it.
type check struct {
	finding FindingRef
	tpls    []pack.Template
}

// plan chooses what a device is checked for: each CVE of its findings that has a template in the pack (at most
// nucleiargv.MaxTemplates templates); a CVE without a template is a no_template row and sends nothing (INV-8).
func (s *Service) plan(ctx context.Context, d Device, onlyCVEs []string) (checks []check, rows []RunRow, err error) {
	if s.cfg.Findings == nil {
		return nil, nil, nil
	}
	fs, err := s.cfg.Findings.List(ctx, d.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("scan: reading the findings of %s: %w", d.ID, err)
	}
	n := 0
	seen := map[string]bool{}
	for _, f := range fs {
		if dismissed(f.Status) || (onlyCVEs != nil && !slices.Contains(onlyCVEs, f.CVE)) {
			continue
		}
		if seen[f.CVE] {
			continue
		}
		seen[f.CVE] = true
		tpls := s.cfg.Pack.ForCVE(f.CVE)
		if len(tpls) == 0 {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_template", FindingID: ptr(f.ID), Note: f.CVE + ": no safe scan template yet, still suspected by version."})
			continue
		}
		if n+len(tpls) > nucleiargv.MaxTemplates {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", FindingID: ptr(f.ID), Note: f.CVE + ": not checked in this scan (more than 32 templates for one device); scan the device again."})
			continue
		}
		n += len(tpls)
		checks = append(checks, check{finding: f, tpls: tpls})
	}
	return checks, rows, nil
}

// dismissed is a finding a person closed (false positive, not relevant, patched): its CVE is not probed again (review
// L3). Mitigated findings are rescanned: a match shows the mitigation did not hold; no match changes nothing (D-133 (5)).
func dismissed(status string) bool {
	return status == "false_positive" || status == "not_relevant" || status == "patched"
}

// endpoints are where nuclei sends requests on a device: its known web services first, then its other TCP ports
// (network templates), at most nucleiargv.MaxTargets; a device with no known port gets ports 80 and 443.
func endpoints(d Device) []nucleiargv.Target {
	var web, other []nucleiargv.Target
	for _, sv := range d.Services {
		name := strings.ToLower(sv.Name)
		switch {
		case strings.Contains(name, "https") || strings.HasPrefix(name, "ssl/http"):
			web = append(web, nucleiargv.Target{Host: d.IP, Port: sv.Port, Scheme: "https"})
		case strings.HasPrefix(name, "http") || name == "www":
			web = append(web, nucleiargv.Target{Host: d.IP, Port: sv.Port, Scheme: "http"})
		default:
			other = append(other, nucleiargv.Target{Host: d.IP, Port: sv.Port})
		}
	}
	all := append(web, other...)
	if len(all) == 0 {
		all = []nucleiargv.Target{{Host: d.IP, Port: 80, Scheme: "http"}, {Host: d.IP, Port: 443, Scheme: "https"}}
	}
	out := make([]nucleiargv.Target, 0, len(all))
	for _, t := range all {
		if len(out) < nucleiargv.MaxTargets && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// scanDevice sends one job for the device and turns what nuclei printed into result rows and finding updates.
func (s *Service) scanDevice(ctx context.Context, runID string, d Device, st Settings, rate int, onlyCVEs []string) ([]RunRow, string) {
	checks, rows, err := s.plan(ctx, d, onlyCVEs)
	if err != nil {
		return s.failed(ctx, d.ID, err), ""
	}
	if len(checks) == 0 {
		if len(rows) == 0 {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "not_applicable", Note: noteNoApply})
		}
		return rows, ""
	}
	job := nucleiargv.Job{Targets: endpoints(d), Rate: rate, MaxHostErrors: st.UnresponsiveAfter}
	var ids []string
	for _, c := range checks {
		for _, t := range c.tpls {
			job.Templates = append(job.Templates, t.Path) // the file of the verified index, never the whole directory (M2)
			ids = append(ids, t.ID)
		}
	}
	if _, err := nucleiargv.Build(job); err != nil { // the same check the worker makes: never hand over a job it would refuse
		return s.failed(ctx, d.ID, err), ""
	}
	probes, err := s.writeProbes(ctx, runID, d, checks)
	if err != nil {
		return s.failed(ctx, d.ID, err), ""
	}
	out, err := s.runJob(ctx, job)
	if ctx.Err() != nil { // Stop now while this device was being scanned
		s.closeProbes(ctx, probes, func(string) string { return "stopped" })
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "skipped", Note: noteStoppedMid}), "stopped"
	}
	var res []nucleiout.Result
	if err == nil && out.Truncated {
		err = errors.New("the output was over the cap")
	}
	if err == nil {
		res, err = nucleiout.Parse(out.JSONL, ids, hostPorts(job.Targets))
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		s.cfg.Log.ErrorContext(ctx, "scan: the scanner failed on a device", "asset", d.ID, "run", runID, "error", err)
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		for _, c := range checks {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Template: ptr(c.tpls[0].Path), Result: "no_response", FindingID: ptr(c.finding.ID), Note: noteEngine})
		}
		return rows, ""
	}
	if errors.Is(err, context.DeadlineExceeded) { // review L5: the device did not finish in time, which is not "did not respond"
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		mins := int(deviceTimeout.Minutes())
		if st.StopOnUnresponsive {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: fmt.Sprintf("The device did not finish within %d minutes; scanning stopped so the device is not hung.", mins)})
			return rows, fmt.Sprintf("%s (%s) did not finish within %d minutes. Vedette stopped so the device is not hung.", d.Label, d.IP, mins)
		}
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: fmt.Sprintf("The device did not finish within %d minutes; skipped.", mins)}), ""
	}
	if unresponsive(res) {
		s.closeProbes(ctx, probes, func(string) string { return "no_response" })
		if st.StopOnUnresponsive {
			rows = append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: noteNoResp})
			return rows, fmt.Sprintf("%s (%s) did not respond after %d attempts in a row. Vedette stopped so the device is not hung.", d.Label, d.IP, st.UnresponsiveAfter)
		}
		return append(rows, RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Result: "no_response", Note: noteNoRespGoOn}), ""
	}
	byTemplate := map[string]string{}
	for _, c := range checks {
		row := s.conclude(ctx, d, c, res, job.Targets)
		rows = append(rows, row)
		for _, t := range c.tpls {
			byTemplate[t.ID] = templateResult(t.ID, res)
		}
	}
	s.closeProbes(ctx, probes, func(tpl string) string { return byTemplate[tpl] })
	return rows, ""
}

// hostPorts are the job's targets as nucleiout matches them (L2).
func hostPorts(ts []nucleiargv.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Host + ":" + strconv.Itoa(t.Port)
	}
	return out
}

// recheckInput is the -u of the "check it yourself" line: the job's own target that matched, never a field of the
// output (L7).
func recheckInput(ts []nucleiargv.Target, hostPort string) string {
	for _, t := range ts {
		if t.Host+":"+strconv.Itoa(t.Port) == hostPort {
			return t.Input()
		}
	}
	return ts[0].Input() // unreachable: nucleiout returns only the job's targets
}

// runJob runs the job on the engine, bounded by the device timeout; after Stop now it waits at most stopGrace.
func (s *Service) runJob(ctx context.Context, job nucleiargv.Job) (Output, error) {
	jctx, cancel := context.WithTimeout(ctx, deviceTimeout)
	defer cancel()
	type result struct {
		out Output
		err error
	}
	ch := make(chan result, 1)
	s.busy.Add(1)
	go func() {
		defer s.busy.Add(-1)
		out, err := s.cfg.Engine.Run(jctx, job)
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-ctx.Done():
		select {
		case r := <-ch:
			return r.out, r.err
		case <-time.After(stopGrace):
			return Output{}, ctx.Err()
		}
	}
}

// unresponsive says the device answered nothing: it printed lines and every one is an error (INV-6). An empty output
// is not that: nuclei may write JSONL only for matches (D-133 (5)), so silence means "no match reported". nuclei itself
// stops sending after max_host_errors errors in a row (-mhe), so the device is not pushed further either way.
func unresponsive(res []nucleiout.Result) bool {
	return len(res) > 0 && !slices.ContainsFunc(res, func(r nucleiout.Result) bool { return r.Error == "" })
}

// templateResult is the probe-log result of one template: matched; no_response when it has lines and every one is an
// error; otherwise not_matched, which means only "no match reported" (D-133 (5)).
func templateResult(id string, res []nucleiout.Result) string {
	seen, answered := false, false
	for _, r := range res {
		if r.Template != id {
			continue
		}
		if r.Matched {
			return "matched"
		}
		seen, answered = true, answered || r.Error == ""
	}
	if seen && !answered {
		return "no_response"
	}
	return "not_matched"
}

// conclude turns the lines of one CVE into its result row and tells the findings module (INV-8, S-SCAN-3).
// One matched line is enough for a template on a device (L3): a template that needs an out-of-band answer is refused by
// the pack (oast), so a "not matched" never stands for a check nuclei could not make with -ni.
func (s *Service) conclude(ctx context.Context, d Device, c check, res []nucleiout.Result, targets []nucleiargv.Target) RunRow {
	cve := c.finding.CVE
	row := RunRow{TargetID: d.ID, Label: d.Label, IP: d.IP, Template: ptr(c.tpls[0].Path), FindingID: ptr(c.finding.ID)}
	var hit *nucleiout.Result
	seen, answered := false, false
	for i, r := range res {
		if !slices.ContainsFunc(c.tpls, func(t pack.Template) bool { return t.ID == r.Template }) {
			continue
		}
		if r.Matched {
			hit = &res[i]
			break
		}
		seen, answered = true, answered || r.Error == ""
	}
	switch {
	case hit != nil:
		tpl := c.tpls[slices.IndexFunc(c.tpls, func(t pack.Template) bool { return t.ID == hit.Template })]
		row.Template = ptr(tpl.Path)
		row.Result, row.Note = "matched", cve+": the scan template matches, the flaw is still there."
		input := recheckInput(targets, hit.Target)
		ev := Evidence{
			// Review M3: only validated parts: the pack path, the address that passed the argv grammar and the job's input.
			// The device name comes from the network (DHCP, mDNS) and could plant a fake command; it is never in here.
			Summary:  fmt.Sprintf("Safe scan template %s matched on %s. To check it yourself, run: nuclei -t %s -u %s", tpl.Path, d.IP, tpl.Path, input),
			Template: tpl.Path, Request: hit.Request, Response: hit.Response, CheckedAt: s.now().UTC(),
		}
		if id, err := s.cfg.Findings.ConfirmFromScan(ctx, d.ID, cve, ev); err != nil {
			s.cfg.Log.ErrorContext(ctx, "scan: recording a confirmed finding failed", "asset", d.ID, "cve", cve, "error", err)
		} else {
			row.FindingID = ptr(id)
		}
		s.publish(ctx, EventFindingConfirmed, FindingConfirmedEvent{AssetID: d.ID, CVE: cve, Template: tpl.Path, Evidence: ev.Summary})
	case seen && !answered:
		row.Result, row.Note = "no_response", cve+": no answer for this check."
	default:
		// D-133 (5): nuclei may report matches only, so this is "no match reported", never "not vulnerable". It never
		// resolves, downgrades or marks the finding: nothing is sent to the findings module.
		row.Result, row.Note = "not_matched", cve+": no match reported by the scan template."
	}
	return row
}

// ---- probe log ----

type probeRow struct{ id, template string }

// writeProbes writes one probe row per template before the job leaves core (INV-7).
func (s *Service) writeProbes(ctx context.Context, runID string, d Device, checks []check) ([]probeRow, error) {
	now := store.FormatTS(s.now())
	var out []probeRow
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		out = out[:0]
		for _, c := range checks {
			for _, t := range c.tpls {
				id := store.NewID("pr")
				if _, err := tx.ExecContext(ctx, `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					id, now, runID, d.IP, clip(d.Label, 300), t.Path, t.Request); err != nil {
					return fmt.Errorf("scan: writing the probe log: %w", err)
				}
				out = append(out, probeRow{id: id, template: t.ID})
			}
		}
		return nil
	})
	return out, err
}

// closeProbes fills in the results; it runs even when the run was stopped (INV-7).
func (s *Service) closeProbes(ctx context.Context, rows []probeRow, result func(template string) string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			res := result(r.template)
			if res == "" {
				res = "no_response"
			}
			if _, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = ? WHERE id = ? AND result IS NULL`, res, r.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: closing the probe log failed", "error", err)
	}
}

// finish writes the end of a run and announces it.
func (s *Service) finish(ctx context.Context, runID, status, reason string, rows []RunRow, done int) {
	matched := 0
	for _, r := range rows {
		if r.Result == "matched" {
			matched++
		}
	}
	if rows == nil {
		rows = []RunRow{}
	}
	b, err := json.Marshal(rows)
	if err == nil {
		var stop *string
		if reason != "" {
			stop = &reason
		}
		err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE scan_run SET status = ?, ended_at = ?, current = NULL, results = ?, matched = ?, stop_reason = ?, done = ? WHERE id = ?`,
				status, store.FormatTS(s.now()), string(b), matched, stop, done, runID); err != nil {
				return err
			}
			// Review L4: a probe row closeProbes could not close does not stay open for good (INV-7).
			left := "no_response"
			if status != "done" {
				left = "stopped"
			}
			_, err := tx.ExecContext(ctx, `UPDATE scan_probe SET result = ? WHERE run_id = ? AND result IS NULL`, left, runID)
			return err
		})
	}
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "scan: writing the end of a run failed", "run", runID, "error", err)
		return
	}
	name := EventRunFinished
	if status != "done" {
		name = EventRunStopped
	}
	s.publish(ctx, name, RunEvent{RunID: runID, Status: status, Matched: matched})
}

func (s *Service) publish(ctx context.Context, name string, data any) {
	if s.cfg.Publisher == nil {
		return
	}
	if err := s.cfg.Publisher.Publish(ctx, events.Event{Name: name, Data: data}); err != nil {
		s.cfg.Log.WarnContext(ctx, "scan: publishing an event failed", "event", name, "error", err)
	}
}
