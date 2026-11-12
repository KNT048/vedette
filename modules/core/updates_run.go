package core

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/internal/release"
)

// The run side of the software update (S-CORE-2, D-340, D-342; update-manifest.md §7 and §10; host-api 6.7, 6.8,
// 6.10). Apply and Rollback are one run over every service, Vedette itself (core) last. The whole plan, with one
// idempotency key per host call, is stored in core_setting core_update_run BEFORE the first host call, and every
// step is written down as it goes: core's own switch restarts this process, and the next one carries on from the
// stored row (the host keeps its runs, host-api 4). A call that may have reached the host is never sent again with
// a new key: it is looked up by its key first.

const (
	updateRunShown     = 24 * time.Hour // an ended run stays on the page this long (contract UpdatesState.run)
	updateHistoryMax   = 100
	updateHistoryShown = 20
	updateRunsWindow   = 500 // the host keeps at most 500 runs: a lookup by key reads them all
	// updateRunMax ends a run that is still not settled this long after it started (lost contact with the host):
	// four pulls and four starts at the host's 45-minute limits would take longer, but a box that slow is broken.
	updateRunMax = 6 * time.Hour
	pullWait     = 50 * time.Minute // container.pull: 45 minutes at the host
	startWait    = 50 * time.Minute // container.start: 45 minutes at the host
	rollbackWait = 35 * time.Minute // container.rollback: 30 minutes at the host

	stepDownload = "download"
	stepStart    = "start"
	stepRestore  = "restore"
	stepRestart  = "restart"

	actionUpdate   = "update"
	actionRollback = "rollback"

	runRunning  = "running"
	runDone     = "done"
	runFailed   = "failed"
	runReverted = "reverted"

	callSkipped = "skipped" // a call of the plan that a failure before it made pointless
)

// updRun is the run side's part of OSHandlers.
type updRun struct {
	mu        sync.Mutex    // one start at a time: from the busy check to the stored run
	following atomic.Bool   // a follower of the stored run is going in this process
	retry     time.Duration // between two tries of the follower: followRetry (shorter in tests)
}

// runRelease is the signed release an update run installs, kept in the stored run: every container.pull (a resend
// after a restart too) carries the same bytes, so the same request id always goes with the same arguments.
type runRelease struct {
	Index       []byte `json:"index"`
	IndexSig    []byte `json:"index_sig"`
	Manifest    []byte `json:"manifest"`
	ManifestSig []byte `json:"manifest_sig"`
}

// updateCall is one host call of a run.
type updateCall struct {
	Step      string `json:"step"`
	Command   string `json:"command"` // host.self_update | container.pull | container.start | container.rollback
	Service   string `json:"service"`
	RequestID string `json:"request_id"`
	// Undo marks a call added after a failure to put a service the run had switched back where it was.
	Undo bool `json:"undo,omitempty"`
	// Sent: the call may have reached the host. From then on it is looked up by RequestID, never sent with a new one.
	Sent   bool   `json:"sent,omitempty"`
	RunID  string `json:"run_id,omitempty"`
	Status string `json:"status,omitempty"` // the host's end status, or skipped
	Code   string `json:"code,omitempty"`   // the host's error code when it did not succeed
	// Package is the id of the downloaded system helper package of host.self_update (<core_data>/host-packages/<id>.deb).
	Package string `json:"package,omitempty"`
}

// updateRunRec is what core_setting core_update_run holds: the view and the plan.
type updateRunRec struct {
	ID         string       `json:"id"`
	Action     string       `json:"action"`
	Component  string       `json:"component"`
	From       *string      `json:"from"`
	To         string       `json:"to"`
	Status     string       `json:"status"`
	Steps      []string     `json:"steps"`
	Step       *string      `json:"step"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt *time.Time   `json:"finished_at"`
	User       string       `json:"user"`
	Actor      string       `json:"actor"` // the label on the host calls
	Error      *string      `json:"error"`
	Calls      []updateCall `json:"calls"`
	Snapshot   string       `json:"snapshot,omitempty"` // backs core's container.start; removed when the run ends
	Release    *runRelease  `json:"release,omitempty"`  // update only, until the run ends
	Host       *runHost     `json:"host,omitempty"`     // update only, when the release brings a newer system helper (D-316)
	// Progress is when the run last moved (a step began, the host took a call or a call ended); a resend or a wait
	// does not count, so a host that refuses for ever still meets the 6-hour rule. The rule counts from it (or from
	// this process's start).
	Progress time.Time `json:"progress"`
	// SnapRefused counts the host's snapshot_required/snapshot_invalid answers to core's switch: a new snapshot is
	// tried up to maxSnapRefused times, then the refusal is final (a deployment error or clock skew, not a wait).
	SnapRefused int `json:"snap_refused,omitempty"`
	// Outcome and Why are the end decided by a failure while the undo calls still run.
	Outcome string `json:"outcome,omitempty"`
	Why     string `json:"why,omitempty"`
}

func (r *updateRunRec) view() updateRunView {
	return updateRunView{ID: r.ID, Action: r.Action, Component: r.Component, From: r.From, To: r.To, Status: r.Status,
		Steps: append([]string{}, r.Steps...), Step: r.Step, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, User: r.User, Error: r.Error}
}

func (h *OSHandlers) loadUpdateRun(ctx context.Context) (*updateRunRec, error) {
	var rec *updateRunRec
	if err := h.loadJSON(ctx, keyUpdateRun, &rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// saveUpdateRun stores the run; it gets its own short deadline, so a step is written down even while core stops.
func (h *OSHandlers) saveUpdateRun(parent context.Context, rec *updateRunRec) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	return h.db.Write(ctx, func(tx *sql.Tx) error { return h.putSetting(ctx, tx, keyUpdateRun, rec, rec.User) })
}

// updateRunning reports whether a software run is in progress. A row that cannot be read counts as running: the
// page then says busy instead of starting a second run over the first.
func (h *OSHandlers) updateRunning(ctx context.Context) bool {
	rec, err := h.loadUpdateRun(ctx)
	if err != nil {
		h.log.ErrorContext(ctx, "core: the software update run could not be read", "error", err)
		return true
	}
	return rec != nil && rec.Status == runRunning
}

// runView is UpdatesState.run: the run, or nil when there is none or it ended more than 24 hours ago.
func (h *OSHandlers) runView(ctx context.Context) (*updateRunView, error) {
	rec, err := h.loadUpdateRun(ctx)
	if err != nil || rec == nil {
		return nil, err
	}
	if rec.Status != runRunning && rec.FinishedAt != nil && h.now().Sub(*rec.FinishedAt) > updateRunShown {
		return nil, nil
	}
	v := rec.view()
	return &v, nil
}

// historyView is UpdatesState.history: newest first, at most 20.
func (h *OSHandlers) historyView(ctx context.Context) ([]updateHistoryView, error) {
	var all []updateHistoryView
	if err := h.loadJSON(ctx, keyUpdateHistory, &all); err != nil {
		return nil, err
	}
	if len(all) > updateHistoryShown {
		all = all[:updateHistoryShown]
	}
	return nonNil(all), nil
}

func errUpdateBusy() *apierr.Error {
	return apierr.New(409, codeBusy, "An update or rollback of the software is already running. Wait for it to finish.")
}

// ---- POST /core/updates/apply ----

// CorePostCoreUpdatesApply implements POST /core/updates/apply (admin): the software only (the other components
// have no update of their own yet: 404 no_update). It stores the run and answers at once with the run going; a
// follower does the host calls (pull every installed service, start the others, core last).
func (h *OSHandlers) CorePostCoreUpdatesApply(ctx context.Context, req *oas.CorePostCoreUpdatesApplyReq) (*oas.CorePostCoreUpdatesApplyOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if req.Component != softwareComponent {
		return nil, errNoUpdateAPI()
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	err = h.beginUpdate(ctx, c, func(ctx context.Context) (*updateRunRec, string, func(*sql.Tx) error, error) {
		rel, err := h.offered(ctx)
		if errors.Is(err, errNoUpdate) {
			return nil, "", nil, errNoUpdateAPI()
		}
		if err != nil {
			return nil, "", nil, err
		}
		rec, detail, err := h.planApply(ctx, c, rel)
		return rec, detail, nil, err
	})
	if err != nil {
		return nil, err
	}
	v, err := h.updatesView(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreUpdatesApplyOK](v)
}

func errNoUpdateAPI() *apierr.Error {
	return apierr.New(404, "no_update", "There is no new version of this component. Click \"Check now\".")
}

// ---- POST /core/updates/rollback ----

// CorePostCoreUpdatesRollback implements POST /core/updates/rollback (admin): every service that moved with core
// goes back to its previous version, core last. 409 confirm_required when the running release says the database
// must be put back too and the caller did not confirm the loss. The mode becomes manual in the same transaction
// as the stored run (D-340 (4)).
func (h *OSHandlers) CorePostCoreUpdatesRollback(ctx context.Context, req *oas.CorePostCoreUpdatesRollbackReq) (*oas.CorePostCoreUpdatesRollbackOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if req.Component != softwareComponent {
		return nil, apierr.New(404, apierr.CodeNotFound, "No such component.")
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	confirmed := req.ConfirmDataLoss.Or(false)
	err = h.beginUpdate(ctx, c, func(ctx context.Context) (*updateRunRec, string, func(*sql.Tx) error, error) {
		rec, detail, err := h.planRollback(ctx, c, confirmed)
		if err != nil {
			return nil, "", nil, err
		}
		return rec, detail, func(tx *sql.Tx) error { return h.setManual(ctx, tx, c.Email) }, nil
	})
	if err != nil {
		return nil, err
	}
	v, err := h.updatesView(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreUpdatesRollbackOK](v)
}

// beginUpdate is the common start of a run: no purge, not busy, the plan, then in one transaction the admin
// check, the audit row of the intent, the stored run and what the action adds (also); then the follower.
func (h *OSHandlers) beginUpdate(ctx context.Context, c caller, plan func(context.Context) (*updateRunRec, string, func(*sql.Tx) error, error)) error {
	leave, ok := h.gate.Enter()
	if !ok {
		return errPurging()
	}
	defer leave()
	h.urun.mu.Lock()
	defer h.urun.mu.Unlock()
	if h.updateRunning(ctx) {
		return errUpdateBusy()
	}
	if h.busy(ctx) {
		return apierr.New(409, codeBusy, "An operating system update is running. Wait for it to finish, then try again.")
	}
	rec, detail, also, err := plan(ctx)
	if err != nil {
		return err
	}
	action := "update.apply"
	if rec.Action == actionRollback {
		action = "update.rollback"
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		if err := h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: action, Target: softwareComponent, Detail: cutAtRune(detail, auditMaxDetail)}); err != nil {
			return err
		}
		if err := h.putSetting(ctx, tx, keyUpdateRun, rec, c.Email); err != nil {
			return err
		}
		if also != nil {
			return also(tx)
		}
		return nil
	})
	if err != nil {
		return err
	}
	h.invalidateState()
	// A run decided before any host call (host_too_old) ends here; if its end cannot be stored, the follower does it.
	if rec.Outcome == "" || len(rec.Calls) > 0 || h.settleUpdate(ctx, rec, rec.Outcome, rec.Why, nil) != nil {
		h.followUpdate()
	}
	return nil
}

// containers reads the services of the box and returns core's.
func (h *OSHandlers) containers(ctx context.Context) (api.ContainersState, *api.ContainerState, error) {
	st, err := h.host.StateContainers(ctx)
	if err != nil {
		return st, nil, hostErr(ctx, h.log, err)
	}
	for i := range st.Services {
		if st.Services[i].Service == api.ServiceCore && st.Services[i].Installed {
			return st, &st.Services[i], nil
		}
	}
	return st, nil, apierr.New(409, CodeNotAppliance, "Vedette itself does not run from a pinned container on this box, so it cannot update itself from here.")
}

func newUpdateRec(c caller, action string, from *string, to string, steps []string) (*updateRunRec, error) {
	id, err := newRequestID()
	if err != nil {
		return nil, err
	}
	step := steps[0]
	return &updateRunRec{ID: "ur_" + strings.ReplaceAll(id, "-", "")[:16], Action: action, Component: softwareComponent, From: from, To: to,
		Status: runRunning, Steps: steps, Step: &step, User: c.Email, Actor: actorLabel(c.Email, c.ID)}, nil
}

func (r *updateRunRec) add(step, command, service string, undo bool) error {
	id, err := newRequestID()
	if err != nil {
		return err
	}
	r.Calls = append(r.Calls, updateCall{Step: step, Command: command, Service: service, RequestID: id, Undo: undo})
	return nil
}

// planApply: host = host.self_update when the release brings a newer system helper (planHost, D-316); download =
// container.pull of every installed service the release has an image for (core included); start =
// container.start with the version for the other services that run (enabled); restart = core's container.start
// with a snapshot. A service that is installed but off (its module is off, its unit
// has no [Install], D-260) is pulled but not started: a start would turn it on (SYS-5) (D-342 (2)).
func (h *OSHandlers) planApply(ctx context.Context, c caller, rel *verifiedRelease) (*updateRunRec, string, error) {
	st, core, err := h.containers(ctx)
	if err != nil {
		return nil, "", err
	}
	if core.Version == nil { // the host could not judge the switch (host-api 6.8): refused before anything is pulled
		return nil, "", mapHostCode(ctx, h.log, api.CodeCurrentVersionUnknown, "", 0)
	}
	to := rel.M.Version
	rec, err := newUpdateRec(c, actionUpdate, core.Version, to, []string{stepDownload, stepStart, stepRestart})
	if err != nil {
		return nil, "", err
	}
	rec.StartedAt, rec.Progress = h.now(), h.now()
	rec.Release = &runRelease{Index: rel.Index, IndexSig: rel.IndexSig, Manifest: rel.Manifest, ManifestSig: rel.ManifestSig}
	detail := fmt.Sprintf("%s to %s", orDash(core.Version), to)
	hostDetail, err := h.planHost(ctx, rec, rel.M) // first: the new images may need the new helper (D-316 (8))
	if err != nil {
		return nil, "", err
	}
	detail += hostDetail
	if rec.Outcome != "" { // the helper is too old to update itself: no call at all
		return rec, detail, nil
	}
	inRelease := map[string]bool{}
	for _, im := range rel.M.Images {
		inRelease[im.Service] = true
	}
	if !inRelease[api.ServiceCore] {
		return nil, "", apierr.New(502, CodeHostError, "The release on offer has no image of Vedette itself, so it cannot be installed. Check again later.")
	}
	var off []string
	for _, s := range st.Services {
		if s.Installed && inRelease[s.Service] {
			if err := rec.add(stepDownload, api.CmdContainerPull, s.Service, false); err != nil {
				return nil, "", err
			}
		}
	}
	for _, s := range st.Services {
		if s.Service == api.ServiceCore || !s.Installed || !inRelease[s.Service] {
			continue
		}
		if !s.Enabled {
			off = append(off, s.Service)
			continue
		}
		if err := rec.add(stepStart, api.CmdContainerStart, s.Service, false); err != nil {
			return nil, "", err
		}
	}
	if err := rec.add(stepRestart, api.CmdContainerStart, api.ServiceCore, false); err != nil {
		return nil, "", err
	}
	if len(off) > 0 {
		detail += "; pulled but not started (off): " + strings.Join(off, ", ")
	}
	return rec, detail, nil
}

// planRollback: start = container.rollback of every other service that runs and moved with core (the same
// current and previous versions); restore (only shown) and restart = core's container.rollback, which puts the
// database back in the same host run when the running release says rollback.safe=false.
func (h *OSHandlers) planRollback(ctx context.Context, c caller, confirmed bool) (*updateRunRec, string, error) {
	st, core, err := h.containers(ctx)
	if err != nil {
		return nil, "", err
	}
	if core.Version == nil {
		return nil, "", mapHostCode(ctx, h.log, api.CodeCurrentVersionUnknown, "", 0)
	}
	if core.Previous == nil || core.Previous.Version == nil {
		return nil, "", mapHostCode(ctx, h.log, api.CodeNoPrevious, "", 0)
	}
	cur, prev := *core.Version, *core.Previous.Version
	if n, err := release.CompareVersions(prev, cur); err == nil && n > 0 {
		return nil, "", mapHostCode(ctx, h.log, api.CodeRollbackIsUpgrade, "", 0)
	}
	restores, err := h.runningRestoresData(ctx)
	if err != nil {
		return nil, "", err
	}
	if restores && !confirmed {
		return nil, "", apierr.New(409, CodeConfirmRequired, "This rollback also puts back the database from before the update, so data written since then is lost. Confirm to go on.")
	}
	steps := []string{stepStart, stepRestart}
	coreStep := stepRestart
	if restores {
		steps = []string{stepStart, stepRestore, stepRestart}
		coreStep = stepRestore
	}
	rec, err := newUpdateRec(c, actionRollback, &cur, prev, steps)
	if err != nil {
		return nil, "", err
	}
	rec.StartedAt, rec.Progress = h.now(), h.now()
	for _, s := range st.Services {
		if s.Service == api.ServiceCore || !s.Installed || !s.Enabled || s.Version == nil || *s.Version != cur ||
			s.Previous == nil || s.Previous.Version == nil || *s.Previous.Version != prev {
			continue
		}
		if err := rec.add(stepStart, api.CmdContainerRollback, s.Service, false); err != nil {
			return nil, "", err
		}
	}
	if err := rec.add(coreStep, api.CmdContainerRollback, api.ServiceCore, false); err != nil {
		return nil, "", err
	}
	detail := cur + " back to " + prev
	if restores {
		detail += "; the database goes back to before the update (confirmed)"
	}
	return rec, detail, nil
}

// ---- the follower ----

// followUpdate starts the follower of the stored run unless one is going in this process.
func (h *OSHandlers) followUpdate() {
	if h.urun.following.CompareAndSwap(false, true) {
		h.goFollow()
	}
}

// goFollow runs the follower; the caller holds urun.following.
func (h *OSHandlers) goFollow() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			h.followOne()
			if !h.handOff() {
				return
			}
		}
	}()
}

// handOff lets go of urun.following when a follower ends. An Apply that stored its run after the follower's last
// look and before the flag went down found a follower going and started none: look again, and keep the flag (true)
// when a run is still running.
func (h *OSHandlers) handOff() bool {
	h.urun.following.Store(false)
	return h.ctx.Err() == nil && h.updateRunning(h.ctx) && h.urun.following.CompareAndSwap(false, true)
}

// followOne carries the stored run until it is settled or core stops.
func (h *OSHandlers) followOne() {
	f := &updFollower{h: h, sent: map[string]bool{}, fetched: map[string]bool{}, started: h.now()}
	retry := h.urun.retry
	if retry <= 0 {
		retry = followRetry
	}
	for h.ctx.Err() == nil {
		done, err := f.advance(h.ctx)
		if done {
			return
		}
		if err != nil && h.ctx.Err() == nil {
			lvl := slog.LevelWarn
			if errors.Is(err, errTransient) { // waiting for the host (a rollback can take 30 minutes), not a fault
				lvl = slog.LevelDebug
			}
			h.log.Log(h.ctx, lvl, "core: the software update run waits for vedette-host", "error", err)
		}
		wait := retry
		if h.urun.retry <= 0 { // tests set their own pause
			wait = retryWait(err, retry)
		}
		select {
		case <-h.ctx.Done():
		case <-time.After(wait):
		}
	}
}

// retryWait is the pause before the next try: base, or the host's retry_after_s (dpkg_locked, rate_limited) when
// that is longer, at most maxRetryAfter.
func retryWait(err error, base time.Duration) time.Duration {
	var he *client.Error
	if errors.As(err, &he) && he.RetryAfterS > 0 {
		return max(base, min(time.Duration(he.RetryAfterS)*time.Second, maxRetryAfter))
	}
	return base
}

// maxRetryAfter caps the wait a host's retry_after_s asks for.
const maxRetryAfter = 5 * time.Minute

// updFollower carries the stored run forward. sent holds the request ids THIS process sent: only those may be
// sent again when the host does not know them (core's own switch is never sent again after a restart).
type updFollower struct {
	h       *OSHandlers
	sent    map[string]bool
	fetched map[string]bool // system helper packages this process downloaded and checked (by id)
	started time.Time       // the 6-hour rule never counts time before this process followed the run
}

// errTransient is a call whose outcome is not known yet: the follower tries again later with the same key.
var errTransient = errors.New("core: no answer from vedette-host yet")

// advance runs the stored plan from the first call that has not ended; done is true when the run is settled.
func (f *updFollower) advance(ctx context.Context) (done bool, err error) {
	h := f.h
	rec, err := h.loadUpdateRun(ctx)
	if err != nil {
		return false, err
	}
	if rec == nil || rec.Status != runRunning {
		return true, nil
	}
	// No progress for 6 hours (counted from the last step written down, or from this process's start: a database put
	// back by a rollback holds an old run that must still be settled from the host's record).
	if last := rec.Progress; h.now().Sub(later(last, f.started)) > updateRunMax {
		err := h.settleUpdate(ctx, rec, runFailed, "The update stopped because Vedette lost contact with its operating system helper for too long. Check the versions below and try again.", nil)
		return err == nil, err
	}
	leave, ok := h.gate.Enter()
	if !ok {
		return false, errPurging()
	}
	defer leave()
	for i := 0; i < len(rec.Calls); i++ {
		c := rec.Calls[i]
		if c.Status != "" {
			continue
		}
		if !c.Undo && (rec.Step == nil || *rec.Step != c.Step) {
			step := c.Step
			rec.Step, rec.Progress = &step, h.now()
			if err := h.saveUpdateRun(ctx, rec); err != nil {
				return false, err
			}
		}
		run, err := f.call(ctx, rec, i)
		if err != nil {
			return false, err
		}
		rec.Calls[i].Status, rec.Progress = string(run.Status), h.now()
		if run.Error != nil {
			rec.Calls[i].Code = run.Error.Code
		}
		if run.Status != api.StatusSucceeded {
			if err := f.failed(ctx, rec, i, run); err != nil {
				return false, err
			}
		} else if c.Command == api.CmdHostSelfUpdate {
			if err := h.hostUpdated(ctx, rec, run); err != nil { // the step and its history entry together
				return false, err
			}
			continue
		}
		if err := h.saveUpdateRun(ctx, rec); err != nil {
			return false, err
		}
	}
	if rec.Outcome != "" {
		err = h.settleUpdate(ctx, rec, rec.Outcome, rec.Why, nil)
	} else {
		var rb *api.Run
		if rb, err = f.rolledBackSince(ctx, rec); err == nil {
			err = h.settleUpdate(ctx, rec, runDone, "", rb)
		}
	}
	return err == nil, err // not stored: the next try settles it again
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// call makes sure call i has a host run and returns it ended. A call that has a run is followed; one that may
// have been sent is looked up by its key; one that was not is sent. errTransient (or a host error): try again.
func (f *updFollower) call(ctx context.Context, rec *updateRunRec, i int) (api.Run, error) {
	h := f.h
	c := &rec.Calls[i]
	if c.RunID != "" {
		run, err := h.host.GetRun(ctx, c.RunID)
		if err != nil {
			return api.Run{}, err
		}
		return f.wait(ctx, c, run)
	}
	if c.Sent {
		run, found, err := h.findRun(ctx, c.Command, c.RequestID)
		if err != nil {
			return api.Run{}, err
		}
		if found {
			c.RunID, rec.Progress = run.RunID, h.now()
			if err := h.saveUpdateRun(ctx, rec); err != nil {
				return api.Run{}, err
			}
			return f.wait(ctx, c, run)
		}
		if c.Service == api.ServiceCore && !c.Undo && !f.sent[c.RequestID] {
			// core stopped before the host took its switch: a switch is never sent from a run that was cut, it
			// could undo a rollback that came after it (D-342 (1)). Nothing changed on core: the others go back.
			return api.Run{Status: api.StatusFailed, Error: &api.RunError{Code: codeInterrupted}}, nil
		}
	}
	return f.send(ctx, rec, i)
}

// maxSnapRefused bounds the new snapshots core's switch tries after the host refused one (SnapRefused).
const maxSnapRefused = 2

// codeInterrupted is the run side's own end code of core's switch when core stopped before the host took it.
const codeInterrupted = "interrupted"

func (f *updFollower) send(ctx context.Context, rec *updateRunRec, i int) (api.Run, error) {
	h := f.h
	c := &rec.Calls[i]
	if c.Command == api.CmdHostSelfUpdate {
		return f.sendHost(ctx, rec, i)
	}
	var pull api.ContainerPullArgs
	if c.Command == api.CmdContainerPull {
		rel := rec.Release
		if rel == nil { // a run stored before the release went into it: nothing to send the same bytes from
			return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: codeNotOffered}}, nil
		}
		enc := base64.StdEncoding.EncodeToString
		pull = api.ContainerPullArgs{Service: c.Service, Version: rec.To, Source: api.PullSourceRegistry,
			Index: enc(rel.Index), IndexSig: enc(rel.IndexSig), Manifest: enc(rel.Manifest), ManifestSig: enc(rel.ManifestSig)}
	}
	c.Sent = true
	f.sent[c.RequestID] = true
	if err := h.saveUpdateRun(ctx, rec); err != nil { // before the snapshot: the copy of the data says the switch was sent
		return api.Run{}, err
	}
	coreSwitch := c.Command == api.CmdContainerStart && c.Service == api.ServiceCore
	if coreSwitch && rec.Snapshot == "" {
		snap, err := h.snaps.create(ctx, true)
		if err != nil {
			code := CodeSnapshotFailed
			if ae, ok := apierr.As(h.snapshotFailure(ctx, err)); ok {
				code = ae.Code
			}
			return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: code}}, nil
		}
		rec.Snapshot = snap.ID
		if err := h.saveUpdateRun(ctx, rec); err != nil {
			return api.Run{}, err
		}
	}
	var run api.Run
	var err error
	switch c.Command {
	case api.CmdContainerPull:
		run, err = h.host.ContainerPull(ctx, pull, c.RequestID, rec.Actor)
	case api.CmdContainerStart:
		a := api.ContainerStartArgs{Service: c.Service, Version: rec.To}
		if coreSwitch {
			a.Snapshot = rec.Snapshot
		}
		run, err = h.host.ContainerStart(ctx, a, c.RequestID, rec.Actor)
	default:
		run, err = h.host.ContainerRollback(ctx, api.ContainerRollbackArgs{Service: c.Service}, c.RequestID, rec.Actor)
	}
	if err != nil {
		var he *client.Error
		if coreSwitch && errors.As(err, &he) && (he.Code == api.CodeSnapshotRequired || he.Code == api.CodeSnapshotInvalid) &&
			rec.SnapRefused < maxSnapRefused { // too old after a wait: a new snapshot, the same key (a refusal frees it)
			h.removeSnapshot(rec.Snapshot)
			rec.Snapshot = ""
			rec.SnapRefused++
			if err := h.saveUpdateRun(ctx, rec); err != nil {
				return api.Run{}, err
			}
			return api.Run{}, errTransient
		}
		if errors.As(err, &he) && tryLater(he.Code) {
			// The host did not take the key (a refusal binds none, host-api 4): the call was not sent. A restart
			// must not read "sent, unknown to the host" as a cut run (core's switch would end interrupted).
			c.Sent = false
			delete(f.sent, c.RequestID)
			if serr := h.saveUpdateRun(ctx, rec); serr != nil {
				return api.Run{}, serr
			}
		}
		return refusalOf(err)
	}
	c.RunID, rec.Progress = run.RunID, h.now()
	if err := h.saveUpdateRun(ctx, rec); err != nil {
		return api.Run{}, err
	}
	return f.wait(ctx, c, run)
}

// refusalOf is a host call that returned no run: no answer or a "try later" is an error (the next try looks the
// call up by its key, or sends it again with it: a refusal frees the key, host-api 4); any other refusal is the
// call's final outcome.
func refusalOf(err error) (api.Run, error) {
	var he *client.Error
	if !errors.As(err, &he) {
		return api.Run{}, err
	}
	if tryLater(he.Code) {
		return api.Run{}, err
	}
	return api.Run{Status: api.StatusRefused, Error: &api.RunError{Code: he.Code, Message: he.Message}}, nil
}

// tryLater: the host did not take the call and asks for it again later.
func tryLater(code string) bool {
	switch code {
	case api.CodeBusy, api.CodeRateLimited, api.CodeShuttingDown, api.CodePendingConfirm, api.CodeNetPendingConfirm,
		api.CodeRebooting, api.CodeDpkgLocked, api.CodeInstallInProgress: // end by themselves: rebooting from any write, dpkg_locked from host.self_update's check, install_in_progress from os.reboot's (a running os.install answers busy)
		return true
	}
	return false
}

// sentAgain: a refusal after which core sends the call again under the same key (try later, or core's switch with a
// new snapshot): the refused run the host records under that key is not the call's outcome.
func sentAgain(r api.Run) bool {
	if r.Status != api.StatusRefused || r.Error == nil {
		return false
	}
	return tryLater(r.Error.Code) || r.Error.Code == api.CodeSnapshotRequired || r.Error.Code == api.CodeSnapshotInvalid
}

// codeNotOffered: the release the run installs is no longer offered (a newer check replaced it) after a restart.
const codeNotOffered = "not_offered"

func (f *updFollower) wait(ctx context.Context, c *updateCall, run api.Run) (api.Run, error) {
	limit := startWait
	var end time.Time // host.self_update: the run's deadline + 20 minutes, across the host's restart
	switch c.Command {
	case api.CmdContainerPull:
		limit = pullWait
	case api.CmdContainerRollback:
		limit = rollbackWait
	case api.CmdHostSelfUpdate:
		end = selfUpdateEnd(run)
		limit = end.Sub(f.h.now())
	}
	pastEnd := func() bool { return !end.IsZero() && !f.h.now().Before(end) }
	stopped := api.Run{Status: api.StatusFailed, Error: &api.RunError{Code: api.CodeSelfUpdateInterrupted}}
	if !run.Status.Terminal() && pastEnd() {
		return stopped, nil
	}
	run, err := waitRun(ctx, f.h.log, f.h.host, run, limit)
	if run.Status.Terminal() {
		return run, nil // a run that did not succeed is an outcome, not an error of the wait
	}
	if pastEnd() {
		return stopped, nil
	}
	if err == nil {
		err = errTransient
	}
	return api.Run{}, err
}

// findRun looks a call up in the host's record by its key (the host keeps 500 runs).
func (h *OSHandlers) findRun(ctx context.Context, command, requestID string) (api.Run, bool, error) {
	runs, err := h.host.ListRuns(ctx, updateRunsWindow)
	if err != nil {
		return api.Run{}, false, err
	}
	for _, r := range runs {
		// the host also records a refusal under the call's key (host-api 4) and frees the key: one core sends again
		// is not the call's outcome (slice 6 lab: a busy host.self_update right after the install ended the run)
		if r.RequestID == requestID && r.Command == command && !sentAgain(r) {
			return r, true, nil
		}
	}
	return api.Run{}, false, nil
}

// failed decides the end of a run whose call i did not succeed: the calls after it are skipped, and every other
// service this run switched (and that still runs the version it switched to) is put back by a container.rollback
// of its own (D-342 (3)). The end is reverted when the host put the failed service back by itself and the others
// went back too; failed otherwise. A failing undo call only adds to the words.
func (f *updFollower) failed(ctx context.Context, rec *updateRunRec, i int, run api.Run) error {
	c := rec.Calls[i]
	code := ""
	if run.Error != nil {
		code = run.Error.Code
	}
	if c.Undo {
		rec.Outcome = runFailed
		rec.Why += " Putting " + serviceName(c.Service) + " back failed as well (" + updateReason(ctx, code) + "). Check the services on the box before you try again."
		return nil
	}
	for j := i + 1; j < len(rec.Calls); j++ {
		if rec.Calls[j].Status == "" {
			rec.Calls[j].Status = callSkipped
		}
	}
	rec.Outcome, rec.Why = runFailed, f.why(ctx, rec, c, run)
	if run.Status == api.StatusReverted {
		rec.Outcome = runReverted
	}
	switched := map[string]bool{}
	for _, x := range rec.Calls[:i] {
		// the system helper is never taken back (D-316 (f))
		if !x.Undo && x.Service != api.ServiceCore && x.Command != api.CmdContainerPull && x.Command != api.CmdHostSelfUpdate && x.Status == string(api.StatusSucceeded) {
			switched[x.Service] = true
		}
	}
	if len(switched) == 0 {
		return nil
	}
	st, err := f.h.host.StateContainers(ctx)
	if err != nil {
		return err // the step is not written down: the next try decides again
	}
	back := 0
	for _, s := range st.Services { // in the host's order
		if switched[s.Service] && s.Version != nil && *s.Version == rec.To {
			if err := rec.add(c.Step, api.CmdContainerRollback, s.Service, true); err != nil {
				return err
			}
			back++
		}
	}
	if back > 0 && rec.From != nil {
		rec.Why += " The other services were put back on " + *rec.From + "."
	}
	return nil
}

// why says in words why call c ended the run, naming the service.
func (f *updFollower) why(ctx context.Context, rec *updateRunRec, c updateCall, run api.Run) string {
	code := ""
	if run.Error != nil {
		code = run.Error.Code
	}
	name := serviceName(c.Service)
	reason := updateReason(ctx, code)
	from := orDash(rec.From)
	switch {
	case code == codeInterrupted && rec.Action == actionRollback:
		return "Vedette restarted during the rollback and the box has no record that Vedette itself went back to " + rec.To + ", so the rollback was stopped. Check the version on this page, then roll back again if needed."
	case code == codeInterrupted:
		return "Vedette restarted during the update and the box has no record that Vedette itself switched to " + rec.To + ", so the update was stopped. Check the version on this page, then apply again if needed."
	case code == codeNotOffered:
		return "The update record does not hold the release " + rec.To + " any more, so the update was stopped. Click Check now, then Apply."
	case c.Command == api.CmdHostSelfUpdate:
		return hostWhy(ctx, rec, code)
	case c.Command == api.CmdContainerPull:
		return "Downloading " + rec.To + " of " + name + " failed: " + reason
	case c.Service == api.ServiceCore && run.Status == api.StatusReverted && rec.Action == actionUpdate:
		return "Vedette " + rec.To + " did not start correctly, so the box went back to " + from + "."
	case c.Service == api.ServiceCore && run.Status == api.StatusReverted:
		return "Vedette " + rec.To + " did not start correctly, so the box stayed on " + from + "."
	case run.Status == api.StatusReverted:
		return name + " did not start correctly on " + rec.To + ", so it went back to " + from + "."
	case rec.Action == actionRollback:
		return "Rolling back " + name + " failed: " + reason
	}
	return name + " could not switch to " + rec.To + ": " + reason
}

// serviceName names a service the way the page does.
func serviceName(s string) string {
	switch s {
	case api.ServiceCore:
		return "Vedette"
	case api.ServiceSensor:
		return "the sensor"
	case api.ServiceHoneypot:
		return "the honeypot"
	case api.ServiceScan:
		return "the scanner"
	case api.ServiceGreenbone:
		return "Greenbone"
	}
	return s
}

// updateReason is one plain sentence for the end code of a container call; codes shared with the OS calls use
// mapHostCode's sentence.
func updateReason(ctx context.Context, code string) string {
	switch code {
	case api.CodeSignatureInvalid, api.CodeKeyRevoked, api.CodeManifestMismatch, api.CodeRegistryNotAllowed, api.CodeDigestNotInManifest:
		return "the release did not pass the signature check on the box, so nothing was installed."
	case api.CodeReleaseRevoked:
		return "this release has been withdrawn by the project, so nothing was installed."
	case api.CodeSequenceRegress, api.CodeReleaseStateInvalid, api.CodeNoTrustedKeys:
		return "the box's record of signed releases does not allow it. See the RUNBOOK (release index)."
	case api.CodePlatformMismatch:
		return "the release has no image for this kind of machine."
	case api.CodePullFailed:
		return "the image could not be downloaded. Check the box's internet access and try again."
	case api.CodeScanBuildFailed:
		return "the scanner image could not be built on the box. Check that the box can reach its package mirror."
	case api.CodeNotPulled:
		return "the new image is not on the box. Try the update again."
	case api.CodeDowngradeNotAllowed:
		return "the box already runs a newer version."
	case api.CodeUpgradePathRequired:
		return "the box must first install an intermediate version. Check the release notes."
	case api.CodeUnitFailed:
		return "it did not become healthy."
	case api.CodeRollbackRevertFailed:
		return "putting the running version back failed too. Check the services on the box (RUNBOOK, update journal)."
	case api.CodeTimeout:
		return "it took too long."
	case CodeSnapshotFailed:
		return "Vedette could not write a copy of its data to the box's data folder. Check that the folder is writable and the disk is healthy."
	case "":
		return "the operating system helper did not say why. The details are in the box log."
	}
	if ae := mapHostCode(ctx, slog.New(slog.DiscardHandler), code, "", 0); ae != nil {
		return ae.Message
	}
	return "the operating system helper could not do this. The details are in the box log."
}

// rolledBackSince finds the rollback that a restored database forgot: core's container.rollback that put the
// pre-update copy back replaced this database with the one from before the update, so the stored run is the update
// (still running at its last step) and the rollback's own row is gone. The host still has its run: newer than
// core's switch, succeeded, with restored_backup_id. nil when there is none (or it cannot be told). errTransient
// while such a rollback is still running: core is back up on the restored database before the host has ended the
// rollback's run (it waits for core's health first), and settling now would lose the rollback for good (lab).
func (f *updFollower) rolledBackSince(ctx context.Context, rec *updateRunRec) (*api.Run, error) {
	h := f.h
	if rec.Action != actionUpdate || rec.From == nil {
		return nil, nil
	}
	coreRun := ""
	for _, c := range rec.Calls {
		if c.Service == api.ServiceCore && c.Command == api.CmdContainerStart && !c.Undo {
			coreRun = c.RunID
		}
	}
	if coreRun == "" {
		return nil, nil
	}
	runs, err := h.host.ListRuns(ctx, updateRunsWindow)
	if err != nil {
		return nil, err // not settled on a failed read: the rollback would be lost for good
	}
	var found *api.Run
	for _, r := range runs { // newest first, down to core's switch
		if r.RunID == coreRun {
			break
		}
		if r.Command != api.CmdContainerRollback {
			continue
		}
		if !r.Status.Terminal() {
			// Before the version check: while the rollback runs, the host reports core's version as null (its record
			// of the version is written after the health check), so the check cannot tell yet.
			return nil, errTransient
		}
		var res api.ContainerRollbackResult
		if found == nil && r.Status == api.StatusSucceeded && json.Unmarshal(r.Result, &res) == nil && res.RestoredBackupID != nil {
			found = &r
		}
	}
	if found == nil {
		return nil, nil
	}
	st, err := h.host.StateContainers(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range st.Services {
		if s.Service == api.ServiceCore && (s.Version == nil || *s.Version != *rec.From) {
			return nil, nil // core still runs what the update installed (or something else): nothing was rolled back here
		}
	}
	return found, nil
}

// settleUpdate ends the run in one transaction: the stored run, a history entry when versions changed, one
// audit row; then the snapshot goes. rb is a rollback that a restored database forgot (rolledBackSince): it is
// written after the update it undid, as its own history entry, audit row and the run shown, and the mode
// becomes manual again (the restore took that back too).
func (h *OSHandlers) settleUpdate(parent context.Context, rec *updateRunRec, status, why string, rb *api.Run) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	fin := h.now()
	rec.Status, rec.Step, rec.FinishedAt, rec.Error = status, nil, &fin, nil
	if why != "" {
		rec.Error = &why
	}
	snap := rec.Snapshot
	rec.Snapshot, rec.Release = "", nil
	var hist []updateHistoryView
	if err := h.loadJSON(ctx, keyUpdateHistory, &hist); err != nil {
		return err
	}
	shown := rec
	if status == runDone {
		hist = append([]updateHistoryView{{ID: "h_" + rec.ID, TS: fin, Component: rec.Component, From: rec.From, To: rec.To, Action: rec.Action, User: rec.User}}, hist...)
	}
	if rb != nil {
		at := fin
		if rb.FinishedAt != nil {
			at = *rb.FinishedAt
		}
		to := rec.To
		back := &updateRunRec{ID: "ur_" + strings.TrimPrefix(rb.RunID, "rn_"), Action: actionRollback, Component: rec.Component, From: &to, To: *rec.From,
			Status: runDone, Steps: []string{stepStart, stepRestore, stepRestart}, StartedAt: rb.StartedAt, FinishedAt: &at, User: rb.Actor, Actor: rb.Actor}
		hist = append([]updateHistoryView{{ID: "h_" + back.ID, TS: at, Component: rec.Component, From: back.From, To: back.To, Action: actionRollback, User: rb.Actor}}, hist...)
		shown = back
	}
	if len(hist) > updateHistoryMax {
		hist = hist[:updateHistoryMax]
	}
	action := "update.apply_done"
	if rec.Action == actionRollback {
		action = "update.rollback_done"
	}
	detail := fmt.Sprintf("%s to %s: %s", orDash(rec.From), rec.To, status)
	if why != "" {
		detail += ": " + why
	}
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.audit.Append(ctx, tx, audit.Entry{User: rec.User, Action: action, Target: rec.Component, Detail: cutAtRune(detail, auditMaxDetail)}); err != nil {
			return err
		}
		if rb != nil {
			d := fmt.Sprintf("%s back to %s: done; the database was put back to before the update, this record was rebuilt from vedette-host", rec.To, *rec.From)
			if err := h.audit.Append(ctx, tx, audit.Entry{User: rb.Actor, Action: "update.rollback_done", Target: rec.Component, Detail: cutAtRune(d, auditMaxDetail)}); err != nil {
				return err
			}
			if err := h.setManual(ctx, tx, rb.Actor); err != nil {
				return err
			}
		}
		if err := h.putSetting(ctx, tx, keyUpdateHistory, hist, rec.User); err != nil {
			return err
		}
		return h.putSetting(ctx, tx, keyUpdateRun, shown, rec.User)
	})
	if err != nil {
		h.log.ErrorContext(ctx, "core: the end of a software update run could not be stored", "run", rec.ID, "error", err)
		return err
	}
	h.removeSnapshot(snap)
	h.removeHostPackages(rec)
	h.invalidateState()
	return nil
}

// resumeUpdate is the start-up pass of the run side: a stored run that is still running is carried on.
func (h *OSHandlers) resumeUpdate() {
	if h.host == nil {
		return
	}
	rec, err := h.loadUpdateRun(h.ctx)
	if err != nil {
		h.log.Error("core: the software update run could not be read at start-up", "error", err)
		return
	}
	if rec != nil && rec.Status == runRunning {
		h.followUpdate()
	}
}
