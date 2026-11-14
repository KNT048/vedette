package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/host/api"
)

// Restore of a backup the helper keeps on the box (S-CORE-1, D-377; host-api 6.12). Before backup.restore core
// writes a snapshot of its data WITH the key, which the host keeps as the pre_restore backup and puts back by
// itself when the restored data does not start (status reverted). A successful restore stops core and swaps its
// database: whatever core wrote about the run is gone with the old file. So the host's run is the record: core
// keeps only a copy in core_setting data.restore, and the first read of the run in a process (the Data page
// polls it, and reconnects to it after the restart) asks the host for the latest backup.restore and settles it
// into whichever database core now runs on: one audit row data.restore_done per run, the copy, and the removal
// of the snapshot. ponytail: no start-up pass (it would spend a host request on every start); a box restored
// and never opened again keeps its end unaudited and its snapshot until the start-up sweep (1 hour), upgrade:
// a start-up pass once the host's rate limit has room for it.
const (
	keyRestore     = "data.restore"
	restoreTimeout = 35 * time.Minute // backup.restore's own limit is 30 minutes
	codeConfirmReq = "confirm_required"
	codeRunLost    = "run_lost" // core's copy says running but the host's recent runs have no such restore
	// restoreRunsTTL is how long the host's run list answers the restore reads: the page polls while a restore
	// runs, and every open tab must not spend the host's 60 requests a minute (as stateTTL for the OS state).
	restoreRunsTTL = 5 * time.Second
)

// restoreRec is core_setting data.restore. Status is empty while the run is going.
type restoreRec struct {
	RunID           string     `json:"run_id"`
	BackupID        string     `json:"backup_id"`
	BackupCreatedAt time.Time  `json:"backup_created_at"`
	User            string     `json:"user"`
	StartedAt       time.Time  `json:"started_at"`
	Status          string     `json:"status,omitempty"` // done | reverted | failed
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	PreRestore      string     `json:"pre_restore,omitempty"`
	Error           string     `json:"error,omitempty"`
	Snapshot        string     `json:"snapshot,omitempty"` // backs the run; removed when it is settled
}

type restoreView struct {
	ID              string     `json:"id"`
	BackupID        string     `json:"backup_id"`
	BackupCreatedAt time.Time  `json:"backup_created_at"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at"`
	User            string     `json:"user"`
	PreRestore      *string    `json:"pre_restore_backup_id"`
	Error           *string    `json:"error"`
}

func (r *restoreRec) view() restoreView {
	v := restoreView{ID: r.RunID, BackupID: r.BackupID, BackupCreatedAt: r.BackupCreatedAt, Status: r.Status, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, User: r.User}
	if v.Status == "" {
		v.Status = "running"
	}
	if v.BackupCreatedAt.IsZero() { // the host no longer lists the backup: the start of the run is the closest date there is
		v.BackupCreatedAt = r.StartedAt
	}
	if r.PreRestore != "" {
		v.PreRestore = &r.PreRestore
	}
	if r.Error != "" {
		v.Error = &r.Error
	}
	return v
}

// restoreStatus maps a terminal host status to the API's; "" for a run still going.
func restoreStatus(s api.Status) string {
	switch s {
	case api.StatusSucceeded:
		return "done"
	case api.StatusReverted:
		return "reverted"
	case api.StatusFailed, api.StatusRefused:
		return "failed"
	}
	return ""
}

// restoreReason is the plain sentence of a restore run that did not end in done.
func restoreReason(ctx context.Context, h *OSHandlers, e *api.RunError) string {
	code := ""
	if e != nil {
		code = e.Code
	}
	switch code {
	case api.CodeRestoreHealthFailed, "":
		return "The restored data did not start correctly, so the box put back the data it had before. Nothing was lost."
	case codeRunLost:
		return "The box has no record of how this restore ended. Check the list of backups and the box log."
	case "restore_revert_failed":
		return "The restored data did not start and the box could not put back the data it had before. The copy from before the restore is still in the list of backups; see the RUNBOOK (restore a backup)."
	}
	msg := ""
	if e != nil {
		msg = e.Message
	}
	return mapHostCode(ctx, h.log, code, msg, 0).Message
}

// ---- GET /core/data/backups ----

// CoreGetCoreDataBackups implements GET /core/data/backups (admin): the backups the helper keeps, newest first.
// Kinds the API does not name are left out.
func (h *OSHandlers) CoreGetCoreDataBackups(ctx context.Context) (*oas.CoreGetCoreDataBackupsOK, error) {
	if err := h.needHost(); err != nil {
		return nil, err
	}
	bl, err := h.host.StateBackups(ctx)
	if err != nil {
		return nil, hostErr(ctx, h.log, err)
	}
	out := &oas.CoreGetCoreDataBackupsOK{Backups: []oas.CoreGetCoreDataBackupsOKBackupsItem{}}
	for _, b := range bl.Backups {
		k := oas.CoreGetCoreDataBackupsOKBackupsItemKind(b.Kind)
		if !slices.Contains(k.AllValues(), k) {
			continue
		}
		out.Backups = append(out.Backups, oas.CoreGetCoreDataBackupsOKBackupsItem{ID: b.BackupID, Kind: k, CreatedAt: b.CreatedAt, Size: int(b.Size), IncludesKey: b.IncludesSecrets})
	}
	slices.SortStableFunc(out.Backups, func(a, b oas.CoreGetCoreDataBackupsOKBackupsItem) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

// ---- POST /core/data/restore ----

// CorePostCoreDataRestore implements POST /core/data/restore (admin, 202). Nothing is asked of the host before
// confirm_data_loss is true (409 confirm_required) and the backup is in the host's list (404 backup_unknown).
func (h *OSHandlers) CorePostCoreDataRestore(ctx context.Context, req *oas.CorePostCoreDataRestoreReq) (*oas.CorePostCoreDataRestoreAccepted, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.needHost(); err != nil {
		return nil, err
	}
	if v, ok := req.ConfirmDataLoss.Get(); !ok || !v {
		return nil, apierr.New(409, codeConfirmReq, "Restoring replaces everything written since the backup. Confirm to go on.")
	}
	unlock, err := h.lockRestore(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	bl, err := h.host.StateBackups(ctx)
	if err != nil {
		return nil, hostErr(ctx, h.log, err)
	}
	i := slices.IndexFunc(bl.Backups, func(b api.Backup) bool { return b.BackupID == req.BackupID })
	if i < 0 {
		return nil, mapHostCode(ctx, h.log, api.CodeBackupUnknown, "", 0)
	}
	b := bl.Backups[i]
	// Step-up as for Delete all data (D-76, D-98, D-154): the current password, counted against the re-auth limiter, then a
	// fresh two-step code when it is on.
	if err := h.auth.VerifyOwnPassword(ctx, c.ID, req.Password, "Wrong password. The password is needed to restore a backup."); err != nil {
		return nil, err
	}
	if u, err := h.auth.GetUser(ctx, c.ID); err != nil {
		return nil, fmt.Errorf("core: read user: %w", err)
	} else if u.TwofaMethod != "" {
		if _, err := h.auth.VerifyTwoStep(ctx, c.ID, req.Code.Or(""), "core.data_restore", "Restore the backup from "+b.CreatedAt.UTC().Format("2006-01-02 15:04")+" UTC"); err != nil {
			return nil, err
		}
	}
	rec, err := h.startRestore(ctx, c, true, b)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreDataRestoreAccepted](rec.view())
}

// lockRestore takes what a restore holds from its busy check until it is stored (one host write of this kind at a time
// through this process, and no software run starting meanwhile: beginUpdate asks restoreRunning) and refuses with 409
// busy while an update or another restore runs. The caller runs unlock when it is done.
func (h *OSHandlers) lockRestore(ctx context.Context) (unlock func(), err error) {
	h.installMu.Lock()
	h.urun.mu.Lock()
	unlock = func() { h.urun.mu.Unlock(); h.installMu.Unlock() }
	if h.busy(ctx) {
		unlock()
		return nil, apierr.New(409, codeBusy, "An update run is in progress. Wait for it to finish, then restore.")
	}
	if rec, err := h.restoreLatest(ctx); err != nil {
		unlock()
		return nil, err
	} else if rec != nil && rec.Status == "" {
		unlock()
		return nil, apierr.New(409, codeBusy, "A restore is already running. Wait for it to finish.")
	}
	return unlock, nil
}

// startRestore runs backup.restore of b (in the host's list) under lockRestore: the intent's audit row (admin: the caller is
// re-checked as an administrator in it), a snapshot of the current data WITH the key that the host keeps as pre_restore,
// core's copy of the run and its follower. Settings -> Data and the first-run restore (D-518) share it.
func (h *OSHandlers) startRestore(ctx context.Context, c caller, admin bool, b api.Backup) (*restoreRec, error) {
	var snap snapshot
	var run api.Run
	keepSnap := false
	err := h.act(ctx, c, admin, "data.restore", b.BackupID, "backup of "+b.CreatedAt.UTC().Format(time.RFC3339), func(id, actor string) error {
		var err error
		if snap, err = h.snaps.create(ctx, true); err != nil {
			return h.snapshotFailure(ctx, err)
		}
		if run, err = h.host.BackupRestore(ctx, b.BackupID, snap.ID, id, actor); err != nil {
			var found, known bool
			if run, found, known = h.recoverRun(ctx, err, api.CmdBackupRestore, id); found {
				return nil
			}
			keepSnap = !known // the host may be reading it: the start-up sweep removes it later
			return notTaken(ctx, h.log, err, run)
		}
		return nil
	})
	if err != nil {
		if !keepSnap {
			snap.remove()
		}
		return nil, err
	}
	rec := &restoreRec{RunID: run.RunID, BackupID: b.BackupID, BackupCreatedAt: b.CreatedAt, User: c.Email, StartedAt: run.StartedAt, Snapshot: snap.ID}
	h.dropRestoreRuns()
	if err := h.storeStarted(context.WithoutCancel(ctx), rec); err != nil {
		h.log.ErrorContext(ctx, "core: could not store the restore run", "run", run.RunID, "error", err) // the host holds the record
	}
	h.wg.Add(1)
	go h.followRestore(run)
	return rec, nil
}

// ---- GET /core/data/restore/run ----

// CoreGetCoreDataRestoreRun implements GET /core/data/restore/run (admin): the latest restore, null before the first.
func (h *OSHandlers) CoreGetCoreDataRestoreRun(ctx context.Context) (oas.NilCoreGetCoreDataRestoreRunOK, error) {
	if err := h.needHost(); err != nil {
		return oas.NilCoreGetCoreDataRestoreRunOK{}, err
	}
	rec, err := h.restoreLatest(ctx)
	if err != nil {
		return oas.NilCoreGetCoreDataRestoreRunOK{}, err
	}
	if rec == nil {
		return oas.NilCoreGetCoreDataRestoreRunOK{Null: true}, nil
	}
	out, err := asOAS[oas.NilCoreGetCoreDataRestoreRunOK](rec.view())
	if err != nil {
		return oas.NilCoreGetCoreDataRestoreRunOK{}, err
	}
	return *out, nil
}

// ---- following and settling ----

// restoreRunning reports whether core's copy says a restore is running and it started less than restoreTimeout ago (an
// older copy is settled by restoreLatest when the page reads it). A copy that cannot be read counts as running.
func (h *OSHandlers) restoreRunning(ctx context.Context) bool {
	rec, err := h.loadRestore(ctx)
	if err != nil {
		h.log.ErrorContext(ctx, "core: the restore record could not be read", "error", err)
		return true
	}
	return rec != nil && rec.Status == "" && h.now().Sub(rec.StartedAt) < restoreTimeout
}

func (h *OSHandlers) loadRestore(ctx context.Context) (*restoreRec, error) {
	var rec restoreRec
	if err := h.loadJSON(ctx, keyRestore, &rec); err != nil {
		return nil, err
	}
	if rec.RunID == "" {
		return nil, nil
	}
	return &rec, nil
}

// restoreLatest is the latest restore as core should show it. A settled copy answers alone once this process
// has looked at the host (restoreSynced): a restored database may hold the copy of an older restore. Otherwise
// it asks the host, settles a run that ended, and describes one still going.
func (h *OSHandlers) restoreLatest(ctx context.Context) (*restoreRec, error) {
	rec, err := h.loadRestore(ctx)
	if err != nil {
		return nil, err
	}
	if rec != nil && rec.Status != "" && h.restoreSynced.Load() {
		return rec, nil
	}
	runs, err := h.restoreRuns(ctx)
	if err != nil {
		return nil, hostErr(ctx, h.log, err)
	}
	h.restoreSynced.Store(true)
	if rec != nil && rec.Status == "" && h.now().Sub(rec.StartedAt) > restoreTimeout && !slices.ContainsFunc(runs, func(r api.Run) bool { return r.RunID == rec.RunID }) {
		// core's copy says running, the run's own limit is long past and the host's recent runs do not have it: settle it
		// as lost, never a 409 busy for ever. (Not sooner: a list read just before the host took the run must not end it.)
		lost := api.Run{RunID: rec.RunID, Command: api.CmdBackupRestore, Status: api.StatusFailed, StartedAt: rec.StartedAt, Error: &api.RunError{Code: codeRunLost}}
		if err := h.settleRestore(ctx, lost); err != nil {
			return nil, err
		}
		if rec, err = h.loadRestore(ctx); err != nil {
			return nil, err
		}
	}
	mine := ""
	if rec != nil {
		mine = rec.RunID
	}
	i := slices.IndexFunc(runs, func(r api.Run) bool { return r.Command == api.CmdBackupRestore && !refusedElsewhere(r, mine) }) // newest first
	if i < 0 || (rec != nil && rec.RunID != runs[i].RunID && rec.StartedAt.After(runs[i].StartedAt)) {
		return rec, nil
	}
	run := runs[i]
	if run.Status.Terminal() {
		if err := h.settleRestore(ctx, run); err != nil {
			return nil, err
		}
		return h.loadRestore(ctx)
	}
	if rec == nil || rec.RunID != run.RunID {
		rec = &restoreRec{RunID: run.RunID, User: run.Actor, StartedAt: run.StartedAt}
	}
	rec.Status = ""
	return rec, nil
}

// restoreRuns is the host's recent runs, shared for restoreRunsTTL.
func (h *OSHandlers) restoreRuns(ctx context.Context) ([]api.Run, error) {
	h.rrMu.Lock()
	defer h.rrMu.Unlock()
	if h.rrRuns != nil && h.now().Sub(h.rrAt) < restoreRunsTTL {
		return h.rrRuns, nil
	}
	runs, err := h.host.ListRuns(ctx, listRunsWindow)
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller maps it with hostErr
	}
	if runs == nil {
		runs = []api.Run{}
	}
	h.rrRuns, h.rrAt = runs, h.now()
	return runs, nil
}

// dropRestoreRuns forgets the shared run list: a restore just started.
func (h *OSHandlers) dropRestoreRuns() {
	h.rrMu.Lock()
	h.rrRuns = nil
	h.rrMu.Unlock()
}

// storeStarted writes the copy of a run just started, unless this database already settled that run (a read
// may have seen it end first): one data.restore_done, never a settled copy turned back into a running one.
func (h *OSHandlers) storeStarted(ctx context.Context, rec *restoreRec) error {
	h.restoreMu.Lock()
	defer h.restoreMu.Unlock()
	if cur, err := h.loadRestore(ctx); err != nil {
		return err
	} else if cur != nil && cur.RunID == rec.RunID && cur.Status != "" {
		return nil
	}
	return h.db.Write(ctx, func(tx *sql.Tx) error { return h.putSetting(ctx, tx, keyRestore, rec, rec.User) })
}

// followRestore waits for a restore run to end and settles it. Core is stopped by a restore that gets that far:
// the follower then dies with the process and the first read in the next one does the rest.
func (h *OSHandlers) followRestore(run api.Run) {
	defer h.wg.Done()
	id := run.RunID
	run, err := waitRun(h.ctx, h.log, h.host, run, restoreTimeout)
	if err != nil && !run.Status.Terminal() { // waitRun also errs for a run that ended badly: that one is settled
		if !errors.Is(err, context.Canceled) {
			h.log.Warn("core: lost track of the restore run; it is settled on the next read", "run", id, "error", err)
		}
		return
	}
	if err := h.settleRestore(h.ctx, run); err != nil {
		h.log.Error("core: could not settle the restore run", "run", run.RunID, "error", err)
	}
}

// settleRestore records the end of a restore run once per database: the copy in core_setting and the audit row
// data.restore_done in one transaction, then removes the snapshot that backed it. A database that does not know
// that id (the restore swapped it) removes every snapshot written before this process started that no resumed run
// needs (removeBefore).
func (h *OSHandlers) settleRestore(ctx context.Context, run api.Run) error {
	h.restoreMu.Lock() // the follower and a read may settle the same run at once: one audit row
	defer h.restoreMu.Unlock()
	rec, err := h.loadRestore(ctx)
	if err != nil {
		return err
	}
	if rec != nil && rec.RunID == run.RunID && rec.Status != "" {
		return nil
	}
	if rec == nil || rec.RunID != run.RunID { // a restored database, or a restore started by an earlier process
		rec = &restoreRec{RunID: run.RunID, User: run.Actor, StartedAt: run.StartedAt}
	}
	var res api.BackupRestoreResult
	if len(run.Result) > 0 {
		_ = json.Unmarshal(run.Result, &res) // a result core cannot read only leaves the ids empty
	}
	if rec.BackupID == "" {
		rec.BackupID = res.RestoredBackupID
	}
	if rec.BackupCreatedAt.IsZero() && rec.BackupID != "" {
		if bl, err := h.host.StateBackups(ctx); err == nil {
			if i := slices.IndexFunc(bl.Backups, func(b api.Backup) bool { return b.BackupID == rec.BackupID }); i >= 0 {
				rec.BackupCreatedAt = bl.Backups[i].CreatedAt
			}
		}
	}
	rec.Status, rec.FinishedAt, rec.PreRestore = restoreStatus(run.Status), run.FinishedAt, res.PreRestoreBackupID
	if rec.Status != "done" {
		rec.Error = restoreReason(ctx, h, run.Error)
	}
	detail := rec.Status
	if run.Error != nil {
		detail += " " + run.Error.Code
	}
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.putSetting(ctx, tx, keyRestore, rec, "system"); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: rec.User, Action: "data.restore_done", Target: rec.BackupID, Detail: cutAtRune(detail, auditMaxDetail)})
	})
	if err != nil {
		return fmt.Errorf("core: settle restore: %w", err)
	}
	switch {
	case h.snaps == nil:
	case rec.Snapshot != "":
		if snapshotIDRE.MatchString(rec.Snapshot) {
			snapshot{ID: rec.Snapshot, dir: filepath.Join(h.snaps.dir, rec.Snapshot)}.remove()
		}
	default:
		var keep []string
		if m, err := h.loadRunMeta(ctx); err == nil && m.Snapshot != "" {
			keep = append(keep, m.Snapshot)
		}
		if u, err := h.loadUpdateRun(ctx); err == nil && u != nil && u.Snapshot != "" {
			keep = append(keep, u.Snapshot)
		}
		h.snaps.removeBefore(h.started, keep...)
	}
	return nil
}
