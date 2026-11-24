package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/host/api"
)

// Restore of a backup the helper keeps on the box (S-CORE-1; host-api 6.12). Before backup.restore core
// writes a snapshot of its data WITH the key, which the host keeps as the pre_restore backup and puts back by
// itself when the restored data does not start (status reverted). A successful restore stops core and swaps its
// database: whatever core wrote about the run is gone with the old file. So the host's run is the record: core
// keeps only a copy in core_setting data.restore and settles the end into whichever database core now runs on: one
// audit row data.restore_done per run, the copy, and the removal of the snapshot. The host marks the run ended only
// once core is healthy on the restored data, so the process that records the end is the one started on it: every
// restore leaves a marker next to the database (restore-pending.json, outside the file the restore replaces), and the
// start-up pass that finds it follows the run to its end and settles it there (settleRestoreAtStart). A read of the run
// (the Data page polls it) settles it too; until the host has said how the newest run ended, a read never answers
// from the copy, which in a restored database is an older restore's.
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
	// Step-up as for Delete all data: the current password, counted against the re-auth limiter, then a
	// fresh two-step code when it is on.
	if err := h.auth.VerifyOwnPassword(ctx, c.ID, req.Password, "Wrong password. The password is needed to restore a backup."); err != nil {
		return nil, err
	}
	if u, err := h.auth.GetUser(ctx, c.ID); err != nil {
		return nil, fmt.Errorf("core: read user: %w", err)
	} else if u.TwofaMethod != "" {
		// The summary goes out in the code email: the time with its zone, UTC (said so) when the organization's cannot be read
		loc, err := h.location(ctx)
		if err != nil {
			h.log.WarnContext(ctx, "core: reading the organization time zone failed; the restore summary uses UTC", "error", err)
			loc = time.UTC
		}
		if _, err := h.auth.VerifyTwoStep(ctx, c.ID, req.Code.Or(""), "core.data_restore", "Restore the backup from "+orgtime.StampZone(b.CreatedAt, loc)); err != nil {
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
// core's copy of the run and its follower. Settings -> Data and the first-run restore share it.
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
	if err := h.writePendingRestore(pendingRestore{RunID: run.RunID, StartedAt: run.StartedAt.UTC()}); err != nil {
		// The page's next read still settles it; only the record without a reader waits for it
		h.log.ErrorContext(ctx, "core: could not leave the pending-restore marker", "run", run.RunID, "error", err)
	}
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
		h.restoreSynced.Store(true)
		return rec, nil
	}
	run := runs[i]
	if run.Status.Terminal() {
		if err := h.settleRestore(ctx, run); err != nil {
			return nil, err
		}
		h.restoreSynced.Store(true)
		return h.loadRestore(ctx)
	}
	// The newest run is still going (core may already run on the restored data while the host checks its health): the
	// copy is not the answer until the host says how it ended, so restoreSynced stays as it is.
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

// backupKindWords names a backup kind as the Data page does.
var backupKindWords = map[string]string{
	"manual": "Manual", "pre_update": "Before Vedette update", "pre_os_update": "Before operating system update", "pre_restore": "Before restore",
}

// restoreDetail is the detail of data.restore_done: the end, and the backup in words (its time in the organization's zone and
// its kind, not only the id in the target). A done restore put back the audit log of that backup's moment too, so the row
// says where the lines written after it are: the request's own data.restore row is among them.
func (h *OSHandlers) restoreDetail(ctx context.Context, rec *restoreRec, kind string, rerr *api.RunError) string {
	detail := rec.Status
	if rerr != nil {
		detail += " " + rerr.Code
	}
	if rec.BackupCreatedAt.IsZero() {
		return detail
	}
	loc, err := h.location(ctx)
	if err != nil {
		loc = time.UTC
	}
	what := "the backup from " + orgtime.Stamp(rec.BackupCreatedAt, loc)
	if w := backupKindWords[kind]; w != "" {
		what += " (" + w + ")"
	}
	if rec.Status != "done" {
		return detail + ": " + what
	}
	if rec.PreRestore == "" {
		return detail + ": " + what + " is back; audit lines written after it are no longer in this log"
	}
	return detail + ": " + what + " is back; audit lines written after it are only in the Before restore copy"
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
		h.dropPendingRestore(run.RunID)
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
	kind := ""
	if rec.BackupID != "" {
		if bl, err := h.host.StateBackups(ctx); err == nil {
			if i := slices.IndexFunc(bl.Backups, func(b api.Backup) bool { return b.BackupID == rec.BackupID }); i >= 0 {
				kind = bl.Backups[i].Kind
				if rec.BackupCreatedAt.IsZero() {
					rec.BackupCreatedAt = bl.Backups[i].CreatedAt
				}
			}
		}
	}
	rec.Status, rec.FinishedAt, rec.PreRestore = restoreStatus(run.Status), run.FinishedAt, res.PreRestoreBackupID
	if rec.Status != "done" {
		rec.Error = restoreReason(ctx, h, run.Error)
	}
	detail := h.restoreDetail(ctx, rec, kind, run.Error)
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.putSetting(ctx, tx, keyRestore, rec, "system"); err != nil {
			return err
		}
		if err := h.audit.Append(ctx, tx, audit.Entry{User: rec.User, Action: "data.restore_done", Target: rec.BackupID, Detail: cutAtRune(detail, auditMaxDetail)}); err != nil {
			return err
		}
		if rec.Status == "done" && run.Actor == setupActor {
			// A first-run restore succeeded: this is the restored database, and the operator accepted the terms before it
			// started (POST /core/setup/restore refuses without): the version shown and the time, from the marker.
			t, ok := h.readTermsMarker()
			if !ok { // no marker, or one that cannot be trusted: the version of this software, the start of the run
				t = firstRunTerms{Version: vedette.TermsVersion(), At: run.StartedAt.UTC()}
			}
			return acceptTerms(ctx, tx, h.audit, termsAcceptance{By: setupActor, At: t.At, Version: t.Version, Via: "restore"})
		}
		return nil
	})
	if err == nil && run.Actor == setupActor {
		h.dropTermsMarker() // the first-run restore is settled, whichever way it ended
	}
	if err != nil {
		return fmt.Errorf("core: settle restore: %w", err)
	}
	h.dropPendingRestore(run.RunID)
	h.dropRestoreRuns() // a shared list read before the end would show the run still going
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

// ---- the restore that core recorded as started, outside the database it replaces ----

const (
	pendingRestoreFile = "restore-pending.json"
	// pendingRestoreMaxAge: a marker older than this belongs to a restore that never came back (the host ends it within
	// restoreTimeout); it is dropped at start-up, not followed.
	pendingRestoreMaxAge = 2 * time.Hour
)

// pendingRestore is restore-pending.json: the run core started. It lives next to the database, not in it, because the
// restore replaces the database; the process that starts on the restored one finds it and records the end there.
type pendingRestore struct {
	RunID     string    `json:"run_id"`
	StartedAt time.Time `json:"started_at"`
}

// runIDRE is the shape of a host run id core accepts from the marker (validated at the edge: the file sits on disk).
var runIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (h *OSHandlers) writePendingRestore(p pendingRestore) error {
	if h.pendingMarker == "" {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("core: encode the pending-restore marker: %w", err)
	}
	tmp := h.pendingMarker + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("core: write the pending-restore marker: %w", err)
	}
	if err := os.Rename(tmp, h.pendingMarker); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("core: write the pending-restore marker: %w", err)
	}
	return nil
}

// readPendingRestore is the marker, ok false when there is none or it cannot be trusted (over 4 KiB, a run id of
// another shape, a start that is not within the last pendingRestoreMaxAge).
func (h *OSHandlers) readPendingRestore() (pendingRestore, bool) {
	var p pendingRestore
	if h.pendingMarker == "" {
		return p, false
	}
	b, err := os.ReadFile(h.pendingMarker)
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &p) != nil || !runIDRE.MatchString(p.RunID) {
		return pendingRestore{}, false
	}
	if now := h.now(); p.StartedAt.IsZero() || p.StartedAt.After(now.Add(time.Minute)) || now.Sub(p.StartedAt) > pendingRestoreMaxAge {
		return pendingRestore{}, false
	}
	return p, true
}

// dropPendingRestore removes the marker when it names runID (now settled), or any marker when runID is "" or the
// marker cannot be trusted.
func (h *OSHandlers) dropPendingRestore(runID string) {
	if h.pendingMarker == "" {
		return
	}
	if p, ok := h.readPendingRestore(); ok && runID != "" && p.RunID != runID {
		return // a newer restore's: it stays for its own end
	}
	if err := os.Remove(h.pendingMarker); err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.log.Warn("core: could not remove the pending-restore marker", "error", err)
	}
}

// settleRestoreAtStart runs once at start-up, only when a restore left its marker (restore-pending.json, or the terms
// marker of a first-run restore): it settles the run into the database core now runs on (the restored one, or the one put
// back), so the end is in the audit log and on the Data page right after the restart whoever opens which page. A run the
// host still checks (the host ends it only once core is healthy, so this is the usual case) is followed to its end. One
// host read, bounded; an error leaves the marker for the next start or the next read of Settings -> Data, never a retry per
// request.
func (h *OSHandlers) settleRestoreAtStart() {
	_, pending := h.readPendingRestore()
	if !pending {
		h.dropPendingRestore("") // none, or one too old or not ours to follow
	}
	if !h.firstRunRestorePending() && !pending {
		return
	}
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()
	rec, err := h.restoreLatest(ctx)
	if err != nil {
		h.log.Warn("core: could not settle the restore at start", "error", err)
		return
	}
	if rec != nil && rec.Status == "" {
		h.wg.Add(1)
		go h.followRestore(api.Run{RunID: rec.RunID, Command: api.CmdBackupRestore, Status: api.StatusRunning, StartedAt: rec.StartedAt, Actor: rec.User})
		return
	}
	h.dropPendingRestore("") // the run is settled here, or the host no longer has it: nothing to follow
}
