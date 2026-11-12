package core_test

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/core"
)

// restoreHost is the helper for the restore tests (S-CORE-1, D-377): the other commands go to the in-process host,
// backup.restore and the run list are faked so a test decides how the run ends without stopping anything.
type restoreHost struct {
	core.Host
	mu      sync.Mutex
	backups []api.Backup
	runs    []api.Run // newest first
	snap    string    // the snapshot named by the last backup.restore
	calls   int
	lists   int      // ListRuns calls
	end     *api.Run // when set, backup.restore answers this run as already ended
}

func (f *restoreHost) StateBackups(context.Context) (api.BackupList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return api.BackupList{Backups: slices.Clone(f.backups)}, nil
}

func (f *restoreHost) BackupRestore(_ context.Context, _, snap, rid, actor string) (api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.snap = snap
	r := api.Run{RunID: "rn_restore1", Command: api.CmdBackupRestore, Status: api.StatusRunning, StartedAt: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC), Actor: actor, RequestID: rid}
	if f.end != nil {
		r.Status, r.FinishedAt, r.Result, r.Error = f.end.Status, f.end.FinishedAt, f.end.Result, f.end.Error
	}
	f.runs = append([]api.Run{r}, f.runs...)
	return r, nil
}

func (f *restoreHost) ListRuns(context.Context, int) ([]api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	return slices.Clone(f.runs), nil
}

// finish ends the latest run as the host would after core came back.
func (f *restoreHost) finish(st api.Status, res any, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at := time.Date(2026, 11, 9, 12, 5, 0, 0, time.UTC)
	f.runs[0].Status, f.runs[0].FinishedAt = st, &at
	if res != nil {
		f.runs[0].Result, _ = json.Marshal(res)
	}
	if code != "" {
		f.runs[0].Error = &api.RunError{Code: code, Message: "x"}
	}
}

func newRestoreEnv(t *testing.T) (*osEnv, *restoreHost) {
	t.Helper()
	e := newOSEnv(t, osOpts{})
	f := &restoreHost{Host: e.hh.Client, backups: []api.Backup{
		{BackupID: "aaaa0000aaaa0000aaaa0000aaaa0000", Kind: "manual", CreatedAt: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC), Size: 2048},
		{BackupID: "bbbb0000bbbb0000bbbb0000bbbb0000", Kind: "pre_os_update", CreatedAt: time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC), Size: 4096, IncludesSecrets: true},
		{BackupID: "cccc0000cccc0000cccc0000cccc0000", Kind: "some_future_kind", CreatedAt: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)},
	}}
	e.handler = e.newHandlers(t, f, 0)
	return e, f
}

func (e *osEnv) count(action string) (n int) {
	for _, a := range e.actions() {
		if a == action {
			n++
		}
	}
	return n
}

// The list is newest first and leaves out kinds the API does not name; the key flag comes from the host.
func TestRestoreListsTheHostsBackups(t *testing.T) {
	t.Parallel()
	e, _ := newRestoreEnv(t)
	r := e.admin.get("/core/data/backups")
	wantOK(t, r, 200)
	l := getArr(r, "backups")
	if len(l) != 2 || l[0].(map[string]any)["kind"] != "pre_os_update" || l[0].(map[string]any)["includes_key"] != true || l[1].(map[string]any)["id"] != "aaaa0000aaaa0000aaaa0000aaaa0000" {
		t.Fatalf("backups = %s", r.Raw)
	}
	wantStatus(t, e.oper.get("/core/data/backups"), 403, "forbidden")
}

// Without confirm_data_loss nothing reaches the host and nothing is written; an unknown id is 404.
func TestRestoreNeedsTheConfirmationAndAKnownBackup(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantStatus(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "aaaa0000aaaa0000aaaa0000aaaa0000", "password": authtest.Password}), 409, "confirm_required")
	wantStatus(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "aaaa0000aaaa0000aaaa0000aaaa0000", "confirm_data_loss": false, "password": authtest.Password}), 409, "confirm_required")
	wantStatus(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "ffff0000ffff0000ffff0000ffff0000", "confirm_data_loss": true, "password": authtest.Password}), 404, "backup_unknown")
	if f.calls != 0 || len(e.snapshotDirs()) != 0 || e.count("data.restore") != 0 {
		t.Fatalf("calls=%d snapshots=%v actions=%v", f.calls, e.snapshotDirs(), e.actions())
	}
	if r := e.admin.get("/core/data/restore/run"); r.Code != 200 || string(r.Raw) != "null" {
		t.Errorf("run before any = %d %s", r.Code, r.Raw)
	}
}

// The restore names a fresh snapshot WITH the key; the run is settled once (audit row, snapshot gone), also after
// a restart of core that finds the end on the host.
func TestRestoreTakesASnapshotAndSettlesOnce(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	r := e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password})
	wantOK(t, r, 202)
	if r.str("status") != "running" || r.str("backup_id") != "bbbb0000bbbb0000bbbb0000bbbb0000" || r.str("user") != "admin@acme.example" || r.str("backup_created_at") != "2026-11-08T09:00:00Z" {
		t.Fatalf("accepted = %s", r.Raw)
	}
	if dirs := e.snapshotDirs(); len(dirs) != 1 || dirs[0] != f.snap {
		t.Fatalf("snapshots = %v, host got %q", dirs, f.snap)
	}
	wantStatus(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 409, "busy")
	f.finish(api.StatusReverted, api.BackupRestoreResult{RestoredBackupID: "bbbb0000bbbb0000bbbb0000bbbb0000", PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"}, api.CodeRestoreHealthFailed)
	e.newHandlers(t, f, 0) // core comes back: the host holds the end
	got := e.admin.get("/core/data/restore/run")
	wantOK(t, got, 200)
	if got.str("status") != "reverted" || got.str("pre_restore_backup_id") != "dddd0000dddd0000dddd0000dddd0000" || got.str("error") == "" {
		t.Fatalf("after = %s", got.Raw)
	}
	eventuallyOS(t, "the snapshot to go", func() bool { return len(e.snapshotDirs()) == 0 })
	e.admin.get("/core/data/restore/run")
	if e.count("data.restore") != 1 || e.count("data.restore_done") != 1 {
		t.Errorf("actions = %v", e.actions())
	}
}

// A restored database knows nothing of the run (its copy was in the old file): core rebuilds it from the host,
// takes the date from the list, and audits the end in the database it now runs on.
func TestRestoreIntoADatabaseThatForgotTheRun(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	at := time.Date(2026, 11, 9, 12, 5, 0, 0, time.UTC)
	res, _ := json.Marshal(api.BackupRestoreResult{RestoredBackupID: "aaaa0000aaaa0000aaaa0000aaaa0000", PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"})
	f.runs = []api.Run{{RunID: "rn_old", Command: api.CmdBackupRestore, Status: api.StatusSucceeded, StartedAt: at.Add(-5 * time.Minute), FinishedAt: &at, Actor: "admin@acme.example", Result: res}}
	e.setting("data.restore", `{"run_id":"rn_older","backup_id":"x","backup_created_at":"2026-10-01T00:00:00Z","user":"a","started_at":"2026-10-01T00:00:00Z","status":"done"}`)
	e.newHandlers(t, f, 0)
	got := e.admin.get("/core/data/restore/run")
	wantOK(t, got, 200)
	if got.str("id") != "rn_old" || got.str("status") != "done" || got.str("backup_created_at") != "2026-11-01T09:00:00Z" || got.JSON["error"] != nil {
		t.Fatalf("run = %s", got.Raw)
	}
	eventuallyOS(t, "one audit row of the end", func() bool { return e.count("data.restore_done") == 1 })
}

// Restore asks for the current password like Delete all data: a wrong one is 400 wrong_password and reaches nothing.
func TestRestoreNeedsTheCurrentPassword(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantStatus(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "aaaa0000aaaa0000aaaa0000aaaa0000", "confirm_data_loss": true, "password": "wrong"}), 400, "wrong_password")
	if f.calls != 0 || len(e.snapshotDirs()) != 0 || e.count("data.restore") != 0 {
		t.Fatalf("calls=%d snapshots=%v actions=%v", f.calls, e.snapshotDirs(), e.actions())
	}
}

// Polling reads share one host run list for a few seconds; a copy that says running for a run the host no longer
// lists, long after the run's own limit, is settled as failed instead of a 409 busy for ever.
func TestRestoreReadsShareTheRunListAndALostRunEnds(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantOK(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 202)
	f.mu.Lock()
	f.runs, f.lists = nil, 0 // the host forgot the run
	f.mu.Unlock()
	for range 3 {
		if r := e.admin.get("/core/data/restore/run"); r.str("status") != "running" {
			t.Fatalf("before the limit = %s", r.Raw)
		}
	}
	if f.lists != 1 {
		t.Errorf("three reads within the cache time made %d host calls, want 1", f.lists)
	}
	e.clock.Advance(36 * time.Minute)
	r := e.admin.get("/core/data/restore/run")
	if r.str("status") != "failed" || r.str("error") == "" || f.lists != 2 {
		t.Fatalf("after the limit = %s (lists %d)", r.Raw, f.lists)
	}
	if e.count("data.restore_done") != 1 {
		t.Errorf("actions = %v", e.actions())
	}
}
