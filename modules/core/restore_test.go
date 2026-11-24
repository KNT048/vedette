package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/core"
)

// restoreHost is the helper for the restore tests (S-CORE-1): the other commands go to the in-process host,
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
	listErr error    // when set, ListRuns fails with it
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
	if f.listErr != nil {
		return nil, f.listErr
	}
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
	// The row says which backup came back in words (its day and time in the organization's zone, +07 here, and its kind, not only its id) and that the audit lines
	// written after that backup are gone from this log: the restore put back the log of that moment, and the Before
	// restore copy holds them.
	want := "done: the backup from 1 Nov 2026, 16:00 (Manual) is back; audit lines written after it are only in the Before restore copy"
	if d := e.auditDetails("data.restore_done"); len(d) != 1 || d[0] != want {
		t.Errorf("data.restore_done detail = %q, want %q", d, want)
	}
}

// The host records a refusal as a run (host-api 4): a busy backup.restore that is the newest run is not a restore
// to settle: no data.restore_done, no failed restore shown.
func TestRestoreRefusedByTheHostIsNotSettled(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f.runs = []api.Run{{RunID: "rn_busy", Command: api.CmdBackupRestore, Status: api.StatusRefused, StartedAt: at, FinishedAt: &at, Error: &api.RunError{Code: api.CodeBusy}}}
	e.newHandlers(t, f, 0)
	if r := e.admin.get("/core/data/restore/run"); r.Code != 200 || string(r.Raw) != "null" {
		t.Fatalf("run = %d %s, want null", r.Code, r.Raw)
	}
	if n := e.count("data.restore_done"); n != 0 {
		t.Errorf("data.restore_done audited %d times for a restore that never ran", n)
	}
}

// A restore core took (202, copy stored) that the host refused while it ran (schema_newer) is the restore: after a
// restart it is settled as failed with one data.restore_done row, and a new restore is no longer busy.
func TestRestoreRefusedWhileItRanIsSettled(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantOK(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 202)
	f.finish(api.StatusRefused, nil, api.CodeSchemaNewer)
	e.newHandlers(t, f, 0) // the follower missed the end
	got := e.admin.get("/core/data/restore/run")
	wantOK(t, got, 200)
	if got.str("id") != "rn_restore1" || got.str("status") != "failed" || got.str("error") == "" {
		t.Fatalf("after = %s", got.Raw)
	}
	eventuallyOS(t, "one data.restore_done row", func() bool { return e.count("data.restore_done") == 1 })
	wantOK(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 202)
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

// followHost is restoreHost with the run followable (GetRun and an event stream that ends at once), as the real host is
// for a core process that starts while backup.restore still checks its health.
type followHost struct {
	*restoreHost
	ev *hostclient.Client
}

func newFollowHost(t *testing.T, f *restoreHost) *followHost {
	t.Helper()
	return &followHost{restoreHost: f, ev: endedStreams(t)}
}

func (f *followHost) GetRun(_ context.Context, id string) (api.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if r.RunID == id {
			return r, nil
		}
	}
	return api.Run{}, &hostclient.Error{Status: 404, Code: "run_not_found", Message: "no such run"}
}

func (f *followHost) Events(ctx context.Context, runID string, after uint64) *hostclient.Stream {
	return f.ev.Events(ctx, runID, after)
}

// endedStreams is a host client whose event streams end at once with a final state (the follower then reads the run itself).
func endedStreams(t *testing.T) *hostclient.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "vr") // unix socket paths are short: t.TempDir is too long on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "id: 1\ndata: {\"seq\":1,\"kind\":\"state\",\"status\":\"succeeded\"}\n\n")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return hostclient.New(sock)
}

// swapIn makes the database look like the one a restore brings back: it holds the copy of an older, settled restore and
// nothing of the run that restored it.
func (e *osEnv) swapIn() {
	e.t.Helper()
	e.setting("data.restore", `{"run_id":"rn_older","backup_id":"aaaa0000aaaa0000aaaa0000aaaa0000","backup_created_at":"2026-10-01T00:00:00Z","user":"a","started_at":"2026-10-01T00:00:00Z","status":"done"}`)
}

// Core starts on the restored database while the host still checks its health. The end of the restore is recorded in
// that database by the start-up pass, without anyone opening a page: one data.restore_done row naming the backup that
// came back, and the run is the latest restore (not the older one the restored data remembers).
func TestRestoreIsRecordedInTheRestoredDatabaseAtStart(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantOK(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 202)
	e.swapIn()
	e.newHandlers(t, newFollowHost(t, f), 0) // core is back on the restored data; the run is not over yet
	f.finish(api.StatusSucceeded, api.BackupRestoreResult{RestoredBackupID: "bbbb0000bbbb0000bbbb0000bbbb0000", PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"}, "")
	eventuallyOS(t, "the restore recorded in the restored database", func() bool { return e.count("data.restore_done") == 1 })
	want := "done: the backup from 8 Nov 2026, 16:00 (Before operating system update) is back; audit lines written after it are only in the Before restore copy"
	if d := e.auditDetails("data.restore_done"); len(d) != 1 || d[0] != want {
		t.Errorf("data.restore_done detail = %q, want %q", d, want)
	}
	got := e.admin.get("/core/data/restore/run")
	if got.str("id") != "rn_restore1" || got.str("status") != "done" || got.str("backup_created_at") != "2026-11-08T09:00:00Z" {
		t.Fatalf("run = %s", got.Raw)
	}
	if _, err := os.Stat(filepath.Join(e.m.CoreData, "restore-pending.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the pending-restore marker stayed after the run was recorded: %v", err)
	}
}

// The Data page reads the run while the host still checks the restored data: it says running, and once the run ended
// the next read records and shows it, never the older restore the restored database remembers.
func TestRestoreReadDuringTheHealthCheckShowsTheNewRun(t *testing.T) {
	t.Parallel()
	e, f := newRestoreEnv(t)
	wantOK(t, e.admin.post("/core/data/restore", map[string]any{"backup_id": "bbbb0000bbbb0000bbbb0000bbbb0000", "confirm_data_loss": true, "password": authtest.Password}), 202)
	e.swapIn()
	e.newHandlers(t, f, 0) // this host cannot be followed: only the page's reads see the end
	if r := e.admin.get("/core/data/restore/run"); r.str("id") != "rn_restore1" || r.str("status") != "running" {
		t.Fatalf("during the health check = %s", r.Raw)
	}
	f.finish(api.StatusSucceeded, api.BackupRestoreResult{RestoredBackupID: "bbbb0000bbbb0000bbbb0000bbbb0000", PreRestoreBackupID: "dddd0000dddd0000dddd0000dddd0000"}, "")
	e.clock.Advance(6 * time.Second) // past the shared run list
	if r := e.admin.get("/core/data/restore/run"); r.str("id") != "rn_restore1" || r.str("status") != "done" {
		t.Fatalf("after the run ended = %s", r.Raw)
	}
	if n := e.count("data.restore_done"); n != 1 {
		t.Errorf("data.restore_done rows = %d, want 1", n)
	}
}
