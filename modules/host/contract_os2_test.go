package host_test

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/server"
)

// TestHelperHoldLock is not a test: the lock tests start this binary again through core/exec (the
// only way tests may start a process) so that another process holds a POSIX lock, which is how
// apt and dpkg hold theirs. Without the two arguments after "--" it does nothing.
func TestHelperHoldLock(t *testing.T) {
	if flag.NArg() != 2 {
		t.Skip("helper process only")
	}
	lockPath, releasePath := flag.Arg(0), flag.Arg(1)
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0) //nolint:gosec // the helper process locks the path the test gave it
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath+".ready", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(releasePath); err == nil {
			return
		}
		select {
		case <-deadline.C:
			return
		case <-tick.C:
		}
	}
}

// holdLock starts the helper process holding a lock on path and returns a function that releases it.
func holdLock(t *testing.T, path string) (release func()) {
	t.Helper()
	dir := t.TempDir()
	releasePath := filepath.Join(dir, "release")
	r, err := vexec.NewRunner(slog.New(slog.DiscardHandler), vexec.Binary{
		Name: "helper", Path: os.Args[0], Validate: func([]string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = r.Run(ctx, "helper", []string{"-test.run=^TestHelperHoldLock$", "--", path, releasePath}, nil)
	}()
	eventually(t, "the helper to take the lock", func() bool {
		_, err := os.Stat(releasePath + ".ready")
		return err == nil
	})
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = os.WriteFile(releasePath, nil, 0o600)
			wg.Wait()
			cancel()
		})
	}
	t.Cleanup(release)
	return release
}

func TestContract_OSCheck_TheRealLockProbeSeesAnotherProcessWithoutTakingTheLock(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.LockHeld = nil }) // the real fcntl probe
	e.rules()
	lock := filepath.Join(e.m.Root, "var/lib/dpkg/lock-frontend")

	// Nobody holds it: the check runs.
	e.ok(t, "os.check", nil)

	release := holdLock(t, lock)
	ce := e.refusedWith(t, "os.check", nil, http.StatusConflict, "dpkg_locked")
	if ce.RetryAfterS != 60 {
		t.Errorf("retry hint = %d", ce.RetryAfterS)
	}
	// Probing did not take the lock: the holder still has it, and once it lets go the check runs.
	release()
	before := len(e.m.Calls("apt-get"))
	e.ok(t, "os.check", nil)
	if len(e.m.Calls("apt-get")) <= before {
		t.Error("the check did not run after the lock was released")
	}
	// Every one of the four lock files is probed.
	for _, rel := range []string{"var/lib/dpkg/lock", "var/lib/apt/lists/lock", "var/cache/apt/archives/lock"} {
		releaseOther := holdLock(t, filepath.Join(e.m.Root, rel))
		e.refused(t, "os.check", nil, http.StatusConflict, "dpkg_locked")
		releaseOther()
	}
	// A missing lock file means nobody holds it.
	_ = os.Remove(lock)
	e.ok(t, "os.check", nil)
}

// --- interrupted restore ---------------------------------------------------------------------------

type noteRecorder struct {
	mu    sync.Mutex
	notes []string
}

func (n *noteRecorder) Note(command, code string, detail map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	b, _ := json.Marshal(detail)
	n.notes = append(n.notes, command+" "+code+" "+string(b))
	return nil
}

func (n *noteRecorder) WriteActive() bool { return false }

func (n *noteRecorder) AwaitingConfirm() bool { return false }

func (n *noteRecorder) Claim(string) (*server.Claimed, error) { return nil, server.ErrNotAwaiting }

func (n *noteRecorder) text() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(n.notes, "\n")
}

func TestContract_Restore_ACutShortRestoreIsPutBackAtStart(t *testing.T) {
	t.Parallel()
	for _, coreRunning := range []bool{false, true} {
		name := map[bool]string{false: "core stopped: previous state is put back", true: "core running: nothing is touched"}[coreRunning]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startSys(t)
			e.restoreRules()
			// The state the host was in before it died: pre_restore holds "first", the live database is half replaced.
			pre := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Snapshot: e.snap(), Kind: "pre_restore", IncludeSecrets: true}))
			e.m.WriteDB("db: half-restored")
			marker, _ := json.Marshal(map[string]any{"pre_restore_backup_id": pre.BackupID, "backup_id": strings.Repeat("a", 32), "started_at": e.clock.Now()})
			if err := os.WriteFile(filepath.Join(e.m.State, "restore.json"), marker, 0o600); err != nil {
				t.Fatal(err)
			}
			if !coreRunning {
				e.m.Mark("stopped", true) // is-active answers inactive until a start
			}
			rec := &noteRecorder{}
			o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = (&fakeTimers{}).after })
			o2.Start(context.Background(), rec)
			defer o2.Close()
			if _, err := os.Stat(filepath.Join(e.m.State, "restore.json")); err == nil {
				t.Error("the marker is still there")
			}
			notes := e.m.DB()
			if coreRunning {
				if notes != "db: half-restored" || !strings.Contains(rec.text(), `"action":"none"`) {
					t.Fatalf("database %q, audit %s", notes, rec.text())
				}
				return
			}
			if notes != "db: first" || !strings.Contains(rec.text(), "restore_interrupted") || !strings.Contains(rec.text(), `"action":"reverted"`) {
				t.Fatalf("database %q, audit %s", notes, rec.text())
			}
			if !slices.Contains(systemctlVerbs(e), "start") {
				t.Error("core was not started again")
			}
		})
	}
}

func TestContract_Backup_StartupRemovesOrphansAndTempFiles(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	keep := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"}))
	orphan := filepath.Join(e.m.State, "backups", strings.Repeat("e", 32)+".tar.gz")
	if err := os.WriteFile(orphan, []byte("a crash left this"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(e.m.State, "tmp", "bk-leftover")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = (&fakeTimers{}).after })
	o2.Start(context.Background(), &noteRecorder{})
	defer o2.Close()
	if _, err := os.Stat(orphan); err == nil {
		t.Error("an archive that is not in the index survived start-up")
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Error("a temp directory survived start-up")
	}
	if _, err := os.Stat(filepath.Join(e.m.State, "backups", keep.BackupID+".tar.gz")); err != nil {
		t.Error("an indexed backup was removed")
	}
}

func TestContract_Restore_RunIsDurableAcrossAClientRestart(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.restoreRules()
	b1 := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual", IncludeSecrets: true}))
	snapID := e.snap()
	run, err := e.h.Client.Run(context.Background(), "backup.restore", api.BackupRestoreArgs{Snapshot: snapID, BackupID: b1.BackupID}, e.id(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	// core is stopped by the restore, so its connection goes away: a brand-new client (a fresh
	// connection pool, as core has after it starts again) asks for the run by id.
	c2 := e.h.NewClient(t)
	e.h.Client.Close()
	eventually(t, "the run to end", func() bool {
		r, err := c2.GetRun(context.Background(), run.RunID)
		return err == nil && r.Status == api.StatusSucceeded
	})
	got, _ := c2.GetRun(context.Background(), run.RunID)
	if res := result[api.BackupRestoreResult](t, got); res.RestoredBackupID != b1.BackupID {
		t.Fatalf("%+v", res)
	}
	// The same request id after the restart is the same run, not a second restore.
	again, err := c2.Run(context.Background(), "backup.restore", api.BackupRestoreArgs{Snapshot: snapID, BackupID: b1.BackupID}, run.RequestID, "admin")
	if err != nil || again.RunID != run.RunID {
		t.Fatalf("replay: %+v %v", again, err)
	}
	if n := strings.Count(strings.Join(systemctlVerbs(e), ","), "stop"); n != 1 {
		t.Errorf("core was stopped %d times", n)
	}
}

// Writes are one at a time across the new commands too: a second write while one runs is busy.
func TestContract_INV3_SystemWritesAreOneAtATime(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.CoreWait = 600 * time.Millisecond })
	b := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"}))
	// Core never comes back, so the restore waits for it (then reverts): long enough to try a second write.
	e.m.Rule("systemctl", "stop", "", 0, "", "stopped")
	e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "stopped", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	run, err := e.h.Client.Run(context.Background(), "backup.restore", api.BackupRestoreArgs{Snapshot: e.snap(), BackupID: b.BackupID}, e.id(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	st, body := rawReq(t, e.h, "/v1/commands/os.reboot", hdr("77777777-7777-4777-8777-777777777777"), `{"args":{"when":"now"}}`)
	if st != http.StatusConflict || errCode(body) != api.CodeBusy {
		t.Fatalf("a write during a restore: %d %s", st, body)
	}
	var eb api.ErrorBody
	_ = json.Unmarshal(body, &eb)
	if eb.Error.RunID != run.RunID {
		t.Errorf("busy names run %q, want %q", eb.Error.RunID, run.RunID)
	}
	if r := waitDone(t, e.h.Client, run.RunID); r.Status == api.StatusSucceeded {
		t.Errorf("the restore of an unhealthy core succeeded: %+v", r)
	}
	if rebootCalls(e) != 0 {
		t.Error("the refused reboot ran")
	}
}
