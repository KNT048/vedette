package host_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// D-156: backup.purge deletes every archive of every kind and the index, and nothing else.
func TestContract_BackupPurge_DeletesEveryArchiveAndTheIndexAndFollowsNoLink(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	for _, kind := range []string{"manual", "pre_update", "pre_os_update", "pre_restore"} {
		e.clock.Advance(time.Minute)
		e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: kind, Snapshot: e.snap()})
	}
	dir := filepath.Join(e.m.State, "backups")
	// A link planted in the store, one with an archive name and one with another name: neither is
	// followed (the target outside survives) and neither is a regular file the host wrote.
	outside := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strings.Repeat("c", 32) + ".tar.gz", "link"} {
		if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// The host's own leftovers: a writeFileAtomic temp in the store, an export with its index, a temp
	// file of an export and temp directories of runs, plus a link with a temp name that must stay.
	state := e.m.State
	plant := func(rel, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(state, rel)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, rel), []byte(content), 0o600); err != nil { //nolint:gosec // a fixed relative name in the test's temp state
			t.Fatal(err)
		}
	}
	plant("backups/.tmp-123", "x")
	plant("exports/index.json", `{"exports":[]}`)
	plant("exports/"+strings.Repeat("d", 32)+".jsonl.gz", "x")
	plant("tmp/ex-777", "x")
	plant("tmp/bk-1/archive.tar.gz", "x")
	plant("tmp/rs-2/sub/vedette.db", "x")
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(state, "tmp", "rb-3")); err != nil {
		t.Fatal(err)
	}
	coreBefore := e.m.DB()
	keyBefore, _ := os.ReadFile(filepath.Join(e.m.CoreData, "vedette.key"))
	snapsBefore, _ := os.ReadDir(filepath.Join(e.m.CoreData, "snapshots"))
	r := e.ok(t, api.CmdBackupPurge, struct{}{})
	for _, rel := range []string{"backups/.tmp-123", "exports/index.json", "exports/" + strings.Repeat("d", 32) + ".jsonl.gz", "tmp/ex-777", "tmp/bk-1", "tmp/rs-2"} {
		if _, err := os.Lstat(filepath.Join(state, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there (%v)", rel, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(state, "tmp", "rb-3")); err != nil {
		t.Errorf("a link named like a temp directory was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(outside))); err != nil {
		t.Fatalf("the link target is gone: %v", err)
	}
	if key, _ := os.ReadFile(filepath.Join(e.m.CoreData, "vedette.key")); string(key) != string(keyBefore) || len(keyBefore) == 0 {
		t.Error("core's key was touched")
	}
	if snaps, _ := os.ReadDir(filepath.Join(e.m.CoreData, "snapshots")); len(snaps) != len(snapsBefore) || len(snaps) == 0 {
		t.Errorf("core's snapshots/ changed: %d -> %d", len(snapsBefore), len(snaps))
	}
	if res := result[api.BackupPurgeResult](t, r); res.Deleted != 4 {
		t.Fatalf("deleted %d", res.Deleted)
	}
	ents, _ := os.ReadDir(dir)
	for _, x := range ents {
		if x.Type().IsRegular() {
			t.Errorf("a regular file is left: %s", x.Name())
		}
	}
	if len(ents) != 2 {
		t.Errorf("left %d entries, want the two planted links", len(ents))
	}
	b, err := os.ReadFile(outside) //nolint:gosec // a temp file of this test
	if err != nil || string(b) != "keep" {
		t.Fatalf("a link was followed: %q %v", b, err)
	}
	bl, err := e.h.Client.StateBackups(context.Background())
	if err != nil || len(bl.Backups) != 0 {
		t.Fatalf("listing %+v %v", bl, err)
	}
	if e.m.DB() != coreBefore {
		t.Fatal("core_data was touched")
	}
	if n := e.notes(t, "backups_purged"); len(n) != 1 || n[0]["deleted"] != float64(4) {
		t.Fatalf("notes %v", n)
	}
	// Purging an empty store is a success with zero; the store itself stays usable: os.install's
	// internal pre_os_update backup is the same code path as backup.create.
	if res := result[api.BackupPurgeResult](t, e.ok(t, api.CmdBackupPurge, struct{}{})); res.Deleted != 0 {
		t.Fatalf("second purge deleted %d", res.Deleted)
	}
	e.clock.Advance(time.Minute)
	res := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap()}))
	if bl, _ := e.h.Client.StateBackups(context.Background()); len(bl.Backups) != 1 || bl.Backups[0].BackupID != res.BackupID {
		t.Fatalf("listing after a new backup %+v", bl)
	}
}

func TestContract_BackupPurge_WithoutAStoreDirectoryIsZero(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	if err := os.RemoveAll(filepath.Join(e.m.State, "backups")); err != nil {
		t.Fatal(err)
	}
	if res := result[api.BackupPurgeResult](t, e.ok(t, api.CmdBackupPurge, struct{}{})); res.Deleted != 0 {
		t.Fatalf("deleted %d", res.Deleted)
	}
}

func TestContract_BackupPurge_TakesNoArgsAndIsBusyDuringARun(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.CoreWait = 600 * time.Millisecond })
	e.refused(t, api.CmdBackupPurge, map[string]any{"backup_id": strings.Repeat("a", 32)}, http.StatusBadRequest, "invalid_args")
	b := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"}))
	// A restore of an unhealthy core runs for a while (see INV-3): a purge then is busy and deletes nothing.
	e.m.Rule("systemctl", "stop", "", 0, "", "stopped")
	e.m.Rule("systemctl", "is-active", "inactive.txt", 3, "stopped", "")
	e.m.Rule("systemctl", "is-active", "active.txt", 0, "", "")
	run, err := e.h.Client.Run(context.Background(), api.CmdBackupRestore, api.BackupRestoreArgs{Snapshot: e.snap(), BackupID: b.BackupID}, e.id(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	st, body := rawReq(t, e.h, "/v1/commands/backup.purge", hdr("77777777-7777-4777-8777-777777777777"), `{"args":{}}`)
	if st != http.StatusConflict || errCode(body) != api.CodeBusy {
		t.Fatalf("a purge during a restore: %d %s", st, body)
	}
	waitDone(t, e.h.Client, run.RunID)
	if _, err := os.Stat(filepath.Join(e.m.State, "backups", b.BackupID+".tar.gz")); err != nil {
		t.Fatalf("a refused purge deleted the archive: %v", err)
	}
}

// After a purge, the rollback of an unsafe core release has no pre_update backup to restore: it
// refuses with rollback_backup_missing and touches nothing (D-138, D-156).
func TestContract_BackupPurge_ThenAnUnsafeCoreRollbackRefusesWithBackupMissing(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.ok(t, api.CmdBackupPurge, struct{}{})
	before := e.unit(t, "core")
	e.forget()
	e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeRollbackBackupMissing)
	e.untouched(t, "gone", "core", before)
	if e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatal("the database was touched")
	}
}

// A core transition that is pending, or that the host gave up on (unrecoverable), may still need a
// backup: purge refuses at Check, like backup.create, and every archive survives (H1).
func TestContract_BackupPurge_RefusesWhileCoreHasATransitionJournal(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit(api.ServiceCore, d1, true)
	e.m.SetRunning(api.ServiceCore, true)
	var ids []string
	for _, kind := range []string{"manual", "pre_update"} {
		e.clock.Advance(time.Minute)
		ids = append(ids, result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: kind, Snapshot: e.snap()})).BackupID)
	}
	for _, unrecoverable := range []bool{false, true} {
		e.unrecoverable(t, unrecoverable)
		e.refused(t, api.CmdBackupPurge, struct{}{}, 412, api.CodeTransitionPending)
		for _, id := range ids {
			if _, err := os.Stat(filepath.Join(e.m.State, "backups", id+".tar.gz")); err != nil {
				t.Fatalf("unrecoverable=%v: a refused purge deleted %s: %v", unrecoverable, id, err)
			}
		}
		if bl, err := e.h.Client.StateBackups(context.Background()); err != nil || len(bl.Backups) != 2 {
			t.Fatalf("unrecoverable=%v: listing %+v %v", unrecoverable, bl, err)
		}
	}
	if err := os.Remove(e.m.TransitionPath("core")); err != nil {
		t.Fatal(err)
	}
	if res := result[api.BackupPurgeResult](t, e.ok(t, api.CmdBackupPurge, struct{}{})); res.Deleted != 2 {
		t.Fatalf("deleted %d once the journal was gone", res.Deleted)
	}
}

// A crash after the index went and before the archives did leaves orphans, never an index entry
// without its file; the host's start-up sweep removes them.
func TestContract_BackupPurge_ACrashAfterTheIndexLeavesOrphansThatStartUpRemoves(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	var ids []string
	for _, kind := range []string{"manual", "pre_os_update"} {
		e.clock.Advance(time.Minute)
		ids = append(ids, result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: kind, Snapshot: e.snap()})).BackupID)
	}
	if err := os.Remove(filepath.Join(e.m.State, "backups", "index.json")); err != nil {
		t.Fatal(err)
	}
	if bl, err := e.h.Client.StateBackups(context.Background()); err != nil || len(bl.Backups) != 0 {
		t.Fatalf("an index without entries must list nothing: %+v %v", bl, err)
	}
	e.o.Start(context.Background(), e.h.Server) // what the host does at start: sweepBackups
	t.Cleanup(e.o.Close)
	for _, id := range ids {
		if _, err := os.Stat(filepath.Join(e.m.State, "backups", id+".tar.gz")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("orphan %s is still there (%v)", id, err)
		}
	}
}

// os.install after a purge still makes its own pre_os_update backup.
func TestContract_BackupPurge_ThenOSInstallStillMakesItsBackup(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.installRules()
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "manual", Snapshot: e.snap()})
	e.ok(t, api.CmdBackupPurge, struct{}{})
	res := result[api.OSRunResult](t, e.ok(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"}))
	bl, err := e.h.Client.StateBackups(context.Background())
	if err != nil || len(bl.Backups) != 1 || bl.Backups[0].BackupID != res.Backup || bl.Backups[0].Kind != "pre_os_update" {
		t.Fatalf("backups %+v %v", bl, err)
	}
}
