package host_test

import (
	"context"
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
	coreBefore := e.m.DB()
	r := e.ok(t, api.CmdBackupPurge, struct{}{})
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
