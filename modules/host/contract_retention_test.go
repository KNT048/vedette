package host_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// D-157 (WP-31 M4): backup retention never drops a backup something still needs, a backup that retention
// would drop at once fails the run, a missing backup is not retried for ever, and os.install waits for core.

func (e *updEnv) listed(t *testing.T) []string {
	t.Helper()
	bl, err := e.h.Client.StateBackups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range bl.Backups {
		ids = append(ids, b.BackupID)
	}
	return ids
}

func (e *updEnv) archive(id string) string { return filepath.Join(e.m.State, "backups", id+".tar.gz") }

// The exact WP-31 failure: an update to a release that says rollback.safe=false records its backup B1, three
// os.install runs follow, and container.rollback must still find B1.
func TestContract_Backup_RetentionKeepsTheBackupARollbackNeedsAfterThreeOSInstalls(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.installRules()
	var made []string
	for range 3 {
		e.clock.Advance(time.Minute)
		e.m.Mark("installed", false) // the fake machine has packages to install again
		res := result[api.OSRunResult](t, e.ok(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"}))
		if res.Backup == "" {
			t.Fatalf("os.install made no backup: %+v", res)
		}
		made = append(made, res.Backup)
	}
	ids := e.listed(t)
	if !slices.Contains(ids, c.backup) {
		t.Fatalf("B1 %s is gone from the index: %v", c.backup, ids)
	}
	if _, err := os.Stat(e.archive(c.backup)); err != nil {
		t.Fatalf("the archive of B1 is gone: %v", err)
	}
	// B1 does not use up the quota of the newest three pre_* backups, and nothing else is kept beyond them.
	if len(ids) != 4 {
		t.Fatalf("kept %d backups, want B1 and the three newest: %v", len(ids), ids)
	}
	for _, id := range made {
		if !slices.Contains(ids, id) {
			t.Fatalf("a recent backup %s was dropped: %v", id, ids)
		}
	}
	// A fourth install pushes the oldest unreferenced one out, B1 stays and the total stays bounded.
	e.clock.Advance(time.Minute)
	e.m.Mark("installed", false)
	e.ok(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"})
	if ids := e.listed(t); len(ids) != 4 || !slices.Contains(ids, c.backup) || slices.Contains(ids, made[0]) {
		t.Fatalf("after a fourth install: %v", ids)
	}
	if _, err := os.Stat(e.archive(made[0])); !os.IsNotExist(err) {
		t.Fatalf("the archive of the evicted backup is still there: %v", err)
	}
	e.m.ClearRules("systemctl") // installRules' "always active" must not hide the stateful unit from the rollback
	res := result[api.ContainerRollbackResult](t, e.rollback(t, "core"))
	if res.RestoredBackupID == nil || *res.RestoredBackupID != c.backup {
		t.Fatalf("%+v", res)
	}
	if e.m.DB() != "db: first" {
		t.Fatalf("db %q", e.m.DB())
	}
}

// What a transition journal points at is kept too (the revert after a failed or interrupted start).
func TestContract_Backup_RetentionKeepsTheBackupAJournalPointsAt(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.clock.Advance(time.Minute)
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "sensor"), e.render(t, "sensor", d1)
	// A journal of another service: core's journal would refuse backup.create (coreFree), this one does not.
	e.seedCrash(t, crashSeed{op: "start", svc: "sensor", phase: "pending", oldText: oldText, newText: newText, onDisk: oldText, version: v1, fromDigest: d1, toDigest: d1, backupID: bk.BackupID})
	for range 4 {
		e.clock.Advance(time.Minute)
		e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap()})
	}
	ids := e.listed(t)
	if !slices.Contains(ids, bk.BackupID) || len(ids) != 4 {
		t.Fatalf("the backup of the journal: %v", ids)
	}
	if _, err := os.Stat(e.archive(bk.BackupID)); err != nil {
		t.Fatal(err)
	}
	// With the journal gone nothing refers to it any more: the next backup lets it go.
	if err := os.Remove(e.m.TransitionPath("sensor")); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap()})
	if ids := e.listed(t); slices.Contains(ids, bk.BackupID) || len(ids) != 3 {
		t.Fatalf("after the journal went: %v", ids)
	}
}

// A clock stepped back makes the new backup the oldest: retention must not drop it and carry on as if it
// existed. The run fails, the archive is removed, the index is unchanged.
func TestContract_Backup_ARetentionThatWouldDropTheNewBackupFailsTheRun(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	for range 3 {
		e.clock.Advance(time.Minute)
		e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})
	}
	before := e.listed(t)
	e.clock.Advance(-2 * time.Hour)
	r := e.final(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}, api.StatusFailed, "backup_failed")
	if r.Error == nil {
		t.Fatalf("%+v", r)
	}
	if got := e.listed(t); !slices.Equal(got, before) {
		t.Fatalf("the index changed: %v -> %v", before, got)
	}
	ents, _ := os.ReadDir(filepath.Join(e.m.State, "backups"))
	if len(ents) != 3+1 { // three archives and index.json: the failed one left nothing
		t.Fatalf("%d files in backups/", len(ents))
	}
	for _, id := range before {
		if _, err := os.Stat(e.archive(id)); err != nil {
			t.Fatalf("an earlier backup was lost: %v", err)
		}
	}
	// With the clock right again the same call works.
	e.clock.Advance(3 * time.Hour)
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})
}

// A backup that the revert needs and that is not there (not in the index, or its archive gone) is not a
// failure to retry: the host marks core's data unrecoverable at once and does not stop core.
func TestContract_Update_ARevertWhoseBackupIsMissingIsUnrecoverableAndDoesNotStopCore(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"not in the index", "archive gone"} {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			e := startUpd(t)
			e.adopt(t, "core", rel1(d1, d1))
			e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
			bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
			oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
			e.m.WriteDB("db: migrated")
			id := bk.BackupID
			if how == "archive gone" {
				if err := os.Remove(e.archive(id)); err != nil {
					t.Fatal(err)
				}
			} else {
				id = strings.Repeat("c", 32)
			}
			e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: id, dbRevert: "backup"})
			n := len(e.ctl())
			rec := e.reboot(t) // returns: the loop did not go on for ever
			b, err := os.ReadFile(e.m.TransitionPath("core"))
			if err != nil || !strings.Contains(string(b), `"unrecoverable":true`) {
				t.Fatalf("%s %v", b, err)
			}
			if strings.Count(rec.text(), "core_data_unrecoverable") != 1 {
				t.Fatalf("notes %s", rec.text())
			}
			if slices.Contains(e.ctl()[n:], "stop vedette-core.service") {
				t.Fatalf("core was stopped for a revert that cannot work: %v", e.ctl()[n:])
			}
			if e.m.DB() != "db: migrated" {
				t.Fatalf("db %q", e.m.DB())
			}
			// Core's commands stay refused, and backup.restore is the way out (D-142).
			e.refused(t, api.CmdContainerStart, e.startArgs(api.ServiceCore, ""), 412, api.CodeTransitionPending)
		})
	}
}

// os.install makes a backup of core, so it waits like backup.create does while core's journal waits.
func TestContract_OSInstall_IsRefusedWhileCoresJournalIsPendingOrUnrecoverable(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.installRules()
	e.m.InstallUnit(api.ServiceCore, d1, true)
	e.m.SetRunning(api.ServiceCore, true)
	for _, unrecoverable := range []bool{false, true} {
		e.unrecoverable(t, unrecoverable)
		before := len(aptCalls(e.sysEnv))
		e.refused(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"}, 412, api.CodeTransitionPending)
		if got := len(aptCalls(e.sysEnv)); got != before {
			t.Fatalf("unrecoverable=%v: apt ran for a refused install (%d calls)", unrecoverable, got-before)
		}
		if ids := e.listed(t); len(ids) != 0 {
			t.Fatalf("unrecoverable=%v: a refused install made a backup: %v", unrecoverable, ids)
		}
	}
	if err := os.Remove(e.m.TransitionPath("core")); err != nil {
		t.Fatal(err)
	}
	if res := result[api.OSRunResult](t, e.ok(t, api.CmdOSInstall, api.OSInstallArgs{Snapshot: e.snap(), Scope: "all"})); res.Backup == "" {
		t.Fatalf("%+v", res)
	}
}
