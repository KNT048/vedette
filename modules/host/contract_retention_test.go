package host_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// D-157 (WP-31 M4): backup retention never drops a backup something still needs and always keeps the one
// just made, a missing or corrupt backup is not retried for ever (and an I/O error is), and os.install waits
// for core.

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

// coreJournal writes core's transition journal as an interrupted update leaves it, pointing at backupID.
func (e *updEnv) coreJournal(t *testing.T, backupID string, unrecoverable bool) {
	t.Helper()
	sha := strings.Repeat("a", 64)
	j := map[string]any{
		"service": "core", "op": "start", "phase": "pending", "digest": d1, "prev_sha256": sha, "new_sha256": sha,
		"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "", "unrecoverable": unrecoverable, "db_revert": "backup", "backup_id": backupID,
	}
	b, _ := json.Marshal(j)
	if err := os.WriteFile(e.m.TransitionPath("core"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

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

// The backup of core's journal is kept too (the revert after a failed or interrupted start). The realistic
// case: the journal says unrecoverable, the person runs backup.restore (D-142), and the pre_restore backup that
// restore makes must not push the journal's backup out.
func TestContract_Backup_RetentionKeepsTheBackupOfCoresJournalWhileBackupRestoreRuns(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit(api.ServiceCore, d1, true)
	e.m.SetRunning(api.ServiceCore, true)
	e.m.WriteDB("db: good")
	mk := func(kind string, secrets bool) string {
		e.clock.Advance(time.Minute)
		return result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: kind, Snapshot: e.snap(), IncludeSecrets: secrets})).BackupID
	}
	manual := mk("manual", true)
	p := mk("pre_update", true) // the journal's backup, the oldest pre_*
	mk("pre_os_update", false)
	mk("pre_os_update", false)
	e.coreJournal(t, p, true)
	e.clock.Advance(time.Minute)
	e.ok(t, api.CmdBackupRestore, api.BackupRestoreArgs{BackupID: manual, Snapshot: e.snap()}) // makes a pre_restore: the fourth pre_*
	if ids := e.listed(t); !slices.Contains(ids, p) {
		t.Fatalf("the backup of the journal was evicted by the pre_restore backup: %v", ids)
	}
	if _, err := os.Stat(e.archive(p)); err != nil {
		t.Fatal(err)
	}
	if e.journal("core") {
		t.Fatal("the journal is still there after the restore")
	}
	// Nothing refers to it any more: the next backup lets it go.
	mk("pre_os_update", false)
	if ids := e.listed(t); slices.Contains(ids, p) {
		t.Fatalf("an unreferenced backup stayed: %v", ids)
	}
}

// A clock stepped back makes a new backup look the oldest. It is still the one the run just made and that the
// update or restore depends on: it is kept, and the oldest OTHER unreferenced pre_* backup ages out. Refusing it
// would stop every pre_* backup, backup.restore (the way out of core_data_unrecoverable) included.
func TestContract_Backup_ASteppedBackClockKeepsTheNewBackupAndDropsTheOldestOther(t *testing.T) {
	t.Parallel()
	t.Run("backup.create", func(t *testing.T) {
		t.Parallel()
		e := startUpd(t)
		var first []string
		for range 3 {
			e.clock.Advance(time.Minute)
			first = append(first, result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})).BackupID)
		}
		e.clock.Advance(-2 * time.Hour)
		nb := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})).BackupID
		ids := e.listed(t)
		if len(ids) != 3 || !slices.Contains(ids, nb) {
			t.Fatalf("the new backup is not kept, or too many are: %v (new %s)", ids, nb)
		}
		// Of the three earlier ones (oldest first in first) the oldest went, by its own age.
		if slices.Contains(ids, first[0]) || !slices.Contains(ids, first[1]) || !slices.Contains(ids, first[2]) {
			t.Fatalf("kept %v of %v", ids, first)
		}
		if _, err := os.Stat(e.archive(nb)); err != nil {
			t.Fatalf("the archive of the new backup: %v", err)
		}
		if _, err := os.Stat(e.archive(first[0])); !os.IsNotExist(err) {
			t.Fatalf("the evicted archive is still there: %v", err)
		}
	})
	t.Run("container.start of core", func(t *testing.T) {
		t.Parallel()
		e := startUpd(t)
		e.adopt(t, "core", rel1(d1, d1))
		e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
		for range 3 {
			e.clock.Advance(time.Minute)
			e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap(), IncludeSecrets: true})
		}
		e.clock.Advance(-2 * time.Hour)
		res := result[api.ContainerStartResult](t, e.ok(t, api.CmdContainerStart, e.startArgs("core", v2)))
		if res.BackupID == nil || !slices.Contains(e.listed(t), *res.BackupID) {
			t.Fatalf("the pre_update backup of the switch is not in the index: %+v %v", res, e.listed(t))
		}
		if _, err := os.Stat(e.archive(*res.BackupID)); err != nil {
			t.Fatal(err)
		}
		if v, _ := e.versions(t, "core"); v != v2 {
			t.Fatalf("version %q", v)
		}
	})
}

// If what needs a backup cannot be read, every pre_update backup is kept (only those are ever referenced) and the
// other kinds age out as usual, so the store stays bounded; one audit line says so.
func TestContract_Backup_RetentionKeepsEveryPreUpdateButAgesTheRestWhenAVersionsFileCannotBeRead(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	if err := os.WriteFile(filepath.Join(e.m.State, "containers", "versions-core.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var pu []string
	for range 5 {
		e.clock.Advance(time.Minute)
		pu = append(pu, result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true})).BackupID)
	}
	for range 5 {
		e.clock.Advance(time.Minute)
		e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap()})
	}
	ids := e.listed(t)
	if len(ids) != 5+3 {
		t.Fatalf("%d backups kept, want the 5 pre_update and 3 pre_os_update: %v", len(ids), ids)
	}
	for _, id := range pu {
		if !slices.Contains(ids, id) {
			t.Fatalf("a pre_update backup was dropped: %s", id)
		}
	}
	if n := e.notes(t, "backup_retention_unknown"); len(n) != 1 {
		t.Fatalf("audit lines: %v", n)
	}
	// Once the file is readable again retention works as before.
	if err := os.Remove(filepath.Join(e.m.State, "containers", "versions-core.json")); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_os_update", Snapshot: e.snap()})
	if ids := e.listed(t); len(ids) != 3 {
		t.Fatalf("%d backups kept, want 3: %v", len(ids), ids)
	}
}

// revertCrash seeds an interrupted core update whose revert needs the pre_update backup, with the backup as it
// is after prepare changed it, and returns the audit recorder of the restarted host.
func revertCrash(t *testing.T, prepare func(e *updEnv, id string) string) (*updEnv, *noteRecorder, int) {
	t.Helper()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
	e.m.WriteDB("db: migrated")
	id := prepare(e, bk.BackupID)
	e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: id, dbRevert: "backup"})
	n := len(e.ctl())
	return e, e.reboot(t), n // reboot returns: the loop did not go on for ever
}

// A backup that the revert needs and that is not there (not in the index, or its archive gone), or is there but
// is not the backup the index describes (corrupt, truncated), is not a failure to retry: the host marks core's
// data unrecoverable at once and does not stop core.
func TestContract_Update_ARevertWhoseBackupIsMissingOrCorruptIsUnrecoverableAndDoesNotStopCore(t *testing.T) {
	t.Parallel()
	for name, prepare := range map[string]func(e *updEnv, id string) string{
		"not in the index": func(_ *updEnv, _ string) string { return strings.Repeat("c", 32) },
		"archive gone": func(e *updEnv, id string) string {
			if err := os.Remove(e.archive(id)); err != nil {
				panic(err)
			}
			return id
		},
		"archive corrupt": func(e *updEnv, id string) string {
			f, err := os.OpenFile(e.archive(id), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				panic(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("garbage"); err != nil {
				panic(err)
			}
			return id
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, rec, n := revertCrash(t, prepare)
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
			e.refused(t, api.CmdContainerStart, e.startArgs(api.ServiceCore, ""), 412, api.CodeTransitionPending)
		})
	}
}

// An index that cannot be read is not "the backup is gone": the host does not give up, it tries again.
func TestContract_Update_ARevertThatCannotReadTheBackupIndexIsRetriedNotGivenUpOn(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
	e.m.WriteDB("db: migrated")
	e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: bk.BackupID, dbRevert: "backup"})
	index := filepath.Join(e.m.State, "backups", "index.json")
	good, err := os.ReadFile(index) //nolint:gosec // the test's own state
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := len(e.ctl())
	o2 := e.m.Ops(e.clock.Now, e.muts...)
	rec := &noteRecorder{}
	o2.Start(context.Background(), rec)
	t.Cleanup(o2.Close)
	e.m.Mark("host-starting", false)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	o2.AfterReady(ctx, e.h.Server) // the loop keeps trying until its context ends
	if _, n := e.sleeps.get(); n < 1 {
		t.Fatal("the loop did not wait and try again")
	}
	b, err := os.ReadFile(e.m.TransitionPath("core"))
	if err != nil || strings.Contains(string(b), `"unrecoverable"`) || strings.Contains(rec.text(), "core_data_unrecoverable") {
		t.Fatalf("an unreadable index was taken as a missing backup:\n%s\n%s %v", b, rec.text(), err)
	}
	if slices.Contains(e.ctl()[n:], "stop vedette-core.service") {
		t.Fatal("core was stopped although the backup could not be checked")
	}
	// The index is readable again: the next try puts the database back.
	if err := os.WriteFile(index, good, 0o600); err != nil { //nolint:gosec // the test's own state directory
		t.Fatal(err)
	}
	o2.AfterReady(context.Background(), e.h.Server)
	if e.m.DB() != "db: first" || e.journal("core") {
		t.Fatalf("db %q journal %t", e.m.DB(), e.journal("core"))
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
