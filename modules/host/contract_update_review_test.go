package host_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// Tests that came out of the independent review of slice 3-8a (D-138 amended: H1 is in contract_update_test.go
// next to the rollback tests; H2, M1, M2, M4, L3 are here).

// H2: core controls the names next to its database. A directory or a symlink planted where the host keeps a
// file it moved aside must never make the host walk (RemoveAll), hang, or delete anything but a regular file.
func TestContract_Update_AThingThatIsNotAFilePlantedAtAnAsideNameIsNeverWalkedOrRemoved(t *testing.T) {
	t.Parallel()
	t.Run("a directory at the aside name stops a rollback before anything moves", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		dir := filepath.Join(e.m.CoreData, "vedette.db.rollback")
		if err := os.MkdirAll(filepath.Join(dir, "deep"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "deep", "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusReverted, api.CodeUnitFailed)
		if e.m.DB() != "db: migrated, plus data written since the update" {
			t.Fatalf("db %q", e.m.DB())
		}
		planted := filepath.Join(dir, "deep", "x")
		if b, err := os.ReadFile(planted); err != nil || string(b) != "x" { //nolint:gosec // test: the file the test planted
			t.Fatalf("the planted directory was walked or removed: %q %v", b, err)
		}
		if e.unit(t, "core") != c.upgraded {
			t.Fatal("the running unit is not back")
		}
	})
	t.Run("a symlink at the aside name is not followed and its target is not touched", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("not core's"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(e.m.CoreData, "vedette.db.rollback")); err != nil {
			t.Fatal(err)
		}
		e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusReverted, api.CodeUnitFailed)
		if b, _ := os.ReadFile(victim); string(b) != "not core's" { //nolint:gosec // test: the victim file the test made
			t.Fatalf("the target of a planted link was changed: %q", b)
		}
	})
	t.Run("dropping the files moved aside leaves a directory alone and does not hang", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
		dir := filepath.Join(e.m.CoreData, "vedette.db.rollback")
		if err := os.MkdirAll(filepath.Join(dir, "deep"), 0o700); err != nil {
			t.Fatal(err)
		}
		e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "verified", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1,
			backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}, applied: true})
		e.reboot(t)
		if _, err := os.Stat(filepath.Join(dir, "deep")); err != nil {
			t.Fatalf("the planted directory was removed: %v", err)
		}
		if e.journal("core") {
			t.Fatal("the journal stayed")
		}
		if v, p := e.versions(t, "core"); v != v1 || p != v2 {
			t.Fatalf("%q %q", v, p)
		}
	})
}

// M1: only the names the journal lists are put back, so a stale aside file of an earlier run can never replace
// the database; and a new rollback clears every stale aside before it moves anything.
func TestContract_Update_OnlyTheJournaledNamesAreMovedAndPutBackAndStaleAsidesAreCleared(t *testing.T) {
	t.Parallel()
	t.Run("a stale aside and a crash before any move put nothing back", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		stale := filepath.Join(e.m.CoreData, "vedette.db.rollback")
		if err := os.WriteFile(stale, []byte("db: stale, from an earlier run"), 0o600); err != nil {
			t.Fatal(err)
		}
		oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
		// The host died after journaling an empty plan (nothing existed to move) and before any move.
		e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: oldText, onDisk: oldText, version: v1, fromDigest: d2, toDigest: d1, backupID: c.backup, dbRevert: "aside"})
		_ = newText
		e.reboot(t)
		if e.m.DB() != "db: migrated, plus data written since the update" {
			t.Fatalf("a stale aside file replaced the database: %q", e.m.DB())
		}
	})
	t.Run("a new rollback clears the stale asides first and restores the right database", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		for _, n := range []string{"vedette.db.rollback", "vedette.db-wal.rollback", "vedette.key.rollback"} {
			if err := os.WriteFile(filepath.Join(e.m.CoreData, n), []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		e.rollback(t, "core")
		if e.m.DB() != "db: first" {
			t.Fatalf("db %q", e.m.DB())
		}
		if a := asides(t, e); len(a) != 0 {
			t.Fatalf("aside files left: %v", a)
		}
	})
	t.Run("the journal names exactly what moved", func(t *testing.T) {
		t.Parallel()
		c := setupCoreUnsafe(t)
		e := c.e
		// Make the restart fail so the run ends with its journal pending, and read the journal.
		e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1")
		e.m.Rule("systemctl", "restart", "", 1, "r1", "")
		e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusFailed, api.CodeRollbackRevertFailed)
		b, err := os.ReadFile(e.m.TransitionPath("core"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"aside":["vedette.db","vedette.key"]`) {
			t.Fatalf("%s", b)
		}
	})
}

// M2: while core's database waits to be put back, every other write command is refused, and the host does not
// give up on putting it back.
func TestContract_Update_WhileADatabaseWaitsToBePutBackEveryWriteIsRefusedAndTheHostDoesNotGiveUp(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
	e.m.WriteDB("db: migrated")
	e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: bk.BackupID, dbRevert: "backup"})
	e.m.Rule("systemctl", "stop", "", 1, "!s1", "s1") // the first two tries to stop core fail
	e.m.Rule("systemctl", "stop", "", 1, "!s2", "s2")
	o2 := e.m.Ops(e.clock.Now, e.muts...)
	o2.Start(context.Background(), &noteRecorder{})
	t.Cleanup(o2.Close)

	// Before the database is back: a command for another service, a backup, a command for core itself.
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Restart: true}, 412, api.CodeTransitionPending)
	e.refused(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "manual", Snapshot: e.snap()}, 412, api.CodeTransitionPending)
	e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeTransitionPending)

	o2.AfterReady(context.Background(), e.h.Server) // returns only once the database is back
	if e.m.DB() != "db: first" || e.journal("core") {
		t.Fatalf("db %q journal %t", e.m.DB(), e.journal("core"))
	}
	stops := 0
	for _, c := range e.ctl() {
		if c == "stop vedette-core.service" {
			stops++
		}
	}
	if stops < 3 {
		t.Fatalf("the host stopped trying after %d stops", stops)
	}
	// And the gate is lifted.
	e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Restart: true})
}

// M4: fail closed when the running version is not recorded.
func TestContract_Update_ASwitchOfAServiceWhoseRunningVersionIsUnknownIsRefusedWithNoWrite(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.m.InstallUnit("sensor", d1, true) // as a bootstrap that wrote no version record leaves it
	e.m.SetRunning("sensor", true)
	e.m.PresentImage("sensor", d1, v1)
	e.pullRel(t, "sensor", rel2(d2, d2))
	before := e.unit(t, "sensor")
	e.forget()
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Version: v2}, 412, api.CodeCurrentVersionUnknown)
	e.untouched(t, "unknown running version", "sensor", before)
	// Starting the version that runs records it; then the switch is allowed.
	e.pullRel(t, "sensor", rel1(d1, d1))
	e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Version: v1})
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Version: v2})
}

// L3: a switch that worked but whose journal cannot be written is not undone and settles nothing.
func TestContract_Update_ASwitchThatWorkedButCannotBeJournaledSettlesNothingAndIsNotReverted(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(e.m.State, "containers"), 0o700) }) //nolint:gosec // test cleanup
	e.m.Mark("lock-containers", true)                                                 // the fake restart makes containers/ read-only: the verified journal cannot be written
	n0 := e.restarts("sensor")
	e.final(t, api.CmdContainerStart, e.startArgs("sensor", v2), api.StatusFailed, api.CodeUnitUnwritable)
	if e.restarts("sensor")-n0 != 1 {
		t.Fatalf("the good switch was reverted: %d restarts", e.restarts("sensor")-n0)
	}
	if e.unit(t, "sensor") != e.render(t, "sensor", d2) {
		t.Fatal("the unit is not the new one")
	}
	if err := os.Chmod(filepath.Join(e.m.State, "containers"), 0o700); err != nil { //nolint:gosec // test: let the checks read
		t.Fatal(err)
	}
	vs, err := os.ReadFile(filepath.Join(e.m.State, "containers", "versions-sensor.json"))
	if err != nil || !strings.Contains(string(vs), `"version":"1.0.0"`) || strings.Contains(string(vs), `"version":"2.0.0"`) {
		t.Fatalf("versions were recorded without a durable journal: %s %v", vs, err)
	}
	if len(e.m.ImageRemoved()) != 0 {
		t.Fatal("retention ran")
	}
}
