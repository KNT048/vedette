package host_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// Tests that came out of the independent review of slice 3-8a (D-138 amended: H1 is in contract_update_test.go
// next to the rollback tests; H2, M1, M2, M4, L3 are here).

// H2: core controls the names next to its database. A directory or a symlink planted where the host keeps a
// file it moved aside must never make the host walk (RemoveAll), hang, or delete anything but a regular file.
func TestContract_Update_AThingThatIsNotAFilePlantedAtAnAsideNameIsNeverWalkedOrRemoved(t *testing.T) {
	t.Parallel()
	t.Run("a directory at the aside name is refused before core is stopped", func(t *testing.T) {
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
		e.forget()
		e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeCoreDataInvalid)
		if slices.Contains(e.ctl(), "stop vedette-core.service") {
			t.Fatal("core was stopped for a rollback that was refused")
		}
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
		e.refused(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, 412, api.CodeCoreDataInvalid)
		// A directory where the live database file belongs is refused too.
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
	rec := &noteRecorder{}
	o2.Start(context.Background(), rec)
	t.Cleanup(o2.Close)

	// Before the database is back: the commands that touch core are refused (D-138 N1 (d)); the others run.
	e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Restart: true})
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
	// The two failed tries audited themselves once, not twice (N5), and core's commands work again.
	if n := strings.Count(rec.text(), "transition_recovery_failed"); n != 1 {
		t.Fatalf("%d recovery-failed lines:\n%s", n, rec.text())
	}
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "manual", Snapshot: e.snap()})
}

// N1 (b): a hostile entry found during the put-back is renamed away, never walked, and the put-back goes on.
func TestContract_Update_AHostileEntryAtTheLiveNameDuringPutBackIsRenamedAwayAndThePutBackGoesOn(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
	live := filepath.Join(e.m.CoreData, "vedette.db")
	if err := os.Rename(live, live+".rollback"); err != nil {
		t.Fatal(err)
	}
	// Core (or someone) planted a directory with content where the database file belongs.
	if err := os.MkdirAll(filepath.Join(live, "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "deep", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1,
		backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}})
	e.reboot(t)
	if e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatalf("db %q", e.m.DB())
	}
	q, _ := filepath.Glob(live + ".quarantine-*")
	if len(q) != 1 {
		t.Fatalf("quarantined: %v", q)
	}
	if b, err := os.ReadFile(filepath.Join(q[0], "deep", "x")); err != nil || string(b) != "x" {
		t.Fatalf("the planted directory was changed: %q %v", b, err)
	}
	if e.journal("core") {
		t.Fatal("the journal stayed")
	}
}

// H2 (rest): on the dbBackup revert path a directory at a sidecar name or at the database name is renamed away too.
func TestContract_Update_TheBackupRestorePathRenamesAwayWhatIsNotARegularFileInsteadOfWalkingIt(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
	for _, n := range []string{"vedette.db-wal", "vedette.db"} {
		p := filepath.Join(e.m.CoreData, n)
		_ = os.Remove(p)
		if err := os.MkdirAll(filepath.Join(p, "deep"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: bk.BackupID, dbRevert: "backup"})
	e.reboot(t)
	if e.m.DB() != "db: first" {
		t.Fatalf("db %q", e.m.DB())
	}
	for _, n := range []string{"vedette.db-wal", "vedette.db"} {
		q, _ := filepath.Glob(filepath.Join(e.m.CoreData, n+".quarantine-*"))
		if len(q) != 1 {
			t.Fatalf("%s quarantined: %v", n, q)
		}
	}
}

// N1 (c) and N4: what trying again cannot cure stops the retries, leaves core stopped, audits one line, and
// lifts the refusal of the commands that do not need core's data.
func TestContract_Update_AnUnrecoverablePutBackStopsLeavesCoreStoppedAndAuditsOnce(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"the aside copy was swapped for a directory", "the unit cannot be put back"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := setupCoreUnsafe(t)
			e := c.e
			e.adopt(t, "sensor", rel1(d1, d1))
			oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
			live := filepath.Join(e.m.CoreData, "vedette.db")
			if name == "the aside copy was swapped for a directory" {
				if err := os.Remove(live); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(live+".rollback", "deep"), 0o700); err != nil {
					t.Fatal(err)
				}
				e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1,
					backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}})
			} else {
				e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1,
					backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}})
				if err := os.Remove(filepath.Join(e.m.State, "containers", "units", "core.prev")); err != nil { // the old bytes are gone
					t.Fatal(err)
				}
			}
			rec := e.reboot(t) // returns: it does not loop
			if !strings.Contains(rec.text(), "core_data_unrecoverable") || strings.Count(rec.text(), "core_data_unrecoverable") != 1 {
				t.Fatalf("notes:\n%s", rec.text())
			}
			b, err := os.ReadFile(e.m.TransitionPath("core"))
			if err != nil || !strings.Contains(string(b), `"unrecoverable":true`) {
				t.Fatalf("%s %v", b, err)
			}
			// Commands for core refuse, with a message that points at the runbook; the others run.
			ce := e.refusedWith(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "core", Restart: true}, 412, api.CodeTransitionPending)
			if !strings.Contains(ce.Message, "RUNBOOK") {
				t.Fatalf("message %q", ce.Message)
			}
			e.refused(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "manual", Snapshot: e.snap()}, 412, api.CodeTransitionPending)
			e.ok(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "sensor", Restart: true})
			if name != "the unit cannot be put back" && e.m.IsRunning("core") {
				t.Fatal("core was started although its data was not put back")
			}
		})
	}
}

// N2: a revert that fails while the run is going restarts the retry loop once the run has released the lock.
func TestContract_Update_AFailedRevertIsRetriedByItselfOnceTheRunHasReleasedTheLock(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.o.AfterReady(context.Background(), e.h.Server)     // what the real host does after READY: remember the lock
	e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1") // the rollback's restart does nothing
	e.m.Rule("systemctl", "restart", "", 1, "!r2", "r2") // the first try to put the old release back fails; later restarts work
	e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusFailed, api.CodeRollbackRevertFailed)
	eventually(t, "the retry loop to put core back", func() bool { return !e.journal("core") })
	if e.m.DB() != "db: migrated, plus data written since the update" || e.unit(t, "core") != c.upgraded {
		t.Fatalf("db %q", e.m.DB())
	}
	if st := e.state(t)["core"]; st.Digest == nil || *st.Digest != d2 {
		t.Fatalf("%+v", st)
	}
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "manual", Snapshot: e.snap()})
}

// N3: when the verified journal cannot be written but can be removed, the switch that worked stands and settles.
func TestContract_Update_AVerifiedJournalThatCannotBeWrittenButCanBeRemovedLetsTheSwitchStand(t *testing.T) {
	t.Parallel()
	e := startUpd(t, func(_ *ops.Config, d *ops.Deps) {
		d.JournalFault = func(_, phase string) error {
			if phase == "verified" {
				return errors.New("disk said no")
			}
			return nil
		}
	})
	e.adopt(t, "sensor", rel1(d1, d1))
	e.pullRel(t, "sensor", rel2(d2, d2))
	e.ok(t, api.CmdContainerStart, e.startArgs("sensor", v2))
	if e.journal("sensor") {
		t.Fatal("the journal stayed")
	}
	if v, p := e.versions(t, "sensor"); v != v2 || p != v1 {
		t.Fatalf("%q %q", v, p)
	}
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
