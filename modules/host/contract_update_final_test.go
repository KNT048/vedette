package host_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// The last review of slice 3-8a (D-138 (9) amended): M1, L1, L2, L3.

// M1: only an unsafe unit directory or a missing/mismatched .prev is unrecoverable; an I/O error is retried.
func TestContract_Update_ATransientErrorPuttingTheUnitBackIsNotMarkedUnrecoverable(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d1)
	e.seedCrash(t, crashSeed{op: "rollback", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v1, fromDigest: d2, toDigest: d1,
		backupID: c.backup, dbRevert: "aside", aside: []string{"vedette.db"}})
	// The Quadlet directory cannot be written (the temp file of the atomic write cannot be made): an I/O error, not an unsafe tree.
	if err := os.Chmod(e.m.UnitsDir(), 0o555); err != nil { //nolint:gosec // test: make the unit write fail
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.m.UnitsDir(), 0o755) }) //nolint:gosec // test cleanup
	rec := e.startOnly(t)
	b, err := os.ReadFile(e.m.TransitionPath("core"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"unrecoverable"`) || strings.Contains(rec.text(), "core_data_unrecoverable") {
		t.Fatalf("a transient error was taken as unrecoverable:\n%s\n%s", b, rec.text())
	}
	if !strings.Contains(rec.text(), "transition_recovery_failed") {
		t.Fatalf("notes %s", rec.text())
	}
	// A missing .prev, which no retry can bring back, is.
	if err := os.Chmod(e.m.UnitsDir(), 0o755); err != nil { //nolint:gosec // test: let the next start write
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.m.State, "containers", "units", "core.prev")); err != nil {
		t.Fatal(err)
	}
	rec = e.startOnly(t)
	if !strings.Contains(rec.text(), "core_data_unrecoverable") {
		t.Fatalf("notes %s", rec.text())
	}
}

// startOnly runs a new Ops's Start (no AfterReady) on the same state.
func (e *updEnv) startOnly(t *testing.T) *noteRecorder {
	t.Helper()
	o2 := e.m.Ops(e.clock.Now, e.muts...)
	rec := &noteRecorder{}
	o2.Start(t.Context(), rec)
	t.Cleanup(o2.Close)
	return rec
}

// L1: a run whose put-back fails for a reason no retry cures marks it at once, and does not start a retry.
func TestContract_Update_ARunWhosePutBackIsUnrecoverableMarksItAtOnceAndAuditsOnce(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.m.BadImage(d1)                  // the rolled-back release never gets healthy
	e.m.Mark("plant-aside-dir", true) // and, at the restart, the copy of the database that was set aside is swapped for a directory
	e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusFailed, api.CodeRollbackRevertFailed)
	b, err := os.ReadFile(e.m.TransitionPath("core"))
	if err != nil || !strings.Contains(string(b), `"unrecoverable":true`) {
		t.Fatalf("%s %v", b, err)
	}
	if n := e.notes(t, "core_data_unrecoverable"); len(n) != 1 {
		t.Fatalf("notes %v", n)
	}
	e.refused(t, api.CmdContainerStart, api.ContainerStartArgs{Service: "core", Restart: true}, 412, api.CodeTransitionPending)
}

// L2: a run that failed before AfterReady stored the lock starts no retry itself; AfterReady finds the journal.
func TestContract_Update_AFailedRevertBeforeAfterReadyIsPickedUpByAfterReady(t *testing.T) {
	t.Parallel()
	c := setupCoreUnsafe(t)
	e := c.e
	e.m.Rule("systemctl", "restart", "", 0, "!r1", "r1")
	e.m.Rule("systemctl", "restart", "", 1, "!r2", "r2")
	e.final(t, api.CmdContainerRollback, api.ContainerRollbackArgs{Service: "core"}, api.StatusFailed, api.CodeRollbackRevertFailed)
	if !e.journal("core") {
		t.Fatal("no journal")
	}
	e.o.AfterReady(t.Context(), e.h.Server)
	if e.journal("core") || e.m.DB() != "db: migrated, plus data written since the update" {
		t.Fatalf("journal %t db %q", e.journal("core"), e.m.DB())
	}
}

// L3: quarantined entries are named with the host's clock.
func TestContract_Update_AQuarantinedEntryIsNamedWithTheHostsClock(t *testing.T) {
	t.Parallel()
	e := startUpd(t)
	e.adopt(t, "core", rel1(d1, d1))
	e.pullRel(t, "core", relSpec{version: v2, core: d2, sensor: d2, unsafe: true})
	bk := result[api.BackupResult](t, e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Kind: "pre_update", Snapshot: e.snap(), IncludeSecrets: true}))
	oldText, newText := e.unit(t, "core"), e.render(t, "core", d2)
	p := filepath.Join(e.m.CoreData, "vedette.db-wal")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	e.seedCrash(t, crashSeed{op: "start", svc: "core", phase: "pending", oldText: oldText, newText: newText, onDisk: newText, version: v2, fromDigest: d1, toDigest: d2, backupID: bk.BackupID, dbRevert: "backup"})
	want := strconv.FormatInt(e.clock.Now().UnixNano(), 10)
	e.reboot(t)
	if _, err := os.Stat(p + ".quarantine-" + want); err != nil {
		q, _ := filepath.Glob(p + ".quarantine-*")
		t.Fatalf("want ...quarantine-%s, have %v", want, q)
	}
}
