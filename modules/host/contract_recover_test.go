package host_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// vedette-host -recover-core-data (D-317, RUNBOOK 5.5): Ops.RecoverCoreData is what the command line calls; the
// daemon check, the flags and the exit codes are tested in cmd/vedette-host.

// asideJournal writes the journal the host leaves when a rollback moved core's files aside and then could not put
// them back (D-138 N1): unrecoverable, db_revert "aside", the names it moved.
func (e *updEnv) asideJournal(t *testing.T, unrecoverable bool, aside ...string) {
	t.Helper()
	sha := strings.Repeat("a", 64)
	j := map[string]any{
		"service": "core", "op": "rollback", "phase": "pending", "digest": d1, "from_digest": d2, "prev_sha256": sha, "new_sha256": sha,
		"was_active": true, "at": "2026-11-10T08:00:00Z", "run_id": "rn_0123456789abcdef", "unrecoverable": unrecoverable, "db_revert": "aside", "aside": aside,
	}
	b, _ := json.Marshal(j)
	if err := os.WriteFile(e.m.TransitionPath("core"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *updEnv) coreFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.m.CoreData, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tree is everything in core_data: name -> kind and content, to compare before and after.
func (e *updEnv) tree(t *testing.T) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(e.m.CoreData)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range ents {
		fi, err := os.Lstat(filepath.Join(e.m.CoreData, d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(filepath.Join(e.m.CoreData, d.Name()))
			out[d.Name()] = string(b)
		} else {
			out[d.Name()] = "<" + fi.Mode().Type().String() + ">"
		}
	}
	return out
}

// startRecover is a box where a rollback of core moved the database, its WAL and the key aside and gave up: the
// live files are the half-made new ones, core is stopped, its unit is installed.
func startRecover(t *testing.T) *updEnv {
	t.Helper()
	e := startUpd(t)
	// The interrupted change was a container.rollback from d2 to d1 that left the unit of d2 (the one the data copies
	// belong to) in place; the copies are d2's data.
	e.m.InstallUnit(api.ServiceCore, d2, true)
	e.m.SetRunning(api.ServiceCore, false)
	e.coreFile(t, "vedette.db", "db: half-migrated")
	e.coreFile(t, "vedette.db-wal", "wal: of the new database")
	e.coreFile(t, "vedette.db.rollback", "db: old")
	e.coreFile(t, "vedette.db-wal.rollback", "wal: old")
	e.coreFile(t, "vedette.key.rollback", "key: old")
	if err := os.Mkdir(filepath.Join(e.m.CoreData, "vedette.db.quarantine-5"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.asideJournal(t, true, "vedette.db", "vedette.db-wal", "vedette.key")
	return e
}

type recovered struct {
	lines []string
	err   error
}

func (e *updEnv) recover(a ops.RecoverArgs) recovered {
	var r recovered
	r.err = e.o.RecoverCoreData(context.Background(), a, func(s string) { r.lines = append(r.lines, s) })
	return r
}

func (e *updEnv) recoverRefused(t *testing.T, a ops.RecoverArgs, code string) {
	t.Helper()
	before := e.tree(t)
	r := e.recover(a)
	if got, _ := ops.BootstrapCode(r.err); r.err == nil || got != code {
		t.Fatalf("want %s, got %v", code, r.err)
	}
	if after := e.tree(t); !mapsEqual(before, after) {
		t.Errorf("a refusal changed core_data: %v -> %v", before, after)
	}
	if !e.journal(api.ServiceCore) {
		t.Error("a refusal removed the journal")
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 0 {
		t.Errorf("audited: %v", n)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func TestContract_Recover_ReportAndDryRunChangeNothing(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	before := e.tree(t)
	for _, a := range []ops.RecoverArgs{{}, {Use: ops.RecoverUseRollback}, {Use: ops.RecoverUseCurrent}} {
		r := e.recover(a)
		if r.err != nil {
			t.Fatalf("%+v: %v", a, r.err)
		}
		out := strings.Join(r.lines, "\n")
		t.Logf("%+v:\n%s", a, out)
		for _, want := range []string{"vedette.db.rollback", "vedette.key.rollback", "vedette.db.quarantine-5", "nothing was changed"} {
			if !strings.Contains(out, want) {
				t.Errorf("%+v: the output lacks %q:\n%s", a, want, out)
			}
		}
		if !mapsEqual(before, e.tree(t)) || !e.journal(api.ServiceCore) {
			t.Fatalf("%+v changed core_data or the journal", a)
		}
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 0 {
		t.Errorf("audited: %v", n)
	}
	// Yes without a choice is a misuse, and changes nothing either.
	if r := e.recover(ops.RecoverArgs{Apply: true}); r.err == nil || !mapsEqual(before, e.tree(t)) {
		t.Fatalf("-yes without -use: %v", r.err)
	}
}

func TestContract_Recover_RollbackPutsTheCopiesBackAndKeepsWhatItReplaces(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true})
	if r.err != nil {
		t.Fatalf("%v\n%s", r.err, strings.Join(r.lines, "\n"))
	}
	tr := e.tree(t)
	if tr["vedette.db"] != "db: old" || tr["vedette.db-wal"] != "wal: old" || tr["vedette.key"] != "key: old" {
		t.Errorf("the copies are not back: %v", tr)
	}
	for _, gone := range []string{"vedette.db.rollback", "vedette.db-wal.rollback", "vedette.key.rollback"} {
		if _, ok := tr[gone]; ok {
			t.Errorf("%s is still there", gone)
		}
	}
	// What was in the way is kept, not deleted; the thing the host quarantined is left alone.
	var replaced []string
	for n, c := range tr {
		if strings.HasPrefix(n, "vedette.db.replaced-") || strings.HasPrefix(n, "vedette.db-wal.replaced-") {
			replaced = append(replaced, c)
		}
	}
	slices.Sort(replaced)
	if !slices.Equal(replaced, []string{"db: half-migrated", "wal: of the new database"}) {
		t.Errorf("the replaced files: %v", replaced)
	}
	if !strings.HasPrefix(tr["vedette.db.quarantine-5"], "<d") {
		t.Errorf("the quarantined directory was touched: %q", tr["vedette.db.quarantine-5"])
	}
	if e.journal(api.ServiceCore) {
		t.Error("the journal is still there")
	}
	n := e.notes(t, "core_data_recovered")
	if len(n) != 1 || n[0]["use"] != "rollback" || n[0]["run_id"] != "rn_0123456789abcdef" {
		t.Fatalf("audit lines: %v", n)
	}
	for _, c := range e.m.Calls("systemctl") {
		if slices.Contains(c, "start") || slices.Contains(c, "stop") {
			t.Errorf("the command touched the service: %v", c)
		}
	}
	// Core's commands work again.
	e.ok(t, api.CmdBackupCreate, api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"})
}

// patchJournal changes fields of the journal on disk (what the host itself would have saved).
func (e *updEnv) patchJournal(t *testing.T, f func(j map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(e.m.TransitionPath("core"))
	if err != nil {
		t.Fatal(err)
	}
	var j map[string]any
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	f(j)
	b, _ = json.Marshal(j)
	if err := os.WriteFile(e.m.TransitionPath("core"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *updEnv) mv(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(filepath.Join(e.m.CoreData, from), filepath.Join(e.m.CoreData, to)); err != nil {
		t.Fatal(err)
	}
}

func recoverProgress(phase string) func(j map[string]any) {
	return func(j map[string]any) {
		j["recover"] = map[string]any{"at": 111, "phase": phase, "names": []string{"vedette.db", "vedette.db-wal", "vedette.key"}}
	}
}

// M1: the states a stopped run really leaves (the order of the code: everything aside first, the database last)
// are finished by the same command and lose nothing: the old WAL that was put back is never set aside again.
func TestContract_Recover_AStoppedRunIsFinishedAndLosesNothing(t *testing.T) {
	t.Parallel()
	t.Run("stopped after the sidecars and the key went back, before the database", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		for _, n := range []string{"vedette.db", "vedette.db-wal", "vedette.key"} {
			e.mv(t, n, n+".replaced-111")
		}
		e.mv(t, "vedette.db-wal.rollback", "vedette.db-wal")
		e.mv(t, "vedette.key.rollback", "vedette.key")
		e.patchJournal(t, recoverProgress("putting"))
		before := e.tree(t)
		if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback}); r.err != nil || !mapsEqual(before, e.tree(t)) {
			t.Fatalf("the dry run: %v", r.err)
		}
		if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}); r.err != nil {
			t.Fatal(r.err)
		}
		tr := e.tree(t)
		if tr["vedette.db"] != "db: old" || tr["vedette.db-wal"] != "wal: old" || tr["vedette.key"] != "key: old" || e.journal(api.ServiceCore) {
			t.Fatalf("not finished: %v", tr)
		}
		if tr["vedette.db-wal.replaced-111"] != "wal: of the new database" || tr["vedette.db.replaced-111"] != "db: half-migrated" {
			t.Errorf("what was set aside is not intact: %v", tr)
		}
		for n, c := range tr {
			if strings.Contains(n, ".replaced-") && !strings.HasSuffix(n, "-111") && c == "wal: old" {
				t.Errorf("the old WAL was set aside again as %s", n)
			}
		}
	})
	t.Run("stopped while setting the files aside", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		e.mv(t, "vedette.db", "vedette.db.replaced-111")
		e.patchJournal(t, recoverProgress("moving"))
		if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}); r.err != nil {
			t.Fatal(r.err)
		}
		tr := e.tree(t)
		if tr["vedette.db"] != "db: old" || tr["vedette.db-wal"] != "wal: old" || tr["vedette.key"] != "key: old" || e.journal(api.ServiceCore) {
			t.Fatalf("not finished: %v", tr)
		}
		if tr["vedette.db-wal.replaced-111"] != "wal: of the new database" {
			t.Errorf("the live WAL was not kept under the stamp of the first run: %v", tr)
		}
	})
	t.Run("everything is back but the journal is still there (the versions failed once)", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		for _, n := range []string{"vedette.db", "vedette.db-wal", "vedette.key"} {
			e.mv(t, n, n+".replaced-111")
			e.mv(t, n+".rollback", n)
		}
		e.patchJournal(t, recoverProgress("putting"))
		if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}); r.err != nil || e.journal(api.ServiceCore) {
			t.Fatalf("%v", r.err)
		}
		// With a recovery half way, keeping the files as they are is not an answer.
		e2 := startRecover(t)
		e2.patchJournal(t, recoverProgress("putting"))
		e2.recoverRefused(t, ops.RecoverArgs{Use: ops.RecoverUseCurrent, Apply: true}, ops.RecoverInProgress)
	})
}

// H1: the copy of the database is gone but copies of its WAL/SHM are not (the host's own putAsideBack leaves this
// when it quarantines a copy that is not a regular file): the sidecars must never be put back beside the live
// database.
func TestContract_Recover_NeverPutsAWALBackWithoutTheDatabaseCopy(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	e.mv(t, "vedette.db.rollback", "vedette.db.rollback.quarantine-7")
	e.coreFile(t, "vedette.db-shm.rollback", "shm: old")
	e.coreFile(t, "vedette.db", "db: the pre_update backup")
	e.mv(t, "vedette.db-wal", "vedette.db-wal.gone")
	if err := os.Remove(filepath.Join(e.m.CoreData, "vedette.db-wal.gone")); err != nil {
		t.Fatal(err)
	}
	e.asideJournal(t, true, "vedette.db", "vedette.db-wal", "vedette.db-shm")
	e.recoverRefused(t, ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}, ops.RecoverDBCopyMissing)
	if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback}); r.err == nil {
		t.Error("the dry run did not refuse")
	}
	// Keeping what is there still works.
	if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseCurrent, Apply: true}); r.err != nil {
		t.Fatal(r.err)
	}
	if tr := e.tree(t); tr["vedette.db"] != "db: the pre_update backup" || tr["vedette.db-wal.rollback"] != "wal: old" {
		t.Errorf("%v", tr)
	}
}

// M2: the copies are the data of the release the rollback moved away from; a unit that pins another one is not put
// under them.
func TestContract_Recover_RollbackNeedsTheUnitOfTheReleaseTheCopiesBelongTo(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	e.m.InstallUnit(api.ServiceCore, d1, true) // the target of the rollback: the unit of the older release
	e.recoverRefused(t, ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}, ops.RecoverUnitMismatch)
	r := e.recover(ops.RecoverArgs{})
	if out := strings.Join(r.lines, "\n"); r.err != nil || !strings.Contains(out, d1) || !strings.Contains(out, d2) {
		t.Errorf("the report does not show both releases:\n%s", out)
	}
	// Keeping the files is not a mix of releases.
	if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseCurrent, Apply: true}); r.err != nil {
		t.Fatal(r.err)
	}
}

// M3: what core names is data: nothing of it reaches the operator's terminal raw.
func TestContract_Recover_NamesFromCoreNeverReachTheTerminalRaw(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	e.coreFile(t, "x\x1b[2J\r\nvedette-host: recover-core-data: done.quarantine-1", "x")
	e.coreFile(t, "vedette.db.quarantine-1\x1b[2J", "x")
	e.coreFile(t, "vedette.db.rollback.quarantine-9", "x")
	r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback})
	if r.err != nil {
		t.Fatal(r.err)
	}
	for _, l := range r.lines {
		if strings.ContainsAny(l, "\x1b\r\n\x00") || strings.HasPrefix(l, "vedette-host:") {
			t.Errorf("a raw control byte or a forged line: %q", l)
		}
	}
	if out := strings.Join(r.lines, "\n"); !strings.Contains(out, "vedette.db.rollback.quarantine-9") {
		t.Errorf("the entry the host made is not listed:\n%s", out)
	}
}

type failingAudit struct{}

func (failingAudit) Note(string, string, map[string]any) error { return os.ErrPermission }

// M4: a change that cannot be recorded is not made.
func TestContract_Recover_AChangeTheAuditLogCannotRecordIsNotMade(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	e.o.AuditTo(failingAudit{})
	journal, _ := os.ReadFile(e.m.TransitionPath("core"))
	for _, use := range []string{ops.RecoverUseRollback, ops.RecoverUseCurrent} {
		e.recoverRefused(t, ops.RecoverArgs{Use: use, Apply: true}, ops.RecoverAuditDown)
		if now, _ := os.ReadFile(e.m.TransitionPath("core")); string(now) != string(journal) {
			t.Fatalf("%s: the journal changed", use)
		}
	}
}

// The start line comes first and the done line last.
func TestContract_Recover_WritesAStartLineAndADoneLine(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}); r.err != nil {
		t.Fatal(r.err)
	}
	if n := e.notes(t, "core_data_recover_start"); len(n) != 1 || n[0]["use"] != "rollback" {
		t.Errorf("start lines: %v", n)
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 1 {
		t.Errorf("done lines: %v", n)
	}
}

func TestContract_Recover_CurrentKeepsTheFilesAndOnlyClearsTheJournal(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	before := e.tree(t)
	if r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseCurrent, Apply: true}); r.err != nil {
		t.Fatal(r.err)
	}
	if !mapsEqual(before, e.tree(t)) {
		t.Errorf("-use current moved a file: %v", e.tree(t))
	}
	if e.journal(api.ServiceCore) {
		t.Error("the journal is still there")
	}
	if n := e.notes(t, "core_data_recovered"); len(n) != 1 || n[0]["use"] != "current" {
		t.Errorf("audit lines: %v", n)
	}
}

func TestContract_Recover_Refusals(t *testing.T) {
	t.Parallel()
	use := ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true}
	t.Run("core is running", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		e.m.SetRunning(api.ServiceCore, true)
		e.recoverRefused(t, use, ops.RecoverCoreRunning)
	})
	t.Run("the host is still working on the journal", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		e.asideJournal(t, false, "vedette.db")
		e.recoverRefused(t, use, ops.RecoverNotUnrecoverable)
	})
	t.Run("the journal is damaged", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		if err := os.WriteFile(e.m.TransitionPath("core"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.recoverRefused(t, use, ops.RecoverJournalInvalid)
	})
	t.Run("an aside copy is a symbolic link", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		p := filepath.Join(e.m.CoreData, "vedette.db.rollback")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/passwd", p); err != nil {
			t.Fatal(err)
		}
		e.recoverRefused(t, use, api.CodeCoreDataInvalid)
		// Not even a report goes on with it.
		if r := e.recover(ops.RecoverArgs{}); r.err == nil {
			t.Error("the report went on")
		}
	})
	t.Run("core_data is a symbolic link", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		behind := e.m.CoreData + ".real"
		if err := os.Rename(e.m.CoreData, behind); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(behind, e.m.CoreData); err != nil {
			t.Fatal(err)
		}
		r := e.recover(use)
		if got, _ := ops.BootstrapCode(r.err); got != api.CodeCoreDataInvalid {
			t.Fatalf("got %v", r.err)
		}
		if b, _ := os.ReadFile(filepath.Join(behind, "vedette.db")); string(b) != "db: half-migrated" { //nolint:gosec // test: under the fake core_data
			t.Error("the files behind the link were touched")
		}
		if !e.journal(api.ServiceCore) {
			t.Error("the journal was removed")
		}
	})
	t.Run("there is no copy to put back", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		e.asideJournal(t, true) // a restore of a backup, not an aside: nothing named
		e.recoverRefused(t, use, ops.RecoverNoCopy)
	})
	t.Run("the unit is not one the recorded versions explain", func(t *testing.T) {
		t.Parallel()
		e := startRecover(t)
		if err := os.Remove(filepath.Join(e.m.UnitsDir(), "vedette-core.container")); err != nil {
			t.Fatal(err)
		}
		e.recoverRefused(t, ops.RecoverArgs{Use: ops.RecoverUseCurrent, Apply: true}, ops.RecoverVersions) // rollback says unit_mismatch first
	})
}

func TestContract_Recover_NothingToRecoverWithoutAJournal(t *testing.T) {
	t.Parallel()
	e := startRecover(t)
	if err := os.Remove(e.m.TransitionPath("core")); err != nil {
		t.Fatal(err)
	}
	before := e.tree(t)
	r := e.recover(ops.RecoverArgs{Use: ops.RecoverUseRollback, Apply: true})
	if r.err != nil || len(r.lines) != 1 || !strings.Contains(r.lines[0], "nothing to recover") {
		t.Fatalf("%v %v", r.err, r.lines)
	}
	if !mapsEqual(before, e.tree(t)) {
		t.Error("core_data changed")
	}
}
