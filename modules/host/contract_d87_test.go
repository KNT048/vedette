// Contract tests of the security review of WP-07b part 1 (D-87 and the findings around it): root
// never opens or parses core's data, never touches core's tree by path, refuses writes once a
// reboot has started, and bounds what logs.export can write. They run on the fake machine (opstest)
// like the rest of the system-command tests.
package host_test

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// sourcesUnder parses every Go file under the given directories, tests included.
func sourcesUnder(t *testing.T, roots ...string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files[p] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no source files found: wrong working directory?")
	}
	return files
}

// INV-13 (D-87): the root host never opens, parses or runs SQL on core's data. No package under
// host/ or cmd/vedette-host (test support and test files included) imports database/sql or a SQL
// driver: core makes its own snapshot and the host copies bytes by file descriptor.
func TestContract_INV13_RootNeverImportsASQLDriver(t *testing.T) {
	t.Parallel()
	banned := []string{
		"database/sql", "modernc.org/sqlite", "github.com/mattn/go-sqlite3", "github.com/glebarez/", "github.com/ncruces/go-sqlite3",
		"zombiezen.com/go/sqlite", "crawshaw.io/sqlite", "github.com/tursodatabase/", "github.com/jackc/pgx", "github.com/lib/pq",
		"github.com/go-sql-driver/", "github.com/pressly/goose", "github.com/knt048/vedette/core/store",
	}
	srcs := sourcesUnder(t, "../../host", "../../cmd/vedette-host")
	if len(srcs) < 40 {
		t.Fatalf("only %d source files found: wrong working directory?", len(srcs))
	}
	for path, f := range srcs {
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, b := range banned {
				b = strings.TrimSuffix(b, "/")
				if p == b || strings.HasPrefix(p, b+"/") {
					t.Errorf("%s imports %s: the root host must not touch SQL (D-87)", path, p)
				}
			}
		}
	}
}

// INV-13 (D-87), the whole binary: the direct-import check above misses a dependency of a dependency (core/chain
// once pulled in core/store and with it the SQLite driver). Walk the import graph of vedette-host inside this
// module, as built for Linux, and refuse any SQL package anywhere in it. Packages outside the module (the
// standard library, golang.org/x/sys) are leaves here: none of them imports a SQL driver, and an import of one
// from inside the module is what this test catches.
func TestContract_INV13_RootBinaryLinksNoSQL(t *testing.T) {
	t.Parallel()
	const mod = "github.com/knt048/vedette"
	bctx := build.Default
	bctx.GOOS = "linux"
	seen := map[string]bool{}
	var walk func(pkg string)
	walk = func(pkg string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		dir := filepath.Join("../..", strings.TrimPrefix(pkg, mod))
		bp, err := bctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("%s: %v", pkg, err)
		}
		for _, imp := range bp.Imports {
			if imp == "database/sql" || strings.Contains(imp, "sqlite") || strings.HasPrefix(imp, mod+"/core/store") || strings.HasPrefix(imp, "github.com/pressly/goose") {
				t.Errorf("%s imports %s: vedette-host must not carry SQL code (D-87)", pkg, imp)
			}
			if strings.HasPrefix(imp, mod+"/") {
				walk(imp)
			}
		}
	}
	walk(mod + "/cmd/vedette-host")
	if len(seen) < 5 {
		t.Fatalf("walked only %d packages: wrong working directory?", len(seen))
	}
}

// The production wiring hands the server the reboot gate; without it a write could start while
// the box shuts down.
func TestContract_FORBID_ProductionWiringHasTheRebootGate(t *testing.T) {
	t.Parallel()
	found := false
	for path, f := range sourcesUnder(t, "../../cmd/vedette-host") {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "WriteGate" {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Error("cmd/vedette-host does not set server.Options.WriteGate")
	}
}

// --- startup ----------------------------------------------------------------------------------

func TestContract_Startup_SweepsRestoreTempsOfADeadRestoreInCoresTree(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	left := filepath.Join(e.m.CoreData, ".vedette-restore-0123456789abcdef")
	mine := filepath.Join(e.m.CoreData, "core-notes.txt")
	for _, p := range []string{left, mine} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &noteRecorder{}
	e.o.Start(context.Background(), rec)
	defer e.o.Close()
	if _, err := os.Lstat(left); err == nil {
		t.Error("a temp file of a dead restore survived start-up")
	}
	if _, err := os.Lstat(mine); err != nil {
		t.Error("a file of core's own was removed")
	}
	if strings.Contains(rec.text(), "core_data_untrusted") {
		t.Errorf("a good tree was reported as untrusted: %s", rec.text())
	}
}

func TestContract_Startup_AnUntrustedCoreDataIsAuditedAndEveryCommandRefusesIt(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	snap := e.snap()
	if err := os.Chmod(filepath.Dir(e.m.CoreData), 0o777); err != nil { //nolint:gosec // the test makes the parent unsafe on purpose
		t.Fatal(err)
	}
	rec := &noteRecorder{}
	e.o.Start(context.Background(), rec)
	defer e.o.Close()
	if !strings.Contains(rec.text(), "core_data_untrusted") {
		t.Errorf("start-up did not report the tree: %q", rec.text())
	}
	e.refused(t, "backup.create", api.BackupCreateArgs{Snapshot: snap, Kind: "manual"}, http.StatusPreconditionFailed, "db_unreadable")
}

// --- reboot ------------------------------------------------------------------------------------

// writeCommands is one request for every write command of the host (all of them change the box).
func (e *sysEnv) writeRequests() map[string]string {
	snap := e.snap()
	return map[string]string{
		"os.check":             `{"args":{}}`,
		"os.install":           `{"args":{"scope":"all","snapshot":"` + snap + `"}}`,
		"os.auto_security.set": `{"args":{"enabled":true}}`,
		"os.reboot":            `{"args":{"when":"now"}}`,
		"os.reboot.cancel":     `{"args":{}}`,
		"backup.create":        `{"args":{"kind":"manual","snapshot":"` + snap + `"}}`,
		"backup.restore":       `{"args":{"backup_id":"` + strings.Repeat("a", 32) + `","snapshot":"` + snap + `"}}`,
		"logs.export":          `{"args":{"units":["vedette-core"],"since":"2026-11-09T00:00:00Z","until":"2026-11-09T01:00:00Z"}}`,
	}
}

// Once the host has told systemd to reboot, no write command starts until the boot id changes: core
// could otherwise interrupt dpkg or a restore by queueing work that the shutdown kills halfway.
func TestContract_Reboot_NoWriteStartsOnceARebootWasStartedUntilTheBootIdChanges(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.o.Start(context.Background(), e.h.Server)
	e.installRules()
	e.rules()
	reqID := "88888888-8888-4888-8888-888888888888"
	first, err := e.h.Client.Run(context.Background(), "os.reboot", api.OSRebootArgs{When: "now"}, reqID, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, e.h.Client, first.RunID)
	eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
	callsBefore := len(e.m.AllCalls())

	reqs := e.writeRequests()
	i := 0
	for cmd, body := range reqs {
		i++
		st, resp := rawReq(t, e.h, "/v1/commands/"+cmd, hdr("99999999-9999-4999-8999-99999999900"+string(rune('0'+i))), body)
		if st != http.StatusConflict || errCode(resp) != api.CodeRebooting {
			t.Errorf("%s while rebooting: %d %s", cmd, st, resp)
		}
	}
	if got := len(e.m.AllCalls()); got != callsBefore {
		t.Errorf("a process started while the box was rebooting: %v", e.m.AllCalls()[callsBefore:])
	}
	if bl, _ := e.h.Client.StateBackups(context.Background()); len(bl.Backups) != 0 {
		t.Errorf("a backup was made while rebooting: %+v", bl)
	}
	// The refusals are audited, and reads keep working.
	n := 0
	for _, a := range audit(t, e.h) {
		if a.Code != nil && *a.Code == api.CodeRebooting {
			n++
		}
	}
	if n != len(reqs) {
		t.Errorf("%d audit lines for the refused writes, want %d", n, len(reqs))
	}
	// A retry of the request that started the reboot still finds its run.
	again, err := e.h.Client.Run(context.Background(), "os.reboot", api.OSRebootArgs{When: "now"}, reqID, "admin@example.com")
	if err != nil || again.RunID != first.RunID {
		t.Errorf("replay of the accepted os.reboot: %+v %v", again, err)
	}
	// The kernel booted again: writes work.
	e.m.SetBootID("99999999-8888-4777-8666-555555555555")
	e.ok(t, "os.check", nil)
}

func TestContract_Reboot_TheGateEndsWhenTheRebootDoesNotComeOrFails(t *testing.T) {
	t.Parallel()
	t.Run("the reboot never happens: writes resume after ten minutes", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.rules()
		e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
		eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
		e.refused(t, "os.check", nil, http.StatusConflict, "rebooting")
		e.clock.Advance(9 * time.Minute)
		e.refused(t, "os.check", nil, http.StatusConflict, "rebooting")
		e.clock.Advance(2 * time.Minute)
		e.ok(t, "os.check", nil)
	})
	t.Run("systemctl reboot fails: the gate is lifted at once", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.o.Start(context.Background(), e.h.Server)
		e.rules()
		e.m.Rule("systemctl", "reboot", "", 1, "", "")
		e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
		eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
		eventually(t, "the gate to lift", func() bool { return e.o.WriteGate() == nil })
		e.ok(t, "os.check", nil)
	})
	t.Run("a refused os.reboot does not raise it", func(t *testing.T) {
		t.Parallel()
		e := startSys(t)
		e.rules()
		e.refused(t, "os.reboot", api.OSRebootArgs{When: "at", At: e.clock.Now().Add(time.Second).Format(time.RFC3339)}, http.StatusPreconditionFailed, "at_in_past")
		e.ok(t, "os.check", nil)
	})
}

func TestContract_Reboot_TheGateSurvivesAHostRestartDuringTheShutdown(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
	eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == 1 })
	// The host process is replaced while the box is still shutting down: same boot id, minutes ago.
	e.clock.Advance(2 * time.Minute)
	o2 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = (&fakeTimers{}).after })
	o2.Start(context.Background(), &noteRecorder{})
	defer o2.Close()
	if ref := o2.WriteGate(); ref == nil || ref.Code != api.CodeRebooting || ref.Status != http.StatusConflict {
		t.Fatalf("the restarted host lets writes through: %+v", ref)
	}
	// After the boot id changes, the next host start has no gate.
	e.m.SetBootID("99999999-8888-4777-8666-555555555555")
	o3 := e.m.Ops(e.clock.Now, func(_ *ops.Config, d *ops.Deps) { d.AfterFunc = (&fakeTimers{}).after })
	o3.Start(context.Background(), &noteRecorder{})
	defer o3.Close()
	if ref := o3.WriteGate(); ref != nil {
		t.Fatalf("a gate on the new boot: %+v", ref)
	}
	// The same host instance also notices the new boot id on its own.
	if ref := o2.WriteGate(); ref != nil {
		t.Errorf("the gate stayed after the boot id changed: %+v", ref)
	}
}

// Setting the wall clock back (a bad NTP step, a board without a clock) must not reset the limit of
// three reboots in 24 hours: starts dated in the future still count.
func TestContract_Reboot_ClockSetBackDoesNotResetTheLimit(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	for i := 0; i < 3; i++ {
		e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
		eventually(t, "systemctl reboot", func() bool { return rebootCalls(e) == i+1 })
		e.m.SetBootID(fmt.Sprintf("11111111-2222-4333-8444-55555555100%d", i))
	}
	e.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "reboot_limit_reached")
	e.clock.Advance(-2 * time.Hour)
	e.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "reboot_limit_reached")
	e.clock.Advance(-30 * 24 * time.Hour)
	e.refused(t, "os.reboot", api.OSRebootArgs{When: "now"}, http.StatusConflict, "reboot_limit_reached")
	if rebootCalls(e) != 3 {
		t.Fatalf("%d reboots", rebootCalls(e))
	}
	// Forward again, past 24 hours after the recorded starts: the limit lifts.
	e.clock.Advance(30*24*time.Hour + 2*time.Hour + 24*time.Hour + time.Minute)
	e.ok(t, "os.reboot", api.OSRebootArgs{When: "now"})
}

// --- logs.export -------------------------------------------------------------------------------

func TestContract_LogsExport_RefusesWhenTheDiskIsAlmostFull(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 1, nil } })
	e.m.Rule("journalctl", "-u vedette-core", "journal_core.jsonl", 0, "", "")
	args := api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-01T00:00:00Z", Until: "2026-11-09T00:00:00Z"}
	for range 3 {
		e.refused(t, "logs.export", args, http.StatusPreconditionFailed, "low_disk")
	}
	if got := e.m.Calls("journalctl"); len(got) != 0 {
		t.Errorf("journalctl ran with no room for its output: %v", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(e.m.State, "exports")); len(ents) != 0 {
		t.Errorf("files in exports/: %v", ents)
	}
	// Exactly twice the largest export is enough.
	const limit = 256 << 20
	e2 := startSys(t, func(_ *ops.Config, d *ops.Deps) { d.FreeBytes = func(string) (uint64, error) { return 2 * limit, nil } })
	e2.m.Rule("journalctl", "-u vedette-core", "journal_core.jsonl", 0, "", "")
	e2.ok(t, "logs.export", args)
}

func TestContract_LogsExport_KeepsAtMostThreeExportsAndEachDownloadIsAudited(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	rec := &noteRecorder{}
	e.o.Start(context.Background(), rec)
	e.m.Rule("journalctl", "-u vedette-core", "journal_core.jsonl", 0, "", "")
	args := api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}
	var ids []string
	for range 5 {
		e.clock.Advance(time.Minute)
		ids = append(ids, result[api.LogsExportResult](t, e.ok(t, "logs.export", args)).ExportID)
	}
	ents, _ := os.ReadDir(filepath.Join(e.m.State, "exports"))
	var files []string
	for _, ent := range ents {
		if strings.HasSuffix(ent.Name(), ".jsonl.gz") {
			files = append(files, strings.TrimSuffix(ent.Name(), ".jsonl.gz"))
		}
	}
	slices.Sort(files)
	want := slices.Clone(ids[2:])
	slices.Sort(want)
	if !slices.Equal(files, want) {
		t.Fatalf("kept exports %v, want the newest three %v", files, want)
	}
	for _, old := range ids[:2] {
		if st, _ := rawGet2(t, e, "/v1/exports/"+old+"/content"); st != http.StatusNotFound {
			t.Errorf("the dropped export %s is still served: %d", old, st)
		}
	}
	for _, id := range ids[2:] {
		if st, _ := rawGet2(t, e, "/v1/exports/"+id+"/content"); st != http.StatusOK {
			t.Errorf("export %s: %d", id, st)
		}
	}
	if got := strings.Count(rec.text(), "logs.download export_downloaded"); got != 3 {
		t.Errorf("%d download audit lines, want 3 (one per download):\n%s", got, rec.text())
	}
}

// One journalctl call is held in memory by core/exec, so it is capped at 64 MiB however large the
// export limit is; going over is the same refusal as going over the limit (never a cut file).
func TestContract_LogsExport_OneUnitIsCappedBelowTheExportLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 64 MiB")
	}
	t.Parallel()
	e := startSys(t)
	e.m.RuleText("journalctl", "-u vedette-core", strings.Repeat("x", 64<<20+16), 0, "", "")
	args := api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}
	e.final(t, "logs.export", args, api.StatusRefused, "output_too_large")
	if ents, _ := os.ReadDir(filepath.Join(e.m.State, "exports")); len(ents) > 1 {
		t.Errorf("an export file was kept: %v", ents)
	}
}

// --- downloads and the audit chain -------------------------------------------------------------

// A download the audit chain cannot record is not served (the host fails closed).
func TestContract_Downloads_AreRefusedWhenTheAuditCannotBeWritten(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	b := result[api.BackupResult](t, e.ok(t, "backup.create", api.BackupCreateArgs{Snapshot: e.snap(), Kind: "manual"}))
	e.m.Rule("journalctl", "-u vedette-core", "journal_core.jsonl", 0, "", "")
	x := result[api.LogsExportResult](t, e.ok(t, "logs.export", api.LogsExportArgs{Units: []string{"vedette-core"}, Since: "2026-11-09T00:00:00Z", Until: "2026-11-09T01:00:00Z"}))
	e.o.Start(context.Background(), failingNotifier{})
	defer e.o.Close()
	for _, p := range []string{"/v1/backups/" + b.BackupID + "/content", "/v1/exports/" + x.ExportID + "/content"} {
		if st, body := rawGet2(t, e, p); st == http.StatusOK || bytes.Contains(body, []byte("gzip")) {
			t.Errorf("GET %s was served without an audit line: %d", p, st)
		}
	}
}

type failingNotifier struct{}

func (failingNotifier) Note(string, string, map[string]any) error {
	return os.ErrClosed
}
func (failingNotifier) WriteActive() bool { return false }

func (failingNotifier) AwaitingConfirm() bool { return false }
