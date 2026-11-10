package core_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/core"
)

// testModule is a module of the test box with what the real ones have: a parent and a child table (a foreign key and an
// AUTOINCREMENT counter), a seed row a fresh install has, an append-only log with a delete trigger, and columns that look like
// secrets (one that must stay out of the export) or hold bytes.
var testModule = fstest.MapFS{"0001_tm.sql": &fstest.MapFile{Data: []byte(`-- +goose Up
CREATE TABLE tm_parent (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE tm_child (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id  TEXT NOT NULL REFERENCES tm_parent (id),
    note       TEXT,
    api_secret TEXT,
    token_hash TEXT,
    blobby     BLOB,
    last4      TEXT,
    secret_last4 TEXT
);
CREATE TABLE tm_seed (id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), v TEXT NOT NULL);
INSERT INTO tm_seed (id, v) VALUES (1, 'fresh');
CREATE TABLE tm_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, line TEXT NOT NULL);
-- +goose StatementBegin
CREATE TRIGGER tm_log_no_delete BEFORE DELETE ON tm_log
BEGIN
    SELECT RAISE(ABORT, 'tm_log is append-only');
END;
-- +goose StatementEnd
`)}}

type dataWorld struct {
	*world
	dir      string
	restarts chan struct{}
}

// newDataWorld is a box with a data directory, the schema of core and of the test module, and a restart hook.
func newDataWorld(t *testing.T) *dataWorld {
	t.Helper()
	dir := t.TempDir()
	restarts := make(chan struct{}, 4)
	w := newWorldWith(t, func(hc *core.HandlersConfig) {
		hc.DataDir = dir
		hc.DataFiles = []string{"logs.db"}
		hc.Schema = []core.SchemaSet{{Module: "core", FS: core.Migrations}, {Module: "tm", FS: testModule}}
		hc.Restart = func() { restarts <- struct{}{} }
	})
	if err := store.Migrate(t.Context(), w.env.DB, "tm", testModule); err != nil {
		t.Fatal(err)
	}
	return &dataWorld{world: w, dir: dir, restarts: restarts}
}

func (w *world) exec(q string, args ...any) {
	w.t.Helper()
	err := w.env.DB.Write(w.t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(w.t.Context(), q, args...)
		return err
	})
	if err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
}

// tableCounts counts the rows of every data table, found in sqlite_master and not from a list.
func (w *world) tableCounts() map[string]int {
	w.t.Helper()
	rows, err := w.env.DB.Reader().QueryContext(w.t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB 'core_migration_*'`)
	if err != nil {
		w.t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			w.t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		w.t.Fatal(err)
	}
	out := map[string]int{}
	for _, n := range names {
		out[n] = w.env.Count(w.t, `SELECT count(*) FROM "`+n+`"`)
	}
	return out
}

// plant puts data in the test module and the files next to the database, and returns the paths that a purge must remove and
// the ones it must keep.
func (w *dataWorld) plant() (gone, kept []string) {
	w.t.Helper()
	w.exec(`INSERT INTO tm_parent (id, name) VALUES ('p1', 'parent')`)
	w.exec(`INSERT INTO tm_child (parent_id, note, api_secret, token_hash, blobby, last4, secret_last4) VALUES ('p1', 'child note', 'PLANT-api-secret-0001', 'PLANT-token-hash-0002', x'deadbeef', 'abcd', 'wxyz')`)
	w.exec(`INSERT INTO tm_log (line) VALUES ('one'), ('two')`)
	w.exec(`UPDATE tm_seed SET v = 'changed'`)
	if err := w.env.DB.Write(w.t.Context(), func(tx *sql.Tx) error {
		_, _, err := w.env.Secrets.Seal(w.t.Context(), tx, "test_plant", []byte("planted secret"), true)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	for _, n := range []string{"logs.db", "logs.db-wal", "logs.db-shm", "logs.db-journal"} {
		gone = append(gone, w.file(n, "log line"))
	}
	gone = append(gone, w.file("snapshots/0123456789abcdef0123456789abcdef/vedette.db", "old copy"), w.file("snapshots/0123456789abcdef0123456789abcdef.meta", "{}"))
	kept = append(kept, w.file("vedette.key", "key"), w.file("vedette-selfsigned.crt", "cert"), w.file("vedette-selfsigned.key", "certkey"), w.file("other-module.db", "x"))
	return gone, kept
}

func (w *dataWorld) file(rel, content string) string {
	w.t.Helper()
	p := filepath.Join(w.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// POST /core/data/purge with the right name: every table is back to what a fresh install has (counted from sqlite_master, the
// seed row of the module is back, the rest is empty), the logs file and the snapshots are gone, the key and the certificate
// are not, the session is over, setup is open again with its one-time code, the audit chain starts again with one row and
// verifies, the modules are at their defaults, and the process is asked to restart.
func TestContract_INV14_PurgeBringsBackAFreshInstall(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	admin := w.setupAdmin()
	wantOK(t, admin.patch("/modules/exposure", map[string]any{"enabled": true}), 200)
	if !w.reg.Enabled("exposure") {
		t.Fatal("exposure should be on before the purge")
	}
	gone, kept := w.plant()
	before := w.tableCounts()
	for _, n := range []string{"core_user", "core_session", "core_audit", "core_org", "core_secret", "tm_child", "tm_log"} {
		if before[n] == 0 {
			t.Fatalf("test setup: table %s is empty before the purge", n)
		}
	}
	nTriggers := w.env.Count(t, `SELECT count(*) FROM sqlite_master WHERE type = 'trigger'`)

	r := admin.post("/core/data/purge", map[string]any{"confirm": "Acme Co"})
	wantOK(t, r, 200)
	removed, _ := r.JSON["removed"].(map[string]any)
	if r.JSON["ok"] != true || removed["core_user"] != float64(1) || removed["tm_child"] != float64(1) || removed["tm_log"] != float64(2) {
		t.Fatalf("purge = %s", r.Raw)
	}
	if _, has := removed["tm_seed"]; has || removed["core_migration_core"] != nil {
		t.Fatalf("removed lists a seed or a migration table: %s", r.Raw)
	}

	// Every table: the fresh state.
	want := map[string]int{
		"core_audit": 1, "core_chain_head": 1, "core_secret": 1, // the purge's own row, its chain head, the new setup code
		"tm_seed":     1,
		"core_module": 0, // set below: one row per module of the build
	}
	want["core_module"] = len(w.reg.List())
	for n, c := range w.tableCounts() {
		if c != want[n] {
			t.Errorf("table %s has %d rows after the purge, want %d", n, c, want[n])
		}
	}
	var v string
	if err := w.env.DB.Reader().QueryRowContext(t.Context(), `SELECT v FROM tm_seed`).Scan(&v); err != nil || v != "fresh" {
		t.Errorf("tm_seed = %q, %v: the seed row of a fresh install is not back", v, err)
	}
	if n := w.env.Count(t, `SELECT count(*) FROM sqlite_master WHERE type = 'trigger'`); n != nTriggers {
		t.Errorf("triggers: %d after the purge, %d before", n, nTriggers)
	}
	if err := w.env.DB.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), `DELETE FROM core_audit`); return err }); err == nil {
		t.Error("core_audit can be deleted from after the purge: its trigger was not restored")
	}
	if n := w.env.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'data.purge' AND user = 'system' AND seq = 1`); n != 1 {
		t.Error("the audit log is not one data.purge row with seq 1")
	}
	if n := w.env.Count(t, `SELECT count(*) FROM core_audit WHERE detail LIKE '%@%' OR target LIKE '%admin%'`); n != 0 {
		t.Error("the purge row names a person")
	}
	if res, err := audit.Verify(t.Context(), w.env.DB.Reader()); err != nil || !res.OK || res.Count != 1 {
		t.Errorf("audit chain after the purge = %+v, %v", res, err)
	}

	// Files.
	for _, p := range gone {
		if exists(p) {
			t.Errorf("%s survived the purge", p)
		}
	}
	if exists(filepath.Join(w.dir, "snapshots")) {
		t.Error("snapshots/ survived the purge")
	}
	for _, p := range kept {
		if !exists(p) {
			t.Errorf("%s was removed by the purge", p)
		}
	}

	// The session is over and setup is open again.
	if admin.signedIn() {
		t.Error("the purge left the session cookie")
	}
	wantStatus(t, admin.get("/me"), 401, "unauthenticated")
	if s := w.client().get("/setup"); s.JSON["complete"] != false || s.JSON["org"] != "" {
		t.Errorf("GET /setup = %s", s.Raw)
	}
	if w.reg.Enabled("exposure") {
		t.Error("the module cache still says exposure is on")
	}
	if n := w.env.Count(t, `SELECT count(*) FROM core_module WHERE enabled`); n < 1 {
		t.Error("core is not on after the purge")
	}
	select {
	case <-w.restarts:
	case <-time.After(5 * time.Second):
		t.Error("the process was not asked to restart")
	}

	// The one-time code is in the log and a first-run setup works on the purged box.
	code, err := w.h.EnsureSetupCode(t.Context())
	if err != nil || code == "" || !strings.Contains(w.logs.String(), code) {
		t.Fatalf("setup code after the purge = %q, %v (in the log: %v)", code, err, strings.Contains(w.logs.String(), code))
	}
	fresh := w.client()
	wantOK(t, fresh.post("/core/setup", setupBody(code)), 200)
	wantOK(t, fresh.get("/me"), 200)
}

// A wrong or empty name changes nothing: not a row, not a file; and not even the scratch directory is left.
func TestContract_INV14_WrongNameDeletesNothing(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	admin := w.setupAdmin()
	gone, kept := w.plant()
	before := w.tableCounts()
	for _, name := range []string{"acme co", "Acme Co ", "Acme", "", "Acme Co​"} {
		wantStatus(t, admin.post("/core/data/purge", map[string]any{"confirm": name}), 400, "confirm_mismatch")
	}
	wantStatus(t, admin.post("/core/data/purge", map[string]any{}), 400, "invalid") // no field at all: the server's own check
	after := w.tableCounts()
	for n, c := range before {
		if after[n] != c {
			t.Errorf("table %s: %d rows before, %d after a refused purge", n, c, after[n])
		}
	}
	for _, p := range append(gone, kept...) {
		if !exists(p) {
			t.Errorf("%s was removed by a refused purge", p)
		}
	}
	wantOK(t, admin.get("/me"), 200)
	if entries, _ := os.ReadDir(filepath.Join(w.dir, "tmp")); len(entries) != 0 {
		t.Errorf("a refused purge left %d entries in tmp", len(entries))
	}
	select {
	case <-w.restarts:
		t.Error("a refused purge asked for a restart")
	case <-time.After(700 * time.Millisecond):
	}
}

// A failure while the files go (here: a data file that is a directory with something in it) rolls every row back: the purge
// can be tried again.
func TestContract_INV14_FailureRollsEverythingBack(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	admin := w.setupAdmin()
	w.file("logs.db/inside", "x") // os.Remove cannot remove a directory that is not empty
	before := w.tableCounts()
	r := admin.post("/core/data/purge", map[string]any{"confirm": "Acme Co"})
	if r.Code != 500 {
		t.Fatalf("purge = %d %s, want 500", r.Code, r.Raw)
	}
	for n, c := range w.tableCounts() {
		if before[n] != c {
			t.Errorf("table %s: %d rows before, %d after a failed purge", n, before[n], c)
		}
	}
	wantOK(t, admin.get("/me"), 200)
	if res, err := audit.Verify(t.Context(), w.env.DB.Reader()); err != nil || !res.OK {
		t.Errorf("audit chain after a failed purge = %+v, %v", res, err)
	}
}

// Only an administrator may export or purge; the refusal changes nothing.
func TestData_ExportAndPurgeAreAdminOnly(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	w.setupAdmin()
	before := w.tableCounts()
	for _, role := range []string{"viewer", "operator"} {
		c, _ := w.signIn(role+"@acme.example", role)
		wantStatus(t, c.get("/core/data/export"), 403, "forbidden")
		wantStatus(t, c.post("/core/data/purge", map[string]any{"confirm": "Acme Co"}), 403, "forbidden")
	}
	after := w.tableCounts()
	if after["core_user"] != before["core_user"]+2 || after["core_org"] != 1 {
		t.Errorf("counts changed by a refused purge: %v -> %v", before, after)
	}
	wantStatus(t, w.client().get("/core/data/export"), 401, "unauthenticated")
}

// The data file list is names, never paths.
func TestData_FileNamesAreCheckedAtStart(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"../x.db", "a/b.db", "/etc/passwd", "", "Logs.db", "vedette.db", "vedette.key", "snapshots", "tmp", ".hidden", "a b"} {
		if err := core.CheckDataFilesForTest([]string{bad}); err == nil {
			t.Errorf("data file %q accepted", bad)
		}
	}
	if err := core.CheckDataFilesForTest([]string{"logs.db", "other-module.db"}); err != nil {
		t.Errorf("plain names refused: %v", err)
	}
}

// exportOf downloads the export and decodes it.
func exportOf(t *testing.T, c *client) (reply, map[string]any) {
	t.Helper()
	r := c.get("/core/data/export")
	wantOK(t, r, 200)
	var doc map[string]any
	if err := json.Unmarshal([]byte(r.Raw), &doc); err != nil {
		t.Fatalf("the export is not JSON: %v\n%.300s", err, r.Raw)
	}
	return r, doc
}

// GET /core/data/export: a dated attachment that is never cached, written for the administrator in core_audit, with the data
// of the box and no secret in it. Secrets are planted in every table and column that holds one; the file is searched for each.
func TestContract_INV26_ExportHoldsNoSecretMaterial(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	admin := w.setupAdmin()
	w.plant()
	user, _ := w.signIn("ann@acme.example", "viewer")
	// Secret-bearing rows of core: a secret, a TOTP seed, an email code, a connection's secret.
	var sealed string
	err := w.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		id, _, err := w.env.Secrets.Seal(t.Context(), tx, "test_export", []byte("PLANT-plaintext-secret-0003"), true)
		sealed = id
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var userID string
	if err := w.env.DB.Reader().QueryRowContext(t.Context(), `SELECT id FROM core_user WHERE email = 'ann@acme.example'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	w.exec(`INSERT INTO core_user_totp (user_id, secret_id, confirmed, last_step, created_at) VALUES (?, ?, 1, 5, '2026-11-09T08:00:00.000Z')`, userID, sealed)
	w.exec(`INSERT INTO core_email_code (user_id, code_hash, expires_at, tries, sent_at) VALUES (?, ?, '2026-11-09T09:00:00.000Z', 0, '2026-11-09T08:00:00.000Z')`, userID, strings.Repeat("c0de", 16))

	r, doc := exportOf(t, admin)
	if cd := r.Header.Get("Content-Disposition"); cd != "attachment; filename=vedette-export-2026-11-09.json" {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.Header.Get("Cache-Control"))
	}
	if doc["format"] != "vedette-export/1" || doc["org"] != "Acme Co" || doc["truncated"] != false || doc["exported_at"] == nil {
		t.Errorf("export head = %v", doc)
	}
	tables, _ := doc["tables"].(map[string]any)
	if rows, _ := tables["core_user"].([]any); len(rows) != 2 {
		t.Errorf("core_user rows in the export = %v", tables["core_user"])
	}
	if rows, _ := tables["tm_child"].([]any); len(rows) != 1 {
		t.Fatalf("tm_child rows in the export = %v", tables["tm_child"])
	} else if row := rows[0].(map[string]any); row["note"] != "child note" || row["last4"] != "abcd" || row["secret_last4"] != "wxyz" || len(row) != 5 {
		t.Errorf("tm_child row = %v (id, parent_id, note, last4 and secret_last4 only)", row)
	}
	if rows, _ := tables["core_audit"].([]any); len(rows) == 0 || rows[0].(map[string]any)["hash"] == nil {
		t.Errorf("the audit log, with its hashes, is not in the export")
	}

	// Nothing secret: whole tables and columns that are left out are searched for in the file.
	for _, name := range []string{"core_secret", "core_session", "core_user_totp", "core_email_code", "core_email_code_send", "core_sensor_cert"} {
		if _, has := tables[name]; has {
			t.Errorf("table %s is in the export", name)
		}
	}
	for _, key := range []string{`"password_hash"`, `"token_hash"`, `"csrf_hash"`, `"code_hash"`, `"secret_id"`, `"api_secret"`, `"ciphertext"`, `"nonce"`, `"blobby"`} {
		if strings.Contains(r.Raw, key) {
			t.Errorf("the export has the column %s", key)
		}
	}
	secrets := []string{authtest.Password, "PLANT-api-secret-0001", "PLANT-token-hash-0002", "PLANT-plaintext-secret-0003", strings.Repeat("c0de", 16), "deadbeef"}
	for _, ck := range []string{auth.CookieSession, auth.CookieCSRF} {
		secrets = append(secrets, user.cookie(ck).Value, admin.cookie(ck).Value)
	}
	// Every value of a column or table the policy leaves out, read from the database itself.
	for _, q := range []string{
		`SELECT password_hash FROM core_user`, `SELECT token_hash FROM core_session`, `SELECT csrf_hash FROM core_session`,
		`SELECT code_hash FROM core_email_code`, `SELECT id FROM core_secret`, `SELECT hex(ciphertext) FROM core_secret`, `SELECT hex(nonce) FROM core_secret`,
		`SELECT api_secret FROM tm_child`, `SELECT token_hash FROM tm_child`,
	} {
		rows, err := w.env.DB.Reader().QueryContext(t.Context(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		n := 0
		for rows.Next() {
			var s sql.NullString
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			if len(s.String) >= 8 {
				secrets = append(secrets, s.String)
				n++
			}
		}
		_ = rows.Close()
		if n == 0 {
			t.Errorf("nothing planted for %q", q)
		}
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(r.Raw, s) {
			t.Errorf("the export contains the secret %.12q...", s)
		}
	}
	if n := w.env.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'data.export' AND user = 'admin@acme.example'`); n != 1 {
		t.Errorf("data.export audit rows = %d, want 1 with the administrator's name", n)
	}
	exportOf(t, admin) // the slot was given back: a second export works
}

// The export is written row by row and stops at its cap: over it the file ends early with truncated:true and the table it
// stopped in, is still valid JSON and never longer than the cap.
func TestContract_INV26_ExportStopsAtItsCap(t *testing.T) {
	t.Parallel()
	w := newDataWorld(t)
	admin := w.setupAdmin()
	w.exec(`INSERT INTO tm_parent (id, name) VALUES ('p1', 'parent')`)
	err := w.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		for i := range 5000 {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO tm_child (parent_id, note) VALUES ('p1', ?)`, fmt.Sprintf("row %d %s", i, strings.Repeat("x", 100))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, full := exportOf(t, admin)
	if full["truncated"] != false || len(full["tables"].(map[string]any)["tm_child"].([]any)) != 5000 {
		t.Fatalf("the uncapped export is not whole")
	}
	for _, limit := range []int64{600 << 10, 20 << 10, 1 << 10} {
		w.h.SetExportCapForTest(limit)
		r, doc := exportOf(t, admin)
		if int64(len(r.Raw)) > limit {
			t.Errorf("cap %d: the file is %d bytes", limit, len(r.Raw))
		}
		if doc["truncated"] != true || doc["truncated_in"] == nil {
			t.Errorf("cap %d: truncated = %v, truncated_in = %v", limit, doc["truncated"], doc["truncated_in"])
		}
	}
}
