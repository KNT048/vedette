package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules"
)

// tableDigest is every row of every data table of db, as text, sorted per table: two databases with the same digest hold the same data.
func tableDigest(t *testing.T, db *sql.DB, tables []string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(tables))
	for _, tbl := range tables {
		rows, err := db.QueryContext(t.Context(), `SELECT * FROM "`+tbl+`"`) //nolint:gosec // a name read from sqlite_master, quoted
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(vals)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, string(b))
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		slices.Sort(lines)
		out[tbl] = strings.Join(lines, "\n")
	}
	return out
}

// A factory reset of a box whose every table of every module holds data: afterwards each table is what a fresh install has (the seed
// rows of the migrations), plus the purge's own audit row and chain head and one row per module. The fresh state is learned from a
// freshly migrated database, so a new table is covered without being named here.
func TestPurge_EveryTableOfEveryModuleIsBackToAFreshInstall(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s := newStackWith(t, func(d *deps) { d.DataDir = t.TempDir() })
	api, err := server.New(server.Config{API: newHandler(ctx, *s.d), Auth: s.d.Auth.Sessions, Modules: s.d.Reg, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	cookies := map[string]*http.Cookie{}
	call := func(method, path string, body any) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req := httptest.NewRequestWithContext(ctx, method, server.Prefix+path, rd)
		req.RemoteAddr, req.Host = "192.0.2.10:40000", "box.test"
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if c, ok := cookies[auth.CookieCSRF]; ok {
			req.Header.Set(auth.HeaderCSRF, c.Value)
		}
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			cookies[c.Name] = c
		}
		return rec.Code, rec.Body.String()
	}
	code, err := s.d.Core.EnsureSetupCode(ctx)
	if err != nil || code == "" {
		t.Fatalf("setup code: %q %v", code, err)
	}
	const password = "correct horse battery staple"
	if c, b := call("POST", "/core/setup", map[string]any{"setup_code": code, "org": "Acme Co", "admin": map[string]any{"name": "Ann", "email": "ann@acme.example", "password": password},
		"lan": []string{"192.168.10.0/24"}, "bundle": "smb", "commitment": true, "accept_terms": true}); c != 200 {
		t.Fatalf("setup = %d %s", c, b)
	}
	planted := plantEveryTable(t, s.d.DB)
	for tbl, n := range dbRowCounts(t, s.d.DB.Reader(), planted) {
		if n == 0 {
			t.Fatalf("table %s is empty before the purge", tbl)
		}
	}

	if c, b := call("POST", "/core/data/purge", map[string]any{"confirm": "Acme Co", "password": password}); c != 200 || !strings.Contains(b, `"ok":true`) {
		t.Fatalf("purge = %d %s", c, b)
	}

	fresh := rowCounts(t, filepath.Join(t.TempDir(), "fresh.db"), true)
	mans, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	nMods := 0
	for _, m := range mans {
		if !m.Component {
			nMods++
		}
	}
	fresh["core_audit"], fresh["core_chain_head"], fresh["core_module"] = 1, 1, nMods
	got := dbRowCounts(t, s.d.DB.Reader(), planted)
	for _, tbl := range planted {
		if got[tbl] != fresh[tbl] {
			t.Errorf("table %s has %d rows after the purge, a fresh install has %d", tbl, got[tbl], fresh[tbl])
		}
	}
	if n := len(moduleSchemaOf(t)); len(planted) != n { // the data tables of a fresh install (a full-text index is not one)
		t.Errorf("%d tables were planted, a fresh install has %d", len(planted), n)
	}
	if n := s.count(`SELECT count(*) FROM pragma_foreign_key_check`); n != 0 {
		t.Errorf("%d rows break a foreign key after the purge", n)
	}
}

// A backup and its restore keep every row of every table of every module: the backup is the snapshot core writes for the host
// (store.SnapshotTo, VACUUM INTO), the restore puts that file in place of the database, and the next start opens it as the box does
// (quick check, then every module's migrations, which find nothing to do). Every table holds data before the backup, and every table
// reads back the same rows after the restore.
func TestBackup_RestoreRoundTripKeepsEveryTable(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	src, err := openMigrated(ctx, filepath.Join(t.TempDir(), "vedette.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	planted := plantEveryTable(t, src)
	want := tableDigest(t, src.Reader(), planted)

	backup := filepath.Join(t.TempDir(), "vedette.db")
	if err := src.SnapshotTo(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(ctx, backup, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	if err := restored.QuickCheck(ctx); err != nil {
		t.Fatalf("the restored database fails the start-up check: %v", err)
	}
	if err := migrateAll(ctx, restored, wiredModules()); err != nil {
		t.Fatalf("the restored database does not start: %v", err)
	}
	got := tableDigest(t, restored.Reader(), planted)
	for _, tbl := range planted {
		if got[tbl] == "" {
			t.Errorf("table %s is empty after the restore", tbl)
		} else if got[tbl] != want[tbl] {
			t.Errorf("table %s differs after the restore:\n got %.300s\nwant %.300s", tbl, got[tbl], want[tbl])
		}
	}
	if gotTables := tableColumns(t, restored); len(gotTables) != len(planted) {
		t.Errorf("%d tables after the restore, %d before", len(gotTables), len(planted))
	}
}

// dbRowCounts counts the rows of the named tables of db.
func dbRowCounts(t *testing.T, db *sql.DB, tables []string) map[string]int {
	t.Helper()
	out := make(map[string]int, len(tables))
	for _, tbl := range tables {
		var n int
		if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM "`+tbl+`"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[tbl] = n
	}
	return out
}

// moduleSchemaOf is the data tables of a freshly migrated vedette.db with their columns.
func moduleSchemaOf(t *testing.T) map[string][][2]string {
	t.Helper()
	db, err := openMigrated(t.Context(), filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	return tableColumns(t, db)
}
