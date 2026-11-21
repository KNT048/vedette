package exposure

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "exposure", Migrations, "exp_", storetest.Migration{Module: "core", FS: core.Migrations})
}

func TestMigrations_Defaults(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	b, err := loadBoxIP(t.Context(), db.Reader())
	if err != nil {
		t.Fatal(err)
	}
	// On by default, every 60 minutes, no check yet
	if !b.Auto || b.IntervalMin != 60 || b.LastRun != nil {
		t.Fatalf("defaults = %+v", b)
	}
}

// The database refuses what the contract forbids, whatever the code does (DATA_MODEL section 6).
func TestMigrations_ConstraintsHold(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	ts := "2026-11-09T10:00:00.000Z"
	parent := `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('t0', 'domain', 'z.example', 'person', 'all', '0123456789abcdef', '` + ts + `')`
	if err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), parent); return err }); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, sql string }{
		{"second settings row", `INSERT INTO exp_setting (id) VALUES (2)`},
		{"last run without ok", `UPDATE exp_setting SET last_run_at = '` + ts + `'`},
		{"unknown kind", `INSERT INTO exp_target (id, kind, value, origin, token, created_at) VALUES ('x1', 'host', 'a.example', 'person', '', '` + ts + `')`},
		{"unknown origin", `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('x1', 'domain', 'a.example', 'robot', 'all', '0123456789abcdef', '` + ts + `')`},
		{"IP with a token", `INSERT INTO exp_target (id, kind, value, origin, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', 'box', '0123456789abcdef', '` + ts + `')`},
		{"IP with a scope", `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', 'box', 'all', '', '` + ts + `')`},
		{"domain without a scope", `INSERT INTO exp_target (id, kind, value, origin, token, created_at) VALUES ('x1', 'domain', 'a.example', 'person', '0123456789abcdef', '` + ts + `')`},
		{"domain without a 16 character token", `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('x1', 'domain', 'a.example', 'person', 'all', 'abc', '` + ts + `')`},
		{"IP verified by TXT", `INSERT INTO exp_target (id, kind, value, origin, method, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', 'box', 'dns_txt', '', '` + ts + `')`},
		{"a box IP with a proof file", `INSERT INTO exp_target (id, kind, value, origin, proof_method, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', 'box', 'ip_file', '', '` + ts + `')`},
		{"timestamp without milliseconds", `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('x1', 'domain', 'a.example', 'person', 'all', '0123456789abcdef', '2026-11-09T10:00:00Z')`},
		{"a commitment that is disruptive", `INSERT INTO exp_consent (target_id, kind, version, text, by_name, disruptive, at) VALUES ('t0', 'commitment', 'v', 's', 'u', 1, '` + ts + `')`},
		{"a service in no state", `INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id) VALUES ('s1', 't0', '8.8.8.8', 443, 'tcp', 'probed', 'gone', '` + ts + `', '` + ts + `', 'r')`},
		{"a service on port 0", `INSERT INTO exp_service (id, target_id, ip, port, proto, ident, state, first_seen, last_seen, last_run_id) VALUES ('s1', 't0', '8.8.8.8', 0, 'tcp', 'probed', 'open', '` + ts + `', '` + ts + `', 'r')`},
		{"a handled issue without a resolution", `INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id) VALUES ('i1', 't0', 'zap', 'k', 't', 'high', 'handled', '` + ts + `', '` + ts + `', 'r')`},
		{"an open issue with a resolution", `INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, resolution, resolved_by, resolved_at, first_seen, last_seen, last_run_id) VALUES ('i1', 't0', 'zap', 'k', 't', 'high', 'open', 'patched', 'u', '` + ts + `', '` + ts + `', '` + ts + `', 'r')`},
		{"an issue of an unknown severity", `INSERT INTO exp_issue (id, target_id, engine, key, title, severity, state, first_seen, last_seen, last_run_id) VALUES ('i1', 't0', 'zap', 'k', 't', 'urgent', 'open', '` + ts + `', '` + ts + `', 'r')`},
	}
	for _, c := range cases {
		err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), c.sql); return err })
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	good := `INSERT INTO exp_target (id, kind, value, origin, scope_mode, token, created_at) VALUES ('x1', 'domain', 'a.example', 'person', 'all', '0123456789abcdef', '` + ts + `')`
	if err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), good); return err }); err != nil {
		t.Fatalf("a valid row was refused: %v", err)
	}
	dup := strings.Replace(good, "'x1'", "'x2'", 1)
	if err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), dup); return err }); err == nil || !store.IsUniqueViolation(err) {
		t.Fatalf("a second target with the same value: %v", err)
	}
}

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "exposure", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
