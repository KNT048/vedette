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
	// kien 2026-11-09: on by default, every 60 minutes, no check yet
	if !b.Auto || b.IntervalMin != 60 || b.LastRun != nil {
		t.Fatalf("defaults = %+v", b)
	}
}

// The database refuses what the contract forbids, whatever the code does (DATA_MODEL section 6).
func TestMigrations_ConstraintsHold(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	ts := "2026-11-09T10:00:00.000Z"
	cases := []struct{ name, sql string }{
		{"interval below 1", `UPDATE exp_setting SET interval_min = 0`},
		{"interval above 1440", `UPDATE exp_setting SET interval_min = 1441`},
		{"auto neither 0 nor 1", `UPDATE exp_setting SET auto = 2`},
		{"second settings row", `INSERT INTO exp_setting (id) VALUES (2)`},
		{"last run without ok", `UPDATE exp_setting SET last_run_at = '` + ts + `'`},
		{"unknown kind", `INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('x1', 'host', 'a.example', '', '` + ts + `')`},
		{"IP with a token", `INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', '0123456789abcdef', '` + ts + `')`},
		{"domain without a 16 character token", `INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('x1', 'domain', 'a.example', 'abc', '` + ts + `')`},
		{"IP verified by TXT", `INSERT INTO exp_target (id, kind, value, method, token, created_at) VALUES ('x1', 'ip', '8.8.8.8', 'dns_txt', '', '` + ts + `')`},
		{"half a commitment", `INSERT INTO exp_target (id, kind, value, token, commitment_by, created_at) VALUES ('x1', 'domain', 'a.example', '0123456789abcdef', 'u', '` + ts + `')`},
		{"timestamp without milliseconds", `INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('x1', 'domain', 'a.example', '0123456789abcdef', '2026-11-09T10:00:00Z')`},
	}
	for _, c := range cases {
		err := db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), c.sql); return err })
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	good := `INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('x1', 'domain', 'a.example', '0123456789abcdef', '` + ts + `')`
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
