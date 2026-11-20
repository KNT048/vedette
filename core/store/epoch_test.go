package store_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

func schemaSets(sql string) []store.MigrationSet {
	return []store.MigrationSet{
		{Module: "aaa", FS: fstest.MapFS{"0001_aaa.sql": {Data: []byte("-- +goose Up\n" + sql)}}},
		{Module: "bbb", FS: fstest.MapFS{"0001_bbb.sql": {Data: []byte("-- +goose Up\nCREATE TABLE bbb_t (id INTEGER PRIMARY KEY);\n")}}},
	}
}

func TestMigrateAllStampsANewDatabaseAndAcceptsItAgain(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	sets := schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n")
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatal(err)
	}
	rev, err := store.SchemaRev(sets)
	if err != nil {
		t.Fatal(err)
	}
	e, ok, err := store.EpochOf(t.Context(), db.Reader())
	if err != nil || !ok || e != (store.Epoch{Epoch: store.SchemaEpoch, Rev: rev}) {
		t.Fatalf("epoch row %+v %v %v, want epoch %d rev %s", e, ok, err, store.SchemaEpoch, rev)
	}
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatalf("the same build again: %v", err)
	}
}

func TestMigrateAllRefusesADatabaseItCannotRunOn(t *testing.T) {
	t.Parallel()
	sets := schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n")
	cases := map[string]func(t *testing.T, db *store.DB){
		// a build from before the epoch: its migration tables, no epoch row
		"no epoch row": func(t *testing.T, db *store.DB) {
			if err := store.Migrate(t.Context(), db, "aaa", sets[0].FS); err != nil {
				t.Fatal(err)
			}
		},
		// another pre-release build: its baseline files differ
		"other files": func(t *testing.T, db *store.DB) {
			if err := store.MigrateAll(t.Context(), db, schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY, x TEXT);\n")); err != nil {
				t.Fatal(err)
			}
		},
		"other epoch": func(t *testing.T, db *store.DB) {
			if err := store.MigrateAll(t.Context(), db, sets); err != nil {
				t.Fatal(err)
			}
			if err := db.Write(t.Context(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(t.Context(), "UPDATE core_schema_epoch SET epoch = epoch - 1")
				return err
			}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db := storetest.New(t)
			setup(t, db)
			before := tables(t, db)
			err := store.MigrateAll(t.Context(), db, sets)
			if !errors.Is(err, store.ErrPreRelease) || !strings.Contains(err.Error(), "install.sh --uninstall --yes without --keep-data") {
				t.Fatalf("want the pre-release refusal, got %v", err)
			}
			if after := tables(t, db); after != before {
				t.Fatalf("the refused database was changed: %s -> %s", before, after)
			}
		})
	}
}

// A first start that stops after the stamp (a migration fails) is resumed by the next start of the same build.
func TestMigrateAllResumesAFirstStartThatStoppedHalfway(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	broken := schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n")
	broken[1].FS = fstest.MapFS{"0001_bbb.sql": {Data: []byte("-- +goose Up\nCREATE TABLE bbb_t (id INTEGER PRIMARY KEY, bad);\nNOT SQL;\n")}}
	if err := store.MigrateAll(t.Context(), db, broken); err == nil {
		t.Fatal("a broken migration applied")
	}
	if err := store.CheckEpoch(t.Context(), db, mustRev(t, broken)); err != nil {
		t.Fatalf("the stamped database of the same build is refused: %v", err)
	}
}

func TestSchemaRevChangesWithAnyFile(t *testing.T) {
	t.Parallel()
	a := mustRev(t, schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n"))
	b := mustRev(t, schemaSets("CREATE TABLE aaa_t (id INTEGER  PRIMARY KEY);\n"))
	renamed := schemaSets("CREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n")
	renamed[1].Module = "ccc"
	if a == b || a == mustRev(t, renamed) || len(a) != 64 {
		t.Fatalf("revs %s %s", a, b)
	}
}

func mustRev(t *testing.T, sets []store.MigrationSet) string {
	t.Helper()
	rev, err := store.SchemaRev(sets)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// tables is the names of the database's tables, in one string.
func tables(t *testing.T, db *store.DB) string {
	t.Helper()
	var s string
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT coalesce(group_concat(name, ','), '') FROM (SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name)`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
