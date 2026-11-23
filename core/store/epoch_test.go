package store_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const tableA = "-- +goose Up\nCREATE TABLE aaa_t (id INTEGER PRIMARY KEY);\n"

func schemaSets(sql string) []store.MigrationSet {
	return []store.MigrationSet{
		{Module: "aaa", FS: fstest.MapFS{"0001_aaa.sql": {Data: []byte(sql)}}},
		{Module: "bbb", FS: fstest.MapFS{"0001_bbb.sql": {Data: []byte("-- +goose Up\nCREATE TABLE bbb_t (id INTEGER PRIMARY KEY);\n")}}},
	}
}

// withFile is sets with one more migration file in module aaa.
func withFile(sets []store.MigrationSet, name, sql string) []store.MigrationSet {
	out := make([]store.MigrationSet, len(sets))
	copy(out, sets)
	fsys := maps.Clone(out[0].FS.(fstest.MapFS))
	fsys[name] = &fstest.MapFile{Data: []byte(sql)}
	out[0].FS = fsys
	return out
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestMigrateAllStampsANewDatabaseAndAcceptsItAgain(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	sets := schemaSets(tableA)
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatal(err)
	}
	e, ok, err := store.EpochOf(t.Context(), db.Reader())
	if err != nil || !ok || e != store.SchemaEpoch {
		t.Fatalf("epoch %d %v %v, want %d", e, ok, err, store.SchemaEpoch)
	}
	files, ok, err := store.AppliedFilesOf(t.Context(), db.Reader())
	want := map[store.FileKey]string{{Module: "aaa", Version: 1}: sum(tableA), {Module: "bbb", Version: 1}: sum("-- +goose Up\nCREATE TABLE bbb_t (id INTEGER PRIMARY KEY);\n")}
	if err != nil || !ok || !maps.Equal(files, want) {
		t.Fatalf("applied files %v %v %v, want %v", files, ok, err, want)
	}
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatalf("the same build again: %v", err)
	}
}

// An update to a later build of the same epoch applies its new migrations: nothing about the files the database was made with
// refuses it. Going back to the earlier build keeps working on the newer database (a rollback that keeps the database).
func TestMigrateAllAcceptsAnAddOnlyUpdateAndItsRollback(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	sets := schemaSets(tableA)
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatal(err)
	}
	next := withFile(sets, "0002_aaa_more.sql", "-- +goose Up\nCREATE TABLE aaa_more (id INTEGER PRIMARY KEY);\n")
	if err := store.MigrateAll(t.Context(), db, next); err != nil {
		t.Fatalf("the update to a build with one more migration was refused: %v", err)
	}
	if got := tables(t, db); !strings.Contains(got, "aaa_more") {
		t.Fatalf("the new migration did not run: %s", got)
	}
	files, _, err := store.AppliedFilesOf(t.Context(), db.Reader())
	if err != nil || files[store.FileKey{Module: "aaa", Version: 2}] == "" {
		t.Fatalf("the new file was not recorded: %v %v", files, err)
	}
	if err := store.MigrateAll(t.Context(), db, sets); err != nil {
		t.Fatalf("the earlier build on the newer database: %v", err)
	}
}

func TestMigrateAllRefusesADatabaseItCannotRunOn(t *testing.T) {
	t.Parallel()
	sets := schemaSets(tableA)
	cases := map[string]struct {
		setup func(t *testing.T, db *store.DB)
		want  error
	}{
		// a build from before the epoch: its migration tables, no epoch row
		"no epoch row": {func(t *testing.T, db *store.DB) {
			if err := store.Migrate(t.Context(), db, "aaa", sets[0].FS); err != nil {
				t.Fatal(err)
			}
		}, store.ErrPreRelease},
		"other epoch": {func(t *testing.T, db *store.DB) {
			if err := store.MigrateAll(t.Context(), db, sets); err != nil {
				t.Fatal(err)
			}
			exec(t, db, "UPDATE core_schema_epoch SET epoch = epoch - 1")
		}, store.ErrPreRelease},
		// a build that applied another 0001_aaa.sql: goose would not run this build's copy
		"an applied migration was edited": {func(t *testing.T, db *store.DB) {
			if err := store.MigrateAll(t.Context(), db, schemaSets("-- +goose Up\nCREATE TABLE aaa_t (id INTEGER PRIMARY KEY, x TEXT);\n")); err != nil {
				t.Fatal(err)
			}
		}, store.ErrMigrationChanged},
		// a database stamped by a pre-release build with the hash of all its files, whose baseline was edited since
		"a stamped pre-release database with other files": {func(t *testing.T, db *store.DB) {
			oldStamp(t, db, schemaSets("-- +goose Up\nCREATE TABLE aaa_t (id INTEGER PRIMARY KEY, x TEXT);\n"))
		}, store.ErrPreRelease},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db := storetest.New(t)
			c.setup(t, db)
			before := tables(t, db)
			err := store.MigrateAll(t.Context(), db, sets)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			if !strings.Contains(err.Error(), "install.sh --uninstall --yes without --keep-data") {
				t.Fatalf("the refusal does not say what to do: %v", err)
			}
			if errors.Is(c.want, store.ErrMigrationChanged) && !strings.Contains(err.Error(), "aaa 0001_aaa.sql") {
				t.Fatalf("the refusal does not name the file: %v", err)
			}
			if after := tables(t, db); after != before {
				t.Fatalf("the refused database was changed: %s -> %s", before, after)
			}
		})
	}
}

// A database a pre-release build stamped with the hash of all its migration files (before the applied files were recorded one
// by one) starts on this build when those files are unchanged, also when this build adds a migration; it then has its files.
func TestMigrateAllAdoptsADatabaseStampedByAPreReleaseBuild(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	sets := schemaSets(tableA)
	oldStamp(t, db, sets)
	next := withFile(sets, "0002_aaa_more.sql", "-- +goose Up\nCREATE TABLE aaa_more (id INTEGER PRIMARY KEY);\n")
	if err := store.MigrateAll(t.Context(), db, next); err != nil {
		t.Fatalf("the stamped database of unchanged files is refused: %v", err)
	}
	files, ok, err := store.AppliedFilesOf(t.Context(), db.Reader())
	if err != nil || !ok || len(files) != 3 {
		t.Fatalf("applied files %v %v %v", files, ok, err)
	}
	if err := store.MigrateAll(t.Context(), db, next); err != nil {
		t.Fatalf("again: %v", err)
	}
}

// A first start that stops after the stamp (a migration fails) is resumed by the next start of the same build.
func TestMigrateAllResumesAFirstStartThatStoppedHalfway(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	broken := schemaSets(tableA)
	broken[1].FS = fstest.MapFS{"0001_bbb.sql": {Data: []byte("-- +goose Up\nCREATE TABLE bbb_t (id INTEGER PRIMARY KEY, bad);\nNOT SQL;\n")}}
	if err := store.MigrateAll(t.Context(), db, broken); err == nil {
		t.Fatal("a broken migration applied")
	}
	if err := store.CheckSchema(t.Context(), db, broken); err != nil {
		t.Fatalf("the stamped database of the same build is refused: %v", err)
	}
}

// oldStamp makes db as a pre-release build did: the epoch row with the SHA-256 of all the migration files of sets in its rev
// column, then every migration.
func oldStamp(t *testing.T, db *store.DB, sets []store.MigrationSet) {
	t.Helper()
	h := sha256.New()
	for _, s := range sets {
		for _, name := range []string{"0001_" + s.Module + ".sql"} {
			b := s.FS.(fstest.MapFS)[name].Data
			_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00", s.Module, name, len(b))
			_, _ = h.Write(b)
		}
	}
	exec(t, db, `CREATE TABLE core_schema_epoch (
    id    INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    rev   TEXT    NOT NULL CHECK (length(rev) = 64)
)`)
	exec(t, db, fmt.Sprintf(`INSERT INTO core_schema_epoch (id, epoch, rev) VALUES (1, %d, '%s')`, store.SchemaEpoch, hex.EncodeToString(h.Sum(nil))))
	for _, s := range sets {
		if err := store.Migrate(t.Context(), db, s.Module, s.FS); err != nil {
			t.Fatal(err)
		}
	}
}

func exec(t *testing.T, db *store.DB, q string) {
	t.Helper()
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), q)
		return err
	}); err != nil {
		t.Fatal(err)
	}
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
