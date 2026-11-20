package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/logs"
)

// The baseline files (one 0001_<module>.sql per module) replace the migration chains in testdata/oldschema. This test proves,
// module by module, that both make the same database: the same sqlite_master rows (SQL text with runs of white space made one
// space) and the same rows in every table. Columns a fresh install fills with the time it migrated are compared by shape.

// timeSeeds are the seed columns that hold the time of the migration.
var timeSeeds = map[string]bool{"notify_box.first_run_at": true, "inv_setting.updated_at": true}

func oldChain(module, dir string) store.MigrationSet {
	return store.MigrationSet{Module: module, FS: os.DirFS(filepath.Join("testdata", "oldschema", "modules", module, "migrations", dir))}
}

func TestBaselinesEqualTheOldMigrationChains(t *testing.T) {
	var oldMain []store.MigrationSet
	for _, s := range migrationSets(wiredModules()) {
		dir := "sqlite"
		if s.Module == logs.ModuleID {
			dir = "config"
		}
		oldMain = append(oldMain, oldChain(s.Module, dir))
	}
	dbs := []struct {
		name     string
		old, new []store.MigrationSet
	}{
		{"vedette.db", oldMain, migrationSets(wiredModules())},
		{"logs.db", []store.MigrationSet{oldChain(logs.ModuleID, "volume")}, []store.MigrationSet{{Module: logs.ModuleID, FS: logs.VolumeMigrations}}},
	}
	for _, d := range dbs {
		oldDB, newDB := storetest.New(t), storetest.New(t)
		for i := range d.old {
			oldObjs, newObjs := masterRows(t, oldDB), masterRows(t, newDB)
			if err := store.Migrate(t.Context(), oldDB, d.old[i].Module, d.old[i].FS); err != nil {
				t.Fatalf("%s: old chain of %s: %v", d.name, d.old[i].Module, err)
			}
			if err := store.Migrate(t.Context(), newDB, d.new[i].Module, d.new[i].FS); err != nil {
				t.Fatalf("%s: baseline of %s: %v", d.name, d.new[i].Module, err)
			}
			gotOld, gotNew := added(masterRows(t, oldDB), oldObjs), added(masterRows(t, newDB), newObjs)
			if !slices.Equal(gotOld, gotNew) {
				t.Errorf("%s: %s: sqlite_master differs\nold chain only: %q\nbaseline only:  %q", d.name, d.new[i].Module, minus(gotOld, gotNew), minus(gotNew, gotOld))
			}
			seeds := 0
			for _, o := range gotNew {
				typ, name, _ := strings.Cut(o, "|")
				if typ != "table" {
					continue
				}
				name, _, _ = strings.Cut(name, "|")
				ro, rn := tableRows(t, oldDB, name), tableRows(t, newDB, name)
				if !slices.Equal(ro, rn) {
					t.Errorf("%s: %s: rows of %s differ\nold chain: %q\nbaseline:  %q", d.name, d.new[i].Module, name, ro, rn)
				}
				seeds += len(rn)
			}
			t.Logf("%s %-14s identical: %3d schema objects, %2d rows", d.name, d.new[i].Module, len(gotNew), seeds)
		}
	}
}

// A database made by the old chains (any build before the baselines) is refused at start, with the words that say what to do,
// and nothing is written to it.
func TestADatabaseOfTheOldChainsIsRefusedAtStart(t *testing.T) {
	db := storetest.New(t)
	for _, s := range migrationSets(wiredModules()) {
		dir := "sqlite"
		if s.Module == logs.ModuleID {
			dir = "config"
		}
		old := oldChain(s.Module, dir)
		if err := store.Migrate(t.Context(), db, old.Module, old.FS); err != nil {
			t.Fatal(err)
		}
	}
	before := masterRows(t, db)
	err := migrateAll(t.Context(), db, wiredModules())
	if !errors.Is(err, store.ErrPreRelease) || !strings.Contains(err.Error(), "pre-release build") || !strings.Contains(err.Error(), "install.sh --uninstall --yes without --keep-data") {
		t.Fatalf("want the pre-release refusal, got %v", err)
	}
	if after := masterRows(t, db); !slices.Equal(before, after) {
		t.Fatalf("the refused database was changed: %q", minus(after, before))
	}
	t.Logf("refused: %v", err)
}

// masterRows is every sqlite_master row but the migration records, as "type|name|tbl_name|sql" with white space normalised.
func masterRows(t *testing.T, db *store.DB) []string {
	t.Helper()
	rows, err := db.Reader().QueryContext(t.Context(), `SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master WHERE name NOT GLOB 'core_migration_*'`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var typ, name, tbl, text string
		if err := rows.Scan(&typ, &name, &tbl, &text); err != nil {
			t.Fatal(err)
		}
		out = append(out, typ+"|"+name+"|"+tbl+"|"+strings.Join(strings.Fields(text), " "))
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func added(after, before []string) []string { return minus(after, before) }

func minus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// tableRows is every row of table, sorted, each as its typed values; a time-of-migration column is checked and masked.
// The goose version tables are left out, so are their counters in sqlite_sequence.
func tableRows(t *testing.T, db *store.DB, table string) []string {
	t.Helper()
	q := `"` + strings.ReplaceAll(table, `"`, `""`) + `"`
	where := ""
	if table == "sqlite_sequence" {
		where = " WHERE name NOT GLOB 'core_migration_*'" // goose's own counter of its version rows
	}
	rows, err := db.Reader().QueryContext(t.Context(), "SELECT * FROM "+q+where)
	if err != nil {
		t.Fatal(err)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(cols))
		for i, v := range vals {
			if timeSeeds[table+"."+cols[i]] {
				s, ok := v.(string)
				if !ok || len(s) != len("2006-01-02T15:04:05.000Z") || !strings.HasSuffix(s, "Z") {
					t.Errorf("%s.%s = %v, want a timestamp", table, cols[i], v)
				}
				v = "<time of the migration>"
			}
			parts[i] = fmt.Sprintf("%s=%T:%v", cols[i], v, v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}
