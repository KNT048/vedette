// Package storetest holds helpers for module tests: a real SQLite database in a temp dir
// and the migration rules of docs/DATA_MODEL.md section 6.
package storetest

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// New opens a database in t.TempDir(), closed when the test ends.
func New(t testing.TB) *store.DB {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("storetest: open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("storetest: close: %v", err)
		}
	})
	return db
}

// Migration is one module's migrations, applied under its module id.
type Migration struct {
	Module string
	FS     fs.FS
}

// AssertMigrationsUsePrefix checks by effect that a module's migrations touch only objects with its
// table prefix (DATA_MODEL section 1 and section 6 rule 3). It opens a database, applies base (for
// example core's migrations, in order), snapshots sqlite_master and a checksum of every table's
// rows, applies the module's own migrations, and then requires:
//   - every new or changed sqlite_master row has the prefix in both name and tbl_name (goose's own
//     core_migration_<module> table and SQLite internals are ignored; so is any row that
//     disappears, which is reported as a removal),
//   - every table that existed before has the same rows afterwards (no DML into other modules' tables),
//   - at least one object was created.
//
// Statement text is never parsed, so comments, string literals, virtual tables and trigger bodies
// cannot hide anything.
func AssertMigrationsUsePrefix(t testing.TB, module string, fsys fs.FS, prefix string, base ...Migration) {
	t.Helper()
	db := New(t)
	ctx := t.Context()
	for _, m := range base {
		if err := store.Migrate(ctx, db, m.Module, m.FS); err != nil {
			t.Fatalf("storetest: migrate base %s: %v", m.Module, err)
		}
	}
	beforeObjs, beforeSums := snapshot(t, db)
	if err := store.Migrate(ctx, db, module, fsys); err != nil {
		t.Fatalf("storetest: migrate %s: %v", module, err)
	}
	afterObjs, afterSums := snapshot(t, db)

	versionTable := "core_migration_" + strings.ReplaceAll(module, "-", "_")
	created := 0
	for key, after := range afterObjs {
		if after.name == versionTable || strings.HasPrefix(after.name, "sqlite_") {
			continue
		}
		before, existed := beforeObjs[key]
		if existed && before == after {
			continue
		}
		created++
		if !strings.HasPrefix(after.name, prefix) || !strings.HasPrefix(after.tblName, prefix) {
			t.Errorf("migrations of %s: %s %q (on table %q) is outside prefix %q", module, after.typ, after.name, after.tblName, prefix)
		}
	}
	for key, before := range beforeObjs {
		if _, ok := afterObjs[key]; !ok {
			t.Errorf("migrations of %s removed %s %q", module, before.typ, before.name)
		}
	}
	for table, sum := range beforeSums {
		if afterSums[table] != sum {
			t.Errorf("migrations of %s changed the rows of table %q", module, table)
		}
	}
	if created == 0 {
		t.Fatalf("storetest: migrations of %s created nothing (prefix %q)", module, prefix)
	}
}

type object struct{ typ, name, tblName, sql string }

// snapshot returns every sqlite_master row (keyed by type and name) and a checksum of every
// non-internal table's rows.
func snapshot(t testing.TB, db *store.DB) (map[string]object, map[string]string) {
	t.Helper()
	ctx := t.Context()
	rows, err := db.Reader().QueryContext(ctx, "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master")
	if err != nil {
		t.Fatalf("storetest: read sqlite_master: %v", err)
	}
	objs := map[string]object{}
	var tables []string
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.typ, &o.name, &o.tblName, &o.sql); err != nil {
			_ = rows.Close()
			t.Fatalf("storetest: scan sqlite_master: %v", err)
		}
		objs[o.typ+"|"+o.name] = o
		if o.typ == "table" && !strings.HasPrefix(o.name, "sqlite_") {
			tables = append(tables, o.name)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatalf("storetest: read sqlite_master: %v", err)
	}
	sums := map[string]string{}
	for _, tbl := range tables {
		sums[tbl] = checksum(t, db, tbl)
	}
	return objs, sums
}

// checksum is the row count plus a hash over all rows (order-independent, type-tagged values).
func checksum(t testing.TB, db *store.DB, table string) string {
	t.Helper()
	rows, err := db.Reader().QueryContext(t.Context(), `SELECT * FROM "`+strings.ReplaceAll(table, `"`, `""`)+`"`)
	if err != nil {
		t.Fatalf("storetest: read %s: %v", table, err)
	}
	cols, err := rows.Columns()
	if err != nil {
		_ = rows.Close()
		t.Fatalf("storetest: columns of %s: %v", table, err)
	}
	var lines []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			_ = rows.Close()
			t.Fatalf("storetest: scan %s: %v", table, err)
		}
		var b strings.Builder
		for _, v := range vals {
			switch x := v.(type) {
			case []byte:
				fmt.Fprintf(&b, "b:%x;", x)
			default:
				fmt.Fprintf(&b, "%T:%v;", x, x)
			}
		}
		lines = append(lines, b.String())
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatalf("storetest: read %s: %v", table, err)
	}
	slices.Sort(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return fmt.Sprintf("%d:%x", len(lines), h)
}

// NewMigrated is New plus the migrations of one module read from dir (a path relative to the
// test's working directory, e.g. "../../modules/core/migrations/sqlite"). Library packages under
// core/ cannot import modules/, so their tests load the SQL files from disk instead.
func NewMigrated(t testing.TB, module, dir string) *store.DB {
	t.Helper()
	db := New(t)
	if err := store.Migrate(t.Context(), db, module, os.DirFS(dir)); err != nil {
		t.Fatalf("storetest: migrate %s: %v", module, err)
	}
	return db
}
