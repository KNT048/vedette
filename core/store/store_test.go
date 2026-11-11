package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

func pragma(t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) string {
	t.Helper()
	var v string
	if err := q.QueryRowContext(t.Context(), "PRAGMA "+name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}

func TestOpenPragmas(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)

	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		for name, want := range map[string]string{"journal_mode": "wal", "foreign_keys": "1", "busy_timeout": "5000", "synchronous": "1", "query_only": "0"} {
			if got := pragma(t, tx, name); got != want {
				t.Errorf("writer PRAGMA %s = %q, want %q", name, got, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"journal_mode": "wal", "foreign_keys": "1", "busy_timeout": "5000", "synchronous": "1", "query_only": "1"} {
		if got := pragma(t, db.Reader(), name); got != want {
			t.Errorf("reader PRAGMA %s = %q, want %q", name, got, want)
		}
	}
	if _, err := db.Reader().ExecContext(t.Context(), "CREATE TABLE x (a)"); err == nil {
		t.Error("reader accepted a write")
	}
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	if _, err := store.Open(t.Context(), "", log); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := store.Open(t.Context(), "/nonexistent-dir-for-vedette/db.sqlite", log); err == nil {
		t.Error("missing parent directory accepted")
	}
	if _, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "db.sqlite"), nil); err == nil {
		t.Error("nil logger accepted")
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE t (a INTEGER)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := db.Reader().QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	insert := func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (1)")
		return err
	}

	t.Run("commit", func(t *testing.T) {
		before := count()
		if err := db.Write(ctx, insert); err != nil {
			t.Fatal(err)
		}
		if got := count(); got != before+1 {
			t.Fatalf("count = %d, want %d", got, before+1)
		}
	})
	t.Run("rollback on error", func(t *testing.T) {
		before := count()
		sentinel := errors.New("boom")
		err := db.Write(ctx, func(tx *sql.Tx) error {
			if err := insert(tx); err != nil {
				return err
			}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want sentinel", err)
		}
		if got := count(); got != before {
			t.Fatalf("count = %d, want %d (rolled back)", got, before)
		}
	})
	t.Run("rollback and re-panic", func(t *testing.T) {
		before := count()
		func() {
			defer func() {
				if r := recover(); r != "kaboom" {
					t.Errorf("recovered %v, want kaboom", r)
				}
			}()
			_ = db.Write(ctx, func(tx *sql.Tx) error {
				if err := insert(tx); err != nil {
					return err
				}
				panic("kaboom")
			})
		}()
		if got := count(); got != before {
			t.Fatalf("count = %d, want %d (rolled back)", got, before)
		}
		// The writer connection must be usable again.
		if err := db.Write(ctx, insert); err != nil {
			t.Fatalf("write after panic: %v", err)
		}
	})
	t.Run("concurrent writers serialise without SQLITE_BUSY", func(t *testing.T) {
		before := count()
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for range 32 {
			wg.Go(func() { errs <- db.Write(ctx, insert) })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
		if got := count(); got != before+32 {
			t.Fatalf("count = %d, want %d", got, before+32)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		if err := db.Write(c, insert); err == nil {
			t.Fatal("write with cancelled context succeeded")
		}
	})
}

func TestCheck(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	if err := db.Check(t.Context()); err != nil {
		t.Fatalf("Check on empty db: %v", err)
	}
}

func migrations(sqlText string) fstest.MapFS {
	return fstest.MapFS{"0001_init.sql": {Data: []byte(sqlText)}}
}

const goodMigration = `-- +goose Up
CREATE TABLE zed_thing (id TEXT PRIMARY KEY, n INTEGER NOT NULL);
-- +goose StatementBegin
CREATE TRIGGER zed_thing_guard BEFORE DELETE ON zed_thing
BEGIN
    SELECT RAISE(ABORT, 'no');
END;
-- +goose StatementEnd
`

func objects(ctx context.Context, t *testing.T, db *store.DB) []string {
	t.Helper()
	rows, err := db.Reader().QueryContext(ctx, "SELECT type || ':' || name FROM sqlite_master ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrate(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("applies, records in the module version table, is idempotent", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		if err := store.Migrate(ctx, db, "my-mod", migrations(goodMigration)); err != nil {
			t.Fatal(err)
		}
		first := objects(ctx, t, db)
		for _, want := range []string{"table:zed_thing", "trigger:zed_thing_guard", "table:core_migration_my_mod"} {
			if !contains(first, want) {
				t.Errorf("missing %s in %v", want, first)
			}
		}
		var versions int
		if err := db.Reader().QueryRowContext(ctx, "SELECT count(*) FROM core_migration_my_mod WHERE version_id = 1 AND is_applied = 1").Scan(&versions); err != nil {
			t.Fatal(err)
		}
		if versions != 1 {
			t.Fatalf("version rows for 1 = %d, want 1", versions)
		}
		if err := store.Migrate(ctx, db, "my-mod", migrations(goodMigration)); err != nil {
			t.Fatalf("second run: %v", err)
		}
		if second := objects(ctx, t, db); fmt.Sprint(second) != fmt.Sprint(first) {
			t.Fatalf("schema changed on re-run:\n%v\n%v", first, second)
		}
		if err := db.Reader().QueryRowContext(ctx, "SELECT count(*) FROM core_migration_my_mod WHERE version_id = 1").Scan(&versions); err != nil || versions != 1 {
			t.Fatalf("version rows after re-run = %d (%v), want 1", versions, err)
		}
		if err := db.Check(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("two modules keep separate version tables", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		a := migrations("-- +goose Up\nCREATE TABLE aaa_t (x);\n")
		b := migrations("-- +goose Up\nCREATE TABLE bbb_t (x);\n")
		if err := store.Migrate(ctx, db, "aaa", a); err != nil {
			t.Fatal(err)
		}
		if err := store.Migrate(ctx, db, "bbb", b); err != nil {
			t.Fatal(err)
		}
		got := objects(ctx, t, db)
		for _, want := range []string{"table:core_migration_aaa", "table:core_migration_bbb", "table:aaa_t", "table:bbb_t"} {
			if !contains(got, want) {
				t.Errorf("missing %s in %v", want, got)
			}
		}
	})

	t.Run("rejects bad module ids", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		for _, id := range []string{"", "Core", "1abc", "a b", "a;drop", "a_b", "-a", "a/b", "abcdefghijklmnopqrstuvwxyzabcdefg"} {
			err := store.Migrate(ctx, db, id, migrations(goodMigration))
			if !errors.Is(err, store.ErrMigration) {
				t.Errorf("module %q: err = %v, want ErrMigration", id, err)
			}
		}
	})

	t.Run("forward-only: a Down section is refused and nothing runs", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		withDown := goodMigration + "-- +goose Down\nDROP TABLE zed_thing;\n"
		err := store.Migrate(ctx, db, "zed", migrations(withDown))
		if !errors.Is(err, store.ErrMigration) {
			t.Fatalf("err = %v, want ErrMigration", err)
		}
		if got := objects(ctx, t, db); contains(got, "table:zed_thing") {
			t.Fatalf("migration ran despite Down section: %v", got)
		}
	})

	t.Run("a failing migration leaves no partial schema", func(t *testing.T) {
		t.Parallel()
		db := storetest.New(t)
		bad := "-- +goose Up\nCREATE TABLE zed_ok (x);\nCREATE TABLE zed_ok (x);\n"
		if err := store.Migrate(ctx, db, "zed", migrations(bad)); err == nil {
			t.Fatal("expected error")
		}
		if got := objects(ctx, t, db); contains(got, "table:zed_ok") {
			t.Fatalf("partial schema left behind: %v", got)
		}
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestNewID(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`^au-[a-z2-7]{26}$`)
	general := regexp.MustCompile(`^[\w.-]{1,96}$`)
	seen := map[string]bool{}
	for range 1000 {
		id := store.NewID("au")
		if !re.MatchString(id) || !general.MatchString(id) {
			t.Fatalf("bad id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "Au", "a-b", "1a", "a b"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewID(%q) did not panic", bad)
				}
			}()
			store.NewID(bad)
		}()
	}
}

func TestFormatTS(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("x", 7*3600)
	tests := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 11, 9, 8, 2, 3, 4_999_999, loc), "2026-11-09T01:02:03.004Z"},
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02T03:04:05.000Z"},
	}
	for _, tc := range tests {
		if got := store.FormatTS(tc.in); got != tc.want {
			t.Errorf("FormatTS(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReaderIsReadOnlyAtFileLevel(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE t (a INTEGER)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Reader().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
		t.Fatalf("PRAGMA query_only = 0: %v", err)
	}
	for _, stmt := range []string{"INSERT INTO t VALUES (1)", "CREATE TABLE u (x)", "DELETE FROM t"} {
		if _, err := conn.ExecContext(ctx, stmt); err == nil {
			t.Errorf("reader ran %q with query_only off", stmt)
		}
	}
}

func TestWriteRollsBackOnGoexit(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE t (a INTEGER)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = db.Write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (1)"); err != nil {
				return err
			}
			runtime.Goexit() // what t.FailNow does inside a callback
			return nil
		})
	}()
	<-done

	// The single writer connection must be free again, and the insert must be gone.
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.Write(c, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(c, "SELECT count(*) FROM t").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("count = %d, want 0 (rolled back)", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("writer leaked or insert committed: %v", err)
	}
}

func TestOpenFilePermissions(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	mode := func(p string) os.FileMode {
		t.Helper()
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}
	t.Run("new database is 0600, and so are its WAL files", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "db.sqlite")
		db, err := store.Open(t.Context(), p, log)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		if err := db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), "CREATE TABLE t (a)")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{p, p + "-wal", p + "-shm"} {
			if got := mode(f); got&0o077 != 0 {
				t.Errorf("%s mode %#o", f, got)
			}
		}
	})
	t.Run("existing 0600 file is fine", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "db.sqlite")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(t.Context(), p, log)
		if err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	})
	t.Run("group or other bits are refused", func(t *testing.T) {
		t.Parallel()
		for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
			p := filepath.Join(t.TempDir(), "db.sqlite")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, m); err != nil {
				t.Fatal(err)
			}
			if db, err := store.Open(t.Context(), p, log); err == nil {
				_ = db.Close()
				t.Errorf("mode %#o accepted", m)
			} else if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("mode %#o: unclear error %v", m, err)
			}
		}
	})
	t.Run("directory is refused", func(t *testing.T) {
		t.Parallel()
		if db, err := store.Open(t.Context(), t.TempDir(), log); err == nil {
			_ = db.Close()
			t.Error("directory accepted")
		}
	})
}

// BEGIN IMMEDIATE is taken when the transaction starts, before the callback runs any statement:
// another connection cannot start a write transaction while a Write callback is open.
func TestWriteTakesTheWriteLockImmediately(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	db, err := store.Open(ctx, path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	other, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "_pragma=busy_timeout(0)"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	conn, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	err = db.Write(ctx, func(*sql.Tx) error { // no statement run here
		_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		if err == nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
			t.Error("second connection got the write lock while Write was open")
		} else if !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "BUSY") {
			t.Errorf("unexpected error: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("lock not released after Write: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE u (id TEXT PRIMARY KEY, email TEXT UNIQUE, n INTEGER CHECK (n > 0))")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	try := func(q string) error {
		return db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err })
	}
	if err := try("INSERT INTO u VALUES ('a', 'x@y.z', 1)"); err != nil {
		t.Fatal(err)
	}
	if err := try("INSERT INTO u VALUES ('b', 'x@y.z', 1)"); !store.IsUniqueViolation(err) {
		t.Fatalf("duplicate UNIQUE column: %v", err)
	}
	if err := try("INSERT INTO u VALUES ('a', 'q@y.z', 1)"); !store.IsUniqueViolation(err) {
		t.Fatalf("duplicate primary key: %v", err)
	}
	if err := try("INSERT INTO u VALUES ('c', 'c@y.z', 0)"); err == nil || store.IsUniqueViolation(err) {
		t.Fatalf("a CHECK failure is not a unique violation: %v", err)
	}
	if store.IsUniqueViolation(nil) || store.IsUniqueViolation(errors.New("UNIQUE constraint failed")) {
		t.Fatal("only driver errors count")
	}
}

// SnapshotTo runs on its own read-only connection, so it works while a write transaction is open on the writer
// (it used to wait for the writer and so could not finish before the transaction did).
func TestSnapshotToDoesNotNeedTheWriter(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE snap_t (v TEXT)`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO snap_t VALUES ('before')`)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snap.db")
	err := db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO snap_t VALUES ('inside the open transaction')`); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- db.SnapshotTo(ctx, out) }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("SnapshotTo did not finish while the writer was held")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	copyDB, err := store.Open(ctx, out, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = copyDB.Close() })
	var n int
	var first string
	if err := copyDB.Reader().QueryRowContext(ctx, `SELECT count(*), min(v) FROM snap_t`).Scan(&n, &first); err != nil {
		t.Fatal(err)
	}
	if n != 1 || first != "before" {
		t.Errorf("the copy holds %d rows (first %q), want the committed one only", n, first)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("snapshot file mode: %v %v", info, err)
	}
}

// Pins today's behaviour (D-183): goose does not refuse a database newer than the binary, and that is intended.
// An older binary must start on a newer database: D-151 (add-only volume migrations, logs.db is never restored)
// and D-138 (rollback.safe=true means the previous version runs on the new database). Whoever adds a refusal
// here must revisit D-138 and D-151 first.
func TestMigrateStartsOnADatabaseNewerThanTheBinary(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	newer := fstest.MapFS{
		"0001_init.sql": {Data: []byte(goodMigration)},
		"0002_more.sql": {Data: []byte("-- +goose Up\nCREATE TABLE zed_more (id TEXT PRIMARY KEY);\n")},
	}
	if err := store.Migrate(ctx, db, "my-mod", newer); err != nil {
		t.Fatal(err)
	}
	before := objects(ctx, t, db)
	if err := store.Migrate(ctx, db, "my-mod", migrations(goodMigration)); err != nil { // the older binary: only 0001
		t.Fatalf("an older binary must start on a newer database: %v", err)
	}
	if after := objects(ctx, t, db); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("Migrate on a newer database changed the schema:\n%v\n%v", before, after)
	}
	var top int
	if err := db.Reader().QueryRowContext(ctx, "SELECT max(version_id) FROM core_migration_my_mod WHERE is_applied = 1").Scan(&top); err != nil || top != 2 {
		t.Fatalf("applied version = %d (%v), want 2 untouched", top, err)
	}
}
