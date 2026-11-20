package selfcheck

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterRejectsMistakes(t *testing.T) {
	for name, inv := range map[string]Invariant{
		"no module":   {Name: "rule", Query: "SELECT 0"},
		"upper case":  {Name: "Mod.Rule", Query: "SELECT 0"},
		"not select":  {Name: "mod.a", Query: "DELETE FROM t"},
		"two queries": {Name: "mod.b", Query: "SELECT 0; DELETE FROM t"},
		"duplicate":   {Name: "sqlite.foreign_key_violations", Query: "SELECT 0"},
		"both":        {Name: "mod.c", Query: "SELECT 0", Count: func(context.Context, *sql.DB) (int64, error) { return 0, nil }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: want a panic", name)
				}
			}()
			Register(inv)
		}()
	}
}

func TestCommandReportsCountsAndMissingTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	rw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.ExecContext(t.Context(), `CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1), (2)`); err != nil {
		t.Fatal(err)
	}
	_ = rw.Close()
	invs := []Invariant{
		{Name: "t.none", Query: `SELECT count(*) FROM t WHERE v > 5`},
		{Name: "t.two", Query: `SELECT count(*) FROM t WHERE v > 0`},
		{Name: "t.missing", Query: `SELECT count(*) FROM absent`},
		{Name: "t.counted", Count: func(ctx context.Context, db *sql.DB) (int64, error) {
			var n int64
			err := db.QueryRowContext(ctx, `SELECT sum(v) FROM t`).Scan(&n)
			return n, err
		}},
	}
	var out bytes.Buffer
	err = Command(context.Background(), path, invs, &out)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("want ErrFailed, got %v", err)
	}
	got := out.String()
	for _, want := range []string{" 0  t.none", " 2  t.two", " -  t.missing: ", " 3  t.counted", "3 of 4 invariants"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	// the handle is read-only
	db, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), `INSERT INTO t VALUES (3)`); err == nil {
		t.Error("a write through the selfcheck handle succeeded")
	}
}
