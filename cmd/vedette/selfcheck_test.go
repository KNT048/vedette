package main

import (
	"bytes"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
)

func migratedDBFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vedette.db")
	if err := writeMigrated(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSelfcheckFreshDatabaseHoldsEveryInvariant(t *testing.T) {
	path := migratedDBFile(t)
	var out, errOut bytes.Buffer
	if err := run(t.Context(), []string{"selfcheck", "-db", path}, &out, &errOut); err != nil {
		t.Fatalf("selfcheck on a fresh database: %v\n%s", err, out.String())
	}
	for _, inv := range selfcheck.Registered() {
		if f := strings.Fields(lineOf(out.String(), inv.Name)); len(f) != 3 || f[0] != "ok" || f[1] != "0" {
			t.Errorf("invariant %s: want an ok line with count 0, got %v", inv.Name, f)
		}
	}
	if len(selfcheck.Registered()) < 4 {
		t.Errorf("only %d invariants registered", len(selfcheck.Registered()))
	}
}

func TestSelfcheckFailsOnAViolationAndNeverWrites(t *testing.T) {
	path := migratedDBFile(t)
	db, err := store.Open(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	err = db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO core_job_run (id, module, job, started_at, finished_at, status)
			VALUES ('r1', 'core', 'j', '2026-01-02T00:00:00.000Z', '2026-01-01T00:00:00.000Z', 'ok')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(t.Context(), []string{"selfcheck", "-db", path}, &out, &bytes.Buffer{})
	if !errors.Is(err, selfcheck.ErrFailed) {
		t.Fatalf("want ErrFailed, got %v\n%s", err, out.String())
	}
	if f := strings.Fields(lineOf(out.String(), "core.job_run_ends_after_start")); len(f) != 3 || f[0] != "FAIL" || f[1] != "1" {
		t.Errorf("the violated invariant is not reported with count 1:\n%s", out.String())
	}
	after, err := os.ReadFile(path) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("selfcheck changed the database file")
	}
}

func TestSelfcheckRefusesAMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.db")
	if err := run(t.Context(), []string{"selfcheck", "-db", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("want an error for a missing database")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("selfcheck created the database file")
	}
}

func lineOf(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasSuffix(l, " "+name) {
			return l
		}
	}
	return ""
}
