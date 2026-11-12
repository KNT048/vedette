package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Every wiring test needs a database with all modules' migrations. Under -race those migrations take about 3.5 s of pure SQLite work
// (0.13 s without), and about 150 tests ran them. The migrations run once per test process into a template file; each test copies
// the file and opens the copy, so a test still has its own database in the same state migrateAll(wiredModules()) leaves.
var (
	tplOnce sync.Once
	tplDir  string
	tplErr  error
)

func templatePath() (string, error) {
	tplOnce.Do(func() {
		tplDir, tplErr = os.MkdirTemp("", "vedette-migrated-")
		if tplErr != nil {
			return
		}
		ctx := context.Background()
		p := filepath.Join(tplDir, "template.db")
		db, err := store.Open(ctx, p, slog.New(slog.DiscardHandler))
		if err != nil {
			tplErr = err
			return
		}
		if err := migrateAll(ctx, db, wiredModules()); err != nil {
			_ = db.Close()
			tplErr = err
			return
		}
		if tplErr = db.Close(); tplErr != nil {
			return
		}
		for _, ext := range []string{"-wal", "-shm"} { // a closed WAL database has none; a copy without them would silently lose pages
			if _, err := os.Stat(p + ext); err == nil {
				tplErr = fmt.Errorf("the template database left %s behind", ext)
			}
		}
	})
	return filepath.Join(tplDir, "template.db"), tplErr
}

// openMigrated is store.Open on path followed by migrateAll(wiredModules()), from the template.
func openMigrated(ctx context.Context, path string, log *slog.Logger) (*store.DB, error) {
	if err := writeMigrated(path); err != nil {
		return nil, err
	}
	return store.Open(ctx, path, log)
}

// writeMigrated writes the template to path (0600): a database file that every wired module's migrations were applied to.
func writeMigrated(path string) error {
	tpl, err := templatePath()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(tpl) //nolint:gosec // tpl is the template this process made in its own temp directory
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600) //nolint:gosec // path is a test's own t.TempDir() file
}

// seedMigrated puts a migrated database at path before a test runs the real process on it, so the process starts on a box whose
// schema is already there (its migrations are then a check of the versions) instead of migrating ~30 modules under -race (several
// seconds of SQLite work per start). Only for tests that are not about the first migration: TestRunServesAndStops and
// TestRunTwiceOnTheSameFiles still start on an empty file.
func seedMigrated(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeMigrated(path); err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	// Tests that compare formatted times want UTC. Each used to call t.Setenv("TZ", "UTC"), which forbids t.Parallel; once here, for all.
	_ = os.Setenv("TZ", "UTC")
	time.Local = time.UTC
	// No box of this package reaches the internet: every one gets the offline feeds client of the end-to-end run, set here before any
	// test starts (so no parallel test sees the package var change) and never put back. A box on the real client pulled the public feeds
	// at its start and stored them in one transaction that held the database writer for seconds (~13 s measured, more under -race on a
	// loaded runner): the purge and the second first-run setup of TestRunPurgeBringsBackAFreshBoxAndStops queued behind it, past the
	// client timeout or into 503 server_busy, and what any test saw depended on the network.
	e2eOffline()
	code := m.Run()
	if tplDir != "" {
		_ = os.RemoveAll(tplDir)
	}
	os.Exit(code)
}
