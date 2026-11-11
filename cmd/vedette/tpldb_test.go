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
	tpl, err := templatePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(tpl)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return store.Open(ctx, path, log)
}

func TestMain(m *testing.M) {
	// Tests that compare formatted times want UTC. Each used to call t.Setenv("TZ", "UTC"), which forbids t.Parallel; once here, for all.
	_ = os.Setenv("TZ", "UTC")
	time.Local = time.UTC
	code := m.Run()
	if tplDir != "" {
		_ = os.RemoveAll(tplDir)
	}
	os.Exit(code)
}
