package main

import (
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/scan"
)

// #164 review H1: the scan window, the schedule and next_run are read in the organization's time zone (core_org), not
// in the process's (UTC in the container), as honeypot and sensor-active do. Otherwise a 02:00 run of a UTC+7 office
// starts at 09:00 local time, on devices people are using.
func TestScanReadsTheOrgTimeZone(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := testServices(t)
	db := d.DB
	// a zone far from the machine's own, so the test fails wherever the process zone is used (UTC on CI, +07 here)
	err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id) VALUES (1, 'Acme', 'America/New_York', 1, 'clean', 'ins-test')
ON CONFLICT (id) DO UPDATE SET timezone = excluded.timezone`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := scanService(d)
	days, from, to, freq, at, on := []int{1, 2, 3, 4, 5, 6, 7}, "22:00", "05:00", "daily", "02:00", true
	if _, err := svc.SaveConfig(ctx, "admin@acme.example", scan.Patch{Days: days, From: &from, To: &to, SchedEnabled: &on, SchedFrequency: &freq, SchedAt: &at}); err != nil {
		t.Fatal(err)
	}
	v, err := svc.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2026-11-11T07:00:00.000Z"; v.NextRun == nil || *v.NextRun != want { // 02:00 in New York (UTC-5)
		t.Fatalf("next_run %v, want %s: the schedule is not read in the organization's time zone", deref(v.NextRun), want)
	}
}

// testServices is a box's services on a migrated database in a temporary directory: the real tables, nothing else running.
func testServices(t *testing.T) deps {
	t.Helper()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	if err := ensureKey(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openMigrated(ctx, filepath.Join(dir, "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	aud := audit.New(nil)
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	d := deps{Log: log, DB: db, Reg: reg, Secrets: sec, Audit: aud, Clock: func() time.Time { return now }, Bus: events.NewBus(log), Argon2: authtest.Cheap}
	if err := buildServices(ctx, &d); err != nil {
		t.Fatal(err)
	}
	return d
}
