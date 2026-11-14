package sensoractive_test

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// D-592 (migration 0007): sa_probe is rebuilt for the all_ports shape with its rows and its AUTOINCREMENT counter kept, and
// sa_all_ports exists.
func TestMigration0007KeepsTheProbeLog(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(sa.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0007" {
			return err
		}
		b, err := fs.ReadFile(sa.Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "sensor-active", before); err != nil {
		t.Fatal(err)
	}
	exec := func(q string) error {
		return db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err })
	}
	for _, q := range []string{
		`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('j', 'device', '2026-11-01T01:00:00.000Z', 'done')`,
		`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'normal', 50, 1, '-sS', '192.168.1.2', 'ok')`,
		`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'normal', 50, 1, '-sS', '192.168.1.3', 'ok')`,
		`DELETE FROM sa_probe WHERE id = 2`,
	} {
		if err := exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx, db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-14T01:00:00.000Z', 'j', 'all_ports', 50, 1, '-p-', '192.168.1.2', 'ok')`); err != nil {
		t.Fatal(err)
	}
	var id, n int
	if err := db.Reader().QueryRowContext(ctx, `SELECT max(id), count(*) FROM sa_probe`).Scan(&id, &n); err != nil || id != 3 || n != 2 {
		t.Fatalf("max id %d, rows %d (%v): want 3 and 2", id, n, err)
	}
	if err := exec(`INSERT INTO sa_all_ports (asset_id, last_at, outcome) VALUES ('a', '2026-11-14T01:00:00.000Z', 'done')`); err != nil {
		t.Fatal(err)
	}
	if exec(`INSERT INTO sa_all_ports (asset_id, last_at, outcome) VALUES ('b', '2026-11-14T01:00:00.000Z', 'maybe')`) == nil {
		t.Fatal("an unknown outcome was stored")
	}
}
