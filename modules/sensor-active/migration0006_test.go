package sensoractive_test

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// D-523 (migration 0006): the rebuild of sa_probe keeps its rows and AUTOINCREMENT counter, and the table takes the normal shape's
// flags with their -p list (about 4,000 characters), still refusing flags longer than 6000.
func TestMigration0006TakesTheLANPortList(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(sa.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0006" {
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
	exec := func(q string, args ...any) error {
		return db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err })
	}
	const insert = `INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-14T01:00:00.000Z', 'j', 'normal', 50, 1, ?, '192.168.1.9', 'ok')`
	normal, _ := nmapargv.Flags(nmapargv.Normal, 50)
	flags := strings.Join(normal, " ")
	for _, q := range []string{
		`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('j', 'device', '2026-11-01T01:00:00.000Z', 'done')`,
		`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'sweep', 1, 1, '-sn', '192.168.1.1', 'ok')`,
		`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'sweep', 1, 1, '-sn', '192.168.1.2', 'ok')`,
		`DELETE FROM sa_probe WHERE id = 2`, // the prune of an old row
	} {
		if err := exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if exec(insert, flags) == nil {
		t.Fatal("before 0006 the long flags fit: the migration is not needed")
	}
	if err := store.Migrate(ctx, db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := exec(insert, flags); err != nil {
		t.Fatalf("%d characters of normal flags refused: %v", len(flags), err)
	}
	if exec(insert, strings.Repeat("x", 6001)) == nil {
		t.Fatal("6001 characters of flags accepted")
	}
	var id int
	var shapes string
	if err := db.Reader().QueryRowContext(ctx, `SELECT max(id), group_concat(shape) FROM sa_probe`).Scan(&id, &shapes); err != nil || id != 3 || shapes != "sweep,normal" {
		t.Fatalf("max id %d, shapes %s (%v), want 3 and sweep,normal", id, shapes, err)
	}
}
