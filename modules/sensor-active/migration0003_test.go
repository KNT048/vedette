package sensoractive_test

import (
	"database/sql"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// D-511 (migration 0003): the rebuild of sa_probe for the gentle_titles shape keeps the AUTOINCREMENT counter, so the id of a pruned
// probe row is never handed out again (an export of the probe log is keyed by it), and the table takes the new shape.
func TestMigration0003KeepsTheProbeCounter(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(sa.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0003" {
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
	exec := func(q string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('j', 'sweep', '2026-11-01T01:00:00.000Z', 'done')`)
	for i := 1; i <= 3; i++ {
		exec(fmt.Sprintf(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'sweep', 1, 1, '-sn', '192.168.1.%d', 'ok')`, i))
	}
	exec(`DELETE FROM sa_probe WHERE id > 1`) // the prune of old rows
	if err := store.Migrate(ctx, db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-13T01:00:00.000Z', 'j', 'gentle_titles', 1, 1, '-sS', '192.168.1.9', 'ok')`)
	var id int
	if err := db.Reader().QueryRowContext(ctx, `SELECT max(id) FROM sa_probe`).Scan(&id); err != nil || id != 4 {
		t.Fatalf("the next probe id is %d (%v), want 4", id, err)
	}
	var shapes string
	_ = db.Reader().QueryRowContext(ctx, `SELECT group_concat(shape) FROM sa_probe`).Scan(&shapes)
	if !strings.Contains(shapes, "gentle_titles") {
		t.Fatalf("shapes = %q", shapes)
	}
}
