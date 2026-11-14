package scan_test

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/scan"
)

// kf-scan item 5 (migration 0007): the rebuild of scan_probe for not_run and refused keeps every row and its rowid (the page and
// the CSV order by it), and the table takes the two new results and still refuses any other.
func TestMigration0007KeepsTheProbeLog(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(scan.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p >= "0007" {
			return err
		}
		b, err := fs.ReadFile(scan.Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "scan", before); err != nil {
		t.Fatal(err)
	}
	exec := func(q string) error {
		return db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err })
	}
	const ins = `INSERT INTO scan_probe (id, ts, ip, label, template, request, result) VALUES `
	for _, q := range []string{
		ins + `('b', '2026-11-01T01:00:00.000Z', '192.168.1.2', 'x', 't', 'GET /', 'matched')`,
		ins + `('a', '2026-11-01T01:00:00.000Z', '192.168.1.3', 'x', 't', 'GET /', NULL)`,
	} {
		if err := exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if exec(ins+`('c', '2026-11-01T01:00:00.000Z', '192.168.1.4', 'x', 't', 'GET /', 'not_run')`) == nil {
		t.Fatal("not_run before 0007")
	}
	if err := store.Migrate(ctx, db, "scan", scan.Migrations); err != nil {
		t.Fatal(err)
	}
	var order string
	if err := db.Reader().QueryRowContext(ctx, `SELECT group_concat(id || ':' || coalesce(result, '-'), ',') FROM (SELECT id, result FROM scan_probe ORDER BY rowid)`).Scan(&order); err != nil || order != "b:matched,a:-" {
		t.Fatalf("rows after 0007: %q %v", order, err)
	}
	for id, r := range map[string]string{"c": "not_run", "d": "refused"} {
		if err := exec(ins + `('` + id + `', '2026-11-02T01:00:00.000Z', '192.168.1.4', 'x', 't', 'GET /', '` + r + `')`); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
	if exec(ins+`('e', '2026-11-02T01:00:00.000Z', '192.168.1.4', 'x', 't', 'GET /', 'maybe')`) == nil {
		t.Fatal("an unknown result was stored")
	}
}
