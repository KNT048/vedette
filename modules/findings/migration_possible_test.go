package findings

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings/findingstest"
	"github.com/knt048/vedette/modules/inventory"
)

// Migration 3 on a database of the release before it, with realistic rows (answered and open questions, an older_line question of a
// whole line, a finding): every row is kept as it was, each question gets an empty check key, the new table starts empty, and the next
// match gives the checkable questions their key. The older code's reads name their columns, so they read the new database unchanged.
func TestMigration3_KeepsTheRowsOfTheReleaseBefore(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "inventory", FS: inventory.Migrations}} {
		if err := store.Migrate(ctx, db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MigrateTo(ctx, db, "findings", Migrations, 2); err != nil {
		t.Fatal(err)
	}
	findingstest.ParentRows(t, db)
	exec := func(q string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at) VALUES
		('q-1', 'a-1', 's-1', 'CVE-2026-1001', 'no_range_data', '{"software":"Junos OS","version":"15.1R7.9","listed":true}', 1, '2026-11-01T00:00:00.000Z', NULL, NULL, NULL),
		('q-2', 'a-1', 's-1', NULL, 'older_line', '{"cve_list":["CVE-2026-1002","CVE-2026-1003"],"line":"15.1"}', 2, '2026-11-01T00:00:00.000Z', 'not_affected', 'ana@example.com', '2026-11-02T00:00:00.000Z'),
		('q-3', 'a-1', 's-1', NULL, 'version_needed', '{"cve_list":["CVE-2026-1004"]}', 1, '2026-11-01T00:00:00.000Z', NULL, NULL, NULL)`)
	before := storetestChecksum(t, db)
	if err := store.Migrate(ctx, db, "findings", Migrations); err != nil {
		t.Fatal(err)
	}
	var n, empty int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*), sum(check_key = '') FROM fnd_question`).Scan(&n, &empty); err != nil {
		t.Fatal(err)
	}
	if n != 3 || empty != 3 {
		t.Errorf("%d questions, %d with an empty key; want 3 and 3", n, empty)
	}
	if after := storetestChecksum(t, db); after != before {
		t.Errorf("the rows changed: %s -> %s", before, after)
	}
	var checks int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM fnd_possible_check`).Scan(&checks); err != nil || checks != 0 {
		t.Errorf("fnd_possible_check: %d rows, %v", checks, err)
	}
}

// storetestChecksum is the questions as the release before reads them (its own columns).
func storetestChecksum(t *testing.T, db *store.DB) string {
	t.Helper()
	var s string
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT group_concat(id || '|' || ifnull(cve, '') || '|' || kind || '|' || ifnull(detail, '') || '|' ||
		ifnull(answer, ''), ';') FROM (SELECT * FROM fnd_question ORDER BY id)`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
