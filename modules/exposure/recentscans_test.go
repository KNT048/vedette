package exposure

import (
	"database/sql"
	"testing"
)

// kien G7a: Settings › Scanning › History lists the stored scans of public targets, newest first, with their counts.
func TestRecentScans_NewestFirstWithTargetAndCounts(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	exec := func(q string) {
		t.Helper()
		if err := e.db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO exp_target (id, kind, value, token, created_at) VALUES ('xt-1', 'ip', '203.0.113.10', '', '2026-11-01T00:00:00.000Z')`)
	exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts) VALUES ('a', 'xt-1', '2026-11-15', '2026-11-15T06:00:00.000Z', '[]', '[]', '[]', '[]', '{"ports":3,"admin_panels":1}')`)
	exec(`INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts) VALUES ('b', 'xt-1', '2026-11-16', '2026-11-16T06:00:00.000Z', '[]', '[]', '[]', '[]', '{"ports":2}')`)
	got, err := e.svc.RecentScans(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ScannedAt != "2026-11-16T06:00:00.000Z" || got[0].Target != "203.0.113.10" || got[0].Counts.Ports != 2 || got[1].Counts.AdminPanels != 1 {
		t.Fatalf("recent scans: %+v", got)
	}
}
