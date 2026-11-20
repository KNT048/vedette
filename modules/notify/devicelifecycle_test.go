package notify_test

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
)

// deleteDevice runs notify's part of an inventory delete in a write of its own, as the inventory does in its write.
func (e *env) deleteDevice(id, actor string) {
	e.t.Helper()
	e.write(func(tx *sql.Tx) error {
		return e.svc.DeviceDeleted(e.ctx(), tx, lifecycle.Delete{Device: id, Actor: actor})
	})
}

// mergeDevices runs notify's part of an inventory merge in a write of its own, as the inventory does in its write; intoName is the
// name the inventory passes.
func (e *env) mergeDevices(from, into, intoName string) {
	e.t.Helper()
	e.write(func(tx *sql.Tx) error {
		return e.svc.DeviceMerged(e.ctx(), tx, lifecycle.Merge{From: from, Into: into, IntoName: intoName})
	})
}

// The notices sent for a finding a merge folded into another are listed on the finding that stays; one already listed keeps its row.
func TestFoldedFindingKeepsItsNotices(t *testing.T) {
	e := newEnv(t)
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice (id, created_at, product, cves) VALUES
			('nt-1', '2026-11-20T10:00:00.000Z', 'Linux', '[]'), ('nt-2', '2026-11-20T10:00:00.000Z', 'Linux', '[]');
			INSERT INTO notify_notice_finding (notice_id, finding_id) VALUES ('nt-1', 'f-gone'), ('nt-2', 'f-gone'), ('nt-2', 'f-kept')`)
		return err
	})
	e.write(func(tx *sql.Tx) error {
		return e.svc.FindingFolded(e.ctx(), tx, lifecycle.FindingFold{From: "f-gone", Into: "f-kept"})
	})
	if n := e.count(`SELECT COUNT(*) FROM notify_notice_finding WHERE finding_id = 'f-gone'`); n != 0 {
		t.Fatalf("%d notice rows still name the folded finding", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_notice_finding WHERE finding_id = 'f-kept'`); n != 2 {
		t.Fatalf("%d notices list the kept finding, want both", n)
	}
}
