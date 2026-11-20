package sensoractive_test

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// mergeDevices runs sensor-active's part of an inventory merge in a write of its own, as the inventory does in its write.
func mergeDevices(t testing.TB, db *store.DB, svc *sa.Service, m lifecycle.Merge) {
	t.Helper()
	if err := db.Write(t.Context(), func(tx *sql.Tx) error { return svc.DeviceMerged(t.Context(), tx, m) }); err != nil {
		t.Fatal(err)
	}
	svc.MergeCommitted(t.Context(), m)
}

// deleteDevice runs sensor-active's part of an inventory delete in a write of its own, as the inventory does in its write.
func deleteDevice(t testing.TB, db *store.DB, svc *sa.Service, id string) {
	t.Helper()
	d := lifecycle.Delete{Device: id}
	if err := db.Write(t.Context(), func(tx *sql.Tx) error { return svc.DeviceDeleted(t.Context(), tx, d) }); err != nil {
		t.Fatal(err)
	}
	svc.DeleteCommitted(t.Context(), d)
}

// When both merged devices have SNMP settings, the ones whose last read answered are kept, wherever they were, and the notice says
// which were kept and which removed; the removed ones' secrets go with them.
func TestMergeKeepsTheSNMPSettingsThatAnswer(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.set("a-sw", v2c("community-1"))
	w.set("a-printer", v2c("community-2"))
	if err := w.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sa_snmp_device SET last_status = 'ok', last_checked_at = '2026-01-01T00:00:00.000Z', last_answer_at = '2026-01-01T00:00:00.000Z' WHERE asset_id = 'a-sw'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	mergeDevices(t, w.db, w.svc, lifecycle.Merge{From: "a-sw", Into: "a-printer", FromName: "core switch", IntoName: "printer"})
	if _, plain := w.secretOf("a-printer", "secret_id"); plain != "community-1" {
		t.Fatalf("kept %q, want the settings that answered", plain)
	}
	if w.count(`SELECT count(*) FROM sa_snmp_device`) != 1 || w.count(`SELECT count(*) FROM core_secret`) != 1 {
		t.Fatalf("%d settings, %d secrets left, want 1 and 1", w.count(`SELECT count(*) FROM sa_snmp_device`), w.count(`SELECT count(*) FROM core_secret`))
	}
	if w.count(`SELECT count(*) FROM sa_snmp_notice WHERE text LIKE 'core switch was merged into printer%Kept: SNMP v2c%last read answered. Removed: SNMP v2c%never read.'`) != 1 {
		t.Fatal("no notice of the settings the merge removed")
	}
}
