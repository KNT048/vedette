package inventory_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// Migration 0006 adds the removals (inv_removed, inv_removed_id) to a box that already has devices: every device stays as it was, in
// the state the one rule gives it, no removal is made up for the devices people deleted before, and the first removal after the
// upgrade keeps its device out.
func TestMigrationRemovedKeepsTheStoredDevices(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateTo(ctx, db, "inventory", inventory.Migrations, 5); err != nil {
		t.Fatal(err)
	}
	const ts = "2026-11-27T09:00:00.000Z"
	rows := [][]any{
		{"a-added", "10.0.10.1", "3c:22:fb:00:00:01", 1, ts},   // added by a person
		{"a-review", "10.0.10.2", "3c:22:fb:00:00:02", 0, nil}, // found, burned-in card: To review
		{"a-phone", "10.0.10.3", "c2:31:86:3f:8c:03", 0, nil},  // found, private address, nothing to look at: Seen briefly
		{"a-routed", "10.20.0.4", nil, 0, nil},                 // found on a routed subnet: no MAC
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, ip, mac, kind, origin, approved, approved_at, fragile, first_seen, last_seen)
				VALUES (?, ?, ?, 'unknown', 'discovered', ?, ?, 0, ?, ?)`, append(r, ts, ts)...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	svc, err := inventory.New(inventory.Config{DB: db, Audit: audit.New(nil), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]inventory.DeviceState{"a-added": inventory.DeviceAdded, "a-review": inventory.DeviceReview, "a-phone": inventory.DeviceSeen, "a-routed": inventory.DeviceReview}
	for id, st := range want {
		d, err := svc.Device(ctx, id)
		if err != nil || d.State != st {
			t.Errorf("%s after the upgrade: state %q, %v; want %q", id, d.State, err, st)
		}
	}
	if l, err := svc.RemovedDevices(ctx); err != nil || len(l) != 0 {
		t.Fatalf("removals after the upgrade: %+v, %v; want none", l, err)
	}
	if err := svc.DeleteDevice(ctx, "it@acme.example", "a-routed", ""); err != nil {
		t.Fatal(err)
	}
	if l, err := svc.RemovedDevices(ctx); err != nil || len(l) != 1 || l[0].Name == "" || l[0].Identifiers != 1 {
		t.Fatalf("the first removal after the upgrade: %+v, %v", l, err)
	}
}
