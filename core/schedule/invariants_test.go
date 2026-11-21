package schedule

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// A fresh box stores a first-run due time for an owner with FirstInWindow. `vedette selfcheck` runs with no owner registered, so the
// test forgets the owner's registration after the box started, and the self-check must still pass; a row that is wrong in a plausible
// way (an hour after its reference) is still found.
func TestAFreshBoxPassesTheSelfCheckWithNoOwnerRegistered(t *testing.T) {
	db := storetest.NewMigrated(t, "core", "../../modules/core/migrations/sqlite")
	now := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	svc, err := New(Config{DB: db, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO core_org (id, name, timezone, install_id) VALUES (1, 'Example', 'Asia/Ho_Chi_Minh', 'ins-test')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(Owner{Module: "scan", Key: "firstrun.check", Default: WeeklyAt("23:00", 7).InWindow(), DefaultOn: true, FirstInWindow: true,
		Start: func(context.Context, *sql.Tx, Fire) (string, error) { return "", nil }}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	firstInWindow.Delete("firstrun.check") // the self-check knows no owners
	if n, err := NextDueMismatches(t.Context(), db.Reader()); err != nil || n != 0 {
		t.Fatalf("a fresh box fails the self-check: %d %v", n, err)
	}
	wrong := store.FormatTS(now.Add(time.Hour))
	err = db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_schedule SET next_due_at = ? WHERE owner_key = 'firstrun.check'`, wrong)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := NextDueMismatches(t.Context(), db.Reader()); n != 1 {
		t.Fatalf("a row an hour past its reference passes: %d", n)
	}
}
