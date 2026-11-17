package inventory

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// D-630, review r2 N2 of #945: of two rows of one machine, an automatic join keeps an approved row a person watches over an ignored
// one, even an older or approved ignored one (a duplicate a person ignored by mistake), so a join never hides a watched server's
// findings. An ignored row next to a row nobody approved still follows the usual order (the re-sighted staff phone stays ignored).
func TestKeptOrderKeepsAWatchedApprovedRowOverAnIgnoredOne(t *testing.T) {
	t.Parallel()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
	ctx := t.Context()
	old, newer := "2026-11-01T10:00:00.000Z", "2026-11-09T10:00:00.000Z"
	err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range []struct {
			id, first string
			approved  bool
			ignored   *string
		}{
			{"a-ignored-dup", old, true, &old}, // older, approved, ignored
			{"a-server", newer, true, nil},     // approved, watched
			{"a-phone", old, false, &old},      // older, ignored, not approved
			{"a-new-phone", newer, false, nil}, // a new sighting nobody approved
			{"a-declared", old, true, &old},    // added by hand, then ignored (origin set below)
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, first_seen, last_seen, ignored_at) VALUES (?, 'unknown', 'discovered', ?, ?, ?, ?)`,
				r.id, r.approved, r.first, r.first, r.ignored); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET origin = 'manual' WHERE id = 'a-declared'`); err != nil {
			return err
		}
		for _, c := range []struct{ x, y, into string }{
			{"a-server", "a-declared", "a-declared"}, // review r1 L1 of #948: a declared row keeps its origin and address; joinAs watches it again
			{"a-ignored-dup", "a-server", "a-server"},
			{"a-server", "a-ignored-dup", "a-server"},
			{"a-phone", "a-new-phone", "a-phone"}, // the usual order: the older row
		} {
			_, into, err := keptOrder(ctx, tx, c.x, c.y)
			if err != nil {
				return err
			}
			if into != c.into {
				t.Errorf("keptOrder(%s, %s) keeps %s, want %s", c.x, c.y, into, c.into)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
