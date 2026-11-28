package feeds

import (
	"database/sql"
	"maps"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// A record tagged unsupported when assigned carries the CVE Program's mark at the start of its description, in any case; a record that
// only mentions support in its words, or has an empty description, is not tagged.
func TestStore_UnsupportedWhenAssignedReadsTheRecordsMark(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{
		"CVE-2026-4001": "** UNSUPPORTED WHEN ASSIGNED ** A flaw in Quillfeather Mail 2.x.",
		"CVE-2026-4002": "** Unsupported When Assigned ** A flaw in Quillfeather Mail 3.x.",
		"CVE-2026-4003": "A flaw in Quillfeather Mail; this release is no longer supported.",
		"CVE-2026-4004": "",
	}
	write(t, db, func(tx *sql.Tx) error {
		for cve, desc := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, description, updated_at) VALUES (?, ?, '2026-11-27T00:00:00.000Z')`, cve, desc); err != nil {
				return err
			}
		}
		return nil
	})
	got, err := NewStore(db).UnsupportedWhenAssigned(ctx, append(slices.Sorted(maps.Keys(rows)), "CVE-2026-4999"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-2026-4001", "CVE-2026-4002"}; !slices.Equal(slices.Sorted(maps.Keys(got)), want) {
		t.Errorf("tagged %v, want %v", slices.Sorted(maps.Keys(got)), want)
	}
}
