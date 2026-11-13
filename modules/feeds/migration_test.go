package feeds

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// Migration 0006 (D-485) on a box that ran 0001..0005: the CISA list still on the old 24-hour default moves to 1 hour, other
// schedules and custom feeds are kept, and the validators the GitHub mirror handed out move to the mirror's own columns.
func TestMigration0006KEVHourlyAndMirrorValidators(t *testing.T) {
	t.Parallel()
	before := fstest.MapFS{}
	entries, err := fs.ReadDir(Migrations, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() >= "0006" { // what a box had before this change
			continue
		}
		b, err := fs.ReadFile(Migrations, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = &fstest.MapFile{Data: b}
	}
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "feeds", FS: before})
	s := &Store{db: db}
	if err := s.SeedBuiltins(t.Context(), epoch0); err != nil {
		t.Fatal(err)
	}
	addCustom(t, db, "cf-v", "Partner advisories", KindVulnerabilities)
	execSQL(t, db, `UPDATE feeds_source SET interval_hours = 24 WHERE id IN ('cisa-kev', 'cf-v')`)
	execSQL(t, db, `UPDATE feeds_source SET answered_by = 'CISA GitHub mirror', etag = '"m1"', last_modified = 'Tue, 03 Nov 2026 10:00:00 GMT' WHERE id = 'cisa-kev'`)

	if err := store.Migrate(t.Context(), db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	kev, err := s.source(t.Context(), "cisa-kev")
	if err != nil {
		t.Fatal(err)
	}
	if kev.IntervalHours != 1 || kev.ETag != nil || kev.LastModified != nil || orEmpty(kev.MirrorETag) != `"m1"` || orEmpty(kev.MirrorLastModified) == "" {
		t.Errorf("cisa-kev after 0006: every %d h, etag %v, mirror etag %v", kev.IntervalHours, kev.ETag, kev.MirrorETag)
	}
	for id, want := range map[string]int{"cf-v": 24, "first-epss": 24, "ipsum": 6} {
		if r, err := s.source(t.Context(), id); err != nil || r.IntervalHours != want {
			t.Errorf("%s: every %d h, want %d (%v)", id, r.IntervalHours, want, err)
		}
	}
}

func execSQL(t *testing.T, db *store.DB, q string) {
	t.Helper()
	write(t, db, func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err })
}
