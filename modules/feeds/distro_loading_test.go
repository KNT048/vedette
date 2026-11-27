package feeds

import (
	"database/sql"
	"maps"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// execSQL runs one statement in a write transaction.
func execSQL(t *testing.T, db *store.DB, q string) {
	t.Helper()
	write(t, db, func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err })
}

// The plan waits for a distribution only while a feed it reads has never completed a pull: a pull that completed is loaded even if it
// stored no row, a feed the plan does not read (ubuntu-vex) never holds the distribution back, and a feed that keeps failing without
// ever succeeding is given up, so the plan says "Check <distro>'s security updates" instead of leaving its devices unchecked.
func TestDistroPlanLoading(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	set := func(id, set string) {
		t.Helper()
		execSQL(t, e.db, `UPDATE feeds_source SET `+set+` WHERE id = '`+id+`'`)
	}
	loading := func() map[string]bool {
		t.Helper()
		l, err := e.svc.st.DistroPlanLoading(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	const ok = `last_success = '2026-11-05T11:00:00.000Z', status = 'ok', failures = 0`
	for _, id := range []string{alpineOSVFeedID, debianTrackerFeedID, ubuntuOSVFeedID, ubuntuVEXFeedID} {
		set(id, `enabled = 1`)
	}
	// never pulled: all three the plan reads are loading
	if got := loading(); !maps.Equal(got, map[string]bool{DistroAlpine: true, DistroDebian: true, DistroUbuntu: true}) {
		t.Fatalf("never pulled: %v", got)
	}
	// a pull that completed and stored zero rows: loaded, for good
	set(alpineOSVFeedID, ok)
	if rowsOf(t, e.db, "feeds_distro_fix") != 0 || loading()[DistroAlpine] {
		t.Fatalf("zero-row successful pull is still loading: %v", loading())
	}
	// ubuntu-osv loaded, ubuntu-vex failing and never succeeded: Ubuntu is not held back by a feed the plan does not read
	set(ubuntuOSVFeedID, ok)
	set(ubuntuVEXFeedID, `failures = 3, status = 'error'`)
	if loading()[DistroUbuntu] {
		t.Fatalf("ubuntu-vex holds Ubuntu back: %v", loading())
	}
	// debian-tracker failing and never succeeded: loading while the failures are few, given up after DistroGiveUpFailures
	set(debianTrackerFeedID, `failures = 2, status = 'error'`)
	if !loading()[DistroDebian] {
		t.Fatalf("a feed that failed twice is given up: %v", loading())
	}
	set(debianTrackerFeedID, `failures = 6, status = 'error'`)
	if loading()[DistroDebian] {
		t.Fatalf("a feed that failed %d times in a row is still waited for: %v", DistroGiveUpFailures, loading())
	}
	// a feed that is off is not loading
	set(debianTrackerFeedID, `failures = 0, status = 'never', enabled = 0`)
	if loading()[DistroDebian] {
		t.Fatalf("a feed that is off is loading: %v", loading())
	}
	// a feed that waits for the CISA list records nothing: it is loading only while that list can still come
	set(debianTrackerFeedID, `enabled = 1`)
	if !loading()[DistroDebian] {
		t.Fatalf("waiting for a CISA list still coming: %v", loading())
	}
	set(kevFeedID, `enabled = 0`)
	if loading()[DistroDebian] {
		t.Fatalf("the CISA list is off, the distribution waits for good: %v", loading())
	}
	set(kevFeedID, `enabled = 1, failures = 6, status = 'error'`)
	if loading()[DistroDebian] {
		t.Fatalf("the CISA list is blocked, the distribution waits for good: %v", loading())
	}
	// the platform question's reading follows the same rule
	if l, err := e.svc.st.DistroLoading(t.Context()); err != nil || l[DistroDebian] {
		t.Fatalf("platform loading with the CISA list blocked: %v %v", l, err)
	}
	set(kevFeedID, `failures = 0, status = 'never'`)
	if l, err := e.svc.st.DistroLoading(t.Context()); err != nil || !l[DistroDebian] {
		t.Fatalf("platform loading while the first pulls can come: %v %v", l, err)
	}
}

// A distribution's data decides its own packages while one of its feeds is on and loaded (a completed pull) or loading; a feed that is off,
// or given up after failing with no pull ever completed, leaves its packages to NVD's ranges. Alpine keeps the platform list's rule.
func TestDistroOn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	set := func(id, set string) {
		t.Helper()
		execSQL(t, e.db, `UPDATE feeds_source SET `+set+` WHERE id = '`+id+`'`)
	}
	on := func() map[string]bool {
		t.Helper()
		l, err := e.svc.st.DistroOn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	for _, id := range []string{alpineOSVFeedID, debianTrackerFeedID, ubuntuOSVFeedID, ubuntuVEXFeedID} {
		set(id, `enabled = 0`)
	}
	if got := on(); len(got) != 0 {
		t.Fatalf("every feed off: %v", got)
	}
	set(ubuntuVEXFeedID, `enabled = 1, last_success = '2026-11-05T11:00:00.000Z', status = 'ok', failures = 0`)
	set(alpineOSVFeedID, `enabled = 1, last_success = '2026-11-05T11:00:00.000Z', status = 'ok', failures = 0`)
	if got := on(); !maps.Equal(got, map[string]bool{DistroUbuntu: true}) {
		t.Fatalf("Ubuntu loaded, Alpine left to its own rule: %v", got)
	}
	set(debianTrackerFeedID, `enabled = 1, last_success = NULL, status = 'error', failures = 6`)
	if got := on(); got[DistroDebian] {
		t.Fatalf("a Debian feed given up is on: %v", got)
	}
}
