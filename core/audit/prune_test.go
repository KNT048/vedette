package audit_test

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// D-416, core INV-37: the audit log keeps 365 days, at most MaxRows lines; the oldest run goes, the newest line stays, the chain verifies
// after every prune, and each prune leaves one "audit.pruned" line.
func TestPruneByAgeAndByCountKeepsTheChain(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	ctx := t.Context()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := audit.New(func() time.Time { return now })

	if n, err := l.PruneWith(ctx, db, 365, 1000); err != nil || n != 0 || count(t, db) != 0 {
		t.Fatalf("empty log: removed %d, %v, %d lines", n, err, count(t, db))
	}
	e := audit.Entry{User: "admin@acme.example", Action: "module.enable", Target: "feeds"}
	appendAll(t, db, l, e, e, e) // 400 days old below
	now = now.AddDate(0, 0, 400)
	appendAll(t, db, l, e, e, e, e)

	steps := []struct {
		name          string
		max           int64
		removed, left int64
	}{
		{"by age: the three old lines go", 1000, 3, 5}, // 4 new + the pruned line
		{"by count: the log holds at most 2 lines", 2, 4, 2},
	}
	for _, s := range steps {
		n, err := l.PruneWith(ctx, db, 365, s.max)
		if err != nil || n != s.removed || count(t, db) != s.left {
			t.Fatalf("%s: removed %d (want %d), %v, %d lines left (want %d)", s.name, n, s.removed, err, count(t, db), s.left)
		}
		verifyOK(t, db, s.left)
		var action, user, detail string
		if err := db.Reader().QueryRowContext(ctx, `SELECT action, user, detail FROM core_audit ORDER BY seq DESC LIMIT 1`).Scan(&action, &user, &detail); err != nil {
			t.Fatal(err)
		}
		if action != "audit.pruned" || user != "system" || !strings.HasPrefix(detail, strconv.FormatInt(s.removed, 10)+" lines:") {
			t.Fatalf("%s: last line %s by %s: %q", s.name, action, user, detail)
		}
	}

	// A clock that jumps three years ahead would make every line "old": the prune removes nothing by age and says why.
	appendAll(t, db, l, e, e, e, e)
	now = now.AddDate(3, 0, 0)
	if n, err := l.PruneWith(ctx, db, 365, 1000); !errors.Is(err, audit.ErrClockSuspect) || n != 0 || count(t, db) != 6 {
		t.Fatalf("clock jump: removed %d, %v, %d lines", n, err, count(t, db))
	}
	verifyOK(t, db, 6)

	// Outside the prune the log is still append-only: the anchor names a line that is gone, so no line can be deleted.
	if err := deleteSeq(t, db, `(SELECT MIN(seq) FROM core_audit)`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("a delete outside the prune: %v", err)
	}
}

// The delete trigger of migration 0011 lets a line go only when it is at or before the line the anchor names, even while that line
// still exists: a prune that deleted before moving the anchor, or past it, is refused.
func TestDeleteTriggerStopsAtTheAnchor(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	ctx := t.Context()
	e := audit.Entry{User: "admin@acme.example", Action: "module.enable", Target: "feeds"}
	appendAll(t, db, audit.New(fixedClock()), e, e, e, e)
	if err := deleteSeq(t, db, "1"); err == nil {
		t.Fatal("no anchor: a delete went through")
	}
	err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO core_chain_anchor (chain, last_pruned_id, last_pruned_hash, pruned_at)
			SELECT 'core_audit', id, hash, '2026-11-13T00:00:00.000Z' FROM core_audit WHERE seq = 2`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := deleteSeq(t, db, "3"); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("a line past the anchor: %v", err)
	}
	for _, seq := range []string{"1", "2"} {
		if err := deleteSeq(t, db, seq); err != nil {
			t.Fatalf("line %s, at or before the anchor: %v", seq, err)
		}
	}
	if err := deleteSeq(t, db, "4"); err == nil {
		t.Fatal("the anchor's line is gone, yet a later line could be deleted")
	}
}

func deleteSeq(t *testing.T, db *store.DB, seq string) error {
	t.Helper()
	return db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM core_audit WHERE seq = `+seq) //nolint:gosec // test constants
		return err
	})
}

func verifyOK(t *testing.T, db *store.DB, want int64) {
	t.Helper()
	res, err := audit.Verify(t.Context(), db.Reader())
	if err != nil || !res.OK || int64(res.Count) != want {
		t.Fatalf("chain: %+v, %v (want %d lines)", res, err, want)
	}
}

func count(t *testing.T, db *store.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM core_audit`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
