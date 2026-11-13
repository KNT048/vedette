package audit_test

import (
	"database/sql"
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
	appendAll(t, db, l, e, e)

	steps := []struct {
		name          string
		days          int
		max           int64
		advance       int
		removed, left int64
	}{
		{"by age: the three old lines go", 365, 1000, 0, 3, 3}, // 2 new + the pruned line
		{"by count: only the newest 2 stay", 365, 2, 0, 1, 3},  // 2 kept + the new pruned line
		{"everything is old: the newest line stays", 365, 1000, 2000, 2, 2},
	}
	for _, s := range steps {
		now = now.AddDate(0, 0, s.advance)
		n, err := l.PruneWith(ctx, db, s.days, s.max)
		if err != nil || n != s.removed || count(t, db) != s.left {
			t.Fatalf("%s: removed %d (want %d), %v, %d lines left (want %d)", s.name, n, s.removed, err, count(t, db), s.left)
		}
		res, err := audit.Verify(ctx, db.Reader())
		if err != nil || !res.OK || int64(res.Count) != s.left {
			t.Fatalf("%s: chain after the prune: %+v, %v", s.name, res, err)
		}
		var action, user, detail string
		if err := db.Reader().QueryRowContext(ctx, `SELECT action, user, detail FROM core_audit ORDER BY seq DESC LIMIT 1`).Scan(&action, &user, &detail); err != nil {
			t.Fatal(err)
		}
		if action != "audit.pruned" || user != "system" || !strings.HasPrefix(detail, strconv.FormatInt(s.removed, 10)+" lines:") {
			t.Fatalf("%s: last line %s by %s: %q", s.name, action, user, detail)
		}
	}
	// Outside the prune the log is still append-only: the anchor names a line that is gone, so no line can be deleted.
	err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM core_audit WHERE seq = (SELECT MIN(seq) FROM core_audit)`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("a delete outside the prune: %v", err)
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
