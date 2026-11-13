package feeds

import (
	"database/sql"
	"testing"
	"time"
)

// D-484 (W1-3): "I have this" alerts from the entry the person answered: the newest CISA entry of the product added on or
// before the answer. Later entries do not move it; an answer that declared no device gives no scope.
func TestHaveSince_IsTheAnsweredEntrysDate(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	write(t, db, func(tx *sql.Tx) error {
		for _, v := range []struct{ cve, added string }{{"CVE-2009-0556", "2022-03-03"}, {"CVE-2026-21509", "2026-11-01"}, {"CVE-2026-30000", "2026-11-10"}} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, description, required_action, links, date_added, due_date, ransomware, has_template, source_id, updated_at)
				VALUES (?, 'Microsoft', 'Office', 'microsoft|office', 'n', 'd', 'a', '[]', ?, NULL, 0, 0, 'cisa-kev', '2026-11-12T00:00:00.000Z')`, v.cve, v.added); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_weekly_answer (key, answer, user_id, answered_at, device_added) VALUES
			('microsoft|office', 'have', 'u-1', '2026-11-05T09:00:00.000Z', 1), ('cisco|broadworks', 'have', 'u-1', '2026-11-05T09:00:00.000Z', 0)`)
		return err
	})
	got, err := s.HaveSince(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC); len(got) != 1 || !got["microsoft|office"].Equal(want) {
		t.Fatalf("HaveSince = %v, want microsoft|office from %v only", got, want)
	}
}
