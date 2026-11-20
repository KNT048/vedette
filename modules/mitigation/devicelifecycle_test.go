package mitigation

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
)

// A merge that folds one finding into another keeps its "Applied" marks and AI results on the finding that stays: an item marked on
// both keeps the earlier mark, of two results of one skill the newer stays.
func TestFoldedFindingKeepsItsAppliedMarksAndAIResults(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.install()
	gone := r.ids[qnapCVE]
	var kept string
	for _, id := range r.ids {
		if id != gone {
			kept = id
			break
		}
	}
	if kept == "" {
		t.Fatal("the rig has one finding only")
	}
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := r.db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO mit_applied (finding_id, item, ts, user) VALUES (?1, 'patch', '2026-01-01T00:00:00.000Z', 'anna'), (?1, 'workaround', '2026-01-03T00:00:00.000Z', 'anna'),
		(?2, 'patch', '2026-01-02T00:00:00.000Z', 'bo')`, gone, kept)
	exec(`INSERT INTO mit_ai_output (finding_id, skill, payload, model, created_at) VALUES (?1, 'explain', '{"v":"new"}', 'm', '2026-01-05T00:00:00.000Z'),
		(?2, 'explain', '{"v":"old"}', 'm', '2026-01-04T00:00:00.000Z')`, gone, kept)
	if err := r.db.Write(ctx, func(tx *sql.Tx) error {
		if err := FindingFolded(ctx, tx, lifecycle.FindingFold{From: gone, Into: kept}); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE id = ?`, gone)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT count(*) FROM mit_applied WHERE finding_id = '` + kept + `' AND ((item = 'patch' AND user = 'anna') OR (item = 'workaround'))`); n != 2 {
		t.Errorf("%d of the 2 applied marks kept as expected", n)
	}
	if n := r.count(`SELECT count(*) FROM mit_ai_output WHERE finding_id = '` + kept + `' AND payload = '{"v":"new"}'`); n != 1 {
		t.Error("the newer AI result did not stay")
	}
}
