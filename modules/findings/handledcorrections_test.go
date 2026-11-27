package findings

import (
	"database/sql"
	"testing"
	"time"
)

// Handled leaves out the findings Vedette closed because it corrected its own match (via data_corrected, by Vedette): never a flaw
// someone handled, and hundreds at once when a kernel's package lines fold into one. It counts them under the same filters, and
// lists them when asked; a person's own decision is always listed.
func TestHandled_LeavesOutVedettesMatchCorrections(t *testing.T) {
	t.Parallel()
	e := blockTargetWorld(t)
	ctx := t.Context()
	fs, err := e.svc.Findings(ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) < 4 {
		t.Fatalf("want at least 4 findings on web-01, got %d", len(fs))
	}
	if _, _, err := e.svc.HandleConfirmed(ctx, []string{fs[0].ID}, ResolutionPatched, "updated by hand", time.Time{}, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	at := e.clock.UTC().Format("2006-01-02T15:04:05.000Z")
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		for _, f := range fs[1:4] {
			if _, err := tx.ExecContext(ctx, `UPDATE fnd_finding SET state = 'handled', resolution = 'not_relevant', via = ?, resolved_by = ?, resolved_at = ? WHERE id = ?`,
				string(ViaDataCorrected), SystemUser, at, f.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	def, err := e.svc.Handled(ctx, HandledFilter{}, Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if def.Total != 1 || len(def.Items) != 1 || def.Items[0].ID != fs[0].ID || def.Corrections != 3 {
		t.Errorf("default: total %d, %d rows, corrections %d; want the person's one row and 3 corrections counted", def.Total, len(def.Items), def.Corrections)
	}
	all, err := e.svc.Handled(ctx, HandledFilter{Corrections: true}, Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 4 || len(all.Items) != 4 || all.Corrections != 3 {
		t.Errorf("with corrections: total %d, %d rows, corrections %d; want 4, 4, 3", all.Total, len(all.Items), all.Corrections)
	}
	none, err := e.svc.Handled(ctx, HandledFilter{Resolutions: []Resolution{ResolutionPatched}}, Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if none.Total != 1 || none.Corrections != 0 {
		t.Errorf("patched only: total %d, corrections %d; want 1 and 0 (the count follows the filters)", none.Total, none.Corrections)
	}
}
