package findings

import (
	"database/sql"
	"strings"
	"testing"
)

// A software line inventory gives to another device with its id (a split gives a merged device its software back whole) takes its
// finding with it: the same finding, with the person's decision, note and history, on the device that has the line now, whichever of
// the two devices is matched first; no finding is created or closed for the move, and a question on the line keeps its answer. When
// the device already holds a finding of that (CVE, line), the two fold and the person's decision stays.
func TestContract_FindingsFollowTheirLineToAnotherDevice(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		order []string
		held  bool // a-2 already holds a finding of the CVE on the line
	}{
		"the device that lost the line is matched first": {order: []string{"a-1", "a-2"}},
		"the device that has the line now first":         {order: []string{"a-2", "a-1"}},
		"the device that has the line holds one":         {order: []string{"a-1", "a-2"}, held: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			id := e.seed() // a-1, line s-1
			const note = "the web interface is off"
			if _, err := e.svc.mark(t.Context(), id, "mitigated", note, "anna"); err != nil {
				t.Fatal(err)
			}
			err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
				_, err := tx.ExecContext(t.Context(), `INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at)
					VALUES ('q-1', 'a-1', 's-1', NULL, 'platform', '{}', 1, '2026-01-01T00:00:00.000Z', 'linux', 'anna', '2026-01-01T00:00:00.000Z')`)
				if err != nil || !c.held {
					return err
				}
				return writeTestFinding(t.Context(), tx, Finding{ID: "f-held", AssetID: "a-2", CVE: "CVE-2022-27593", SoftwareID: "s-1", FirstSeen: t0})
			})
			if err != nil {
				t.Fatal(err)
			}
			moved := nas("6.1.1")
			moved.ID, moved.Name = "a-2", "nas02"
			e.inv.mu.Lock()
			e.inv.match["a-1"] = Asset{ID: "a-1", Name: "nas01"} // the line is a-2's now, with its id
			e.inv.match["a-2"] = moved
			e.inv.mu.Unlock()
			e.pub.take()

			if _, err := e.svc.OnMatchChanged(t.Context(), c.order[0]); err != nil {
				t.Fatal(err)
			}
			if c.order[0] == "a-1" { // a match of a-2 rewrites its questions (this one does not hold there)
				var qAsset, answer string
				if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT asset_id, ifnull(answer, '') FROM fnd_question WHERE id = 'q-1'`).Scan(&qAsset, &answer); err != nil ||
					qAsset != "a-2" || answer != "linux" {
					t.Errorf("the question on the line after the first match: %s answered %q (%v), want a-2 with its answer", qAsset, answer, err)
				}
			}
			if _, err := e.svc.OnMatchChanged(t.Context(), c.order[1]); err != nil {
				t.Fatal(err)
			}
			f, err := e.svc.Finding(t.Context(), id)
			if err != nil {
				t.Fatalf("the finding is gone: %v", err)
			}
			if f.AssetID != "a-2" || f.SoftwareID != "s-1" || f.State != StateHandled || f.Resolution != ResolutionMitigated || f.Note != note || f.ResolvedBy != "anna" {
				t.Errorf("the finding after the move: %s on %s, %s %s by %s, note %q", f.AssetID, f.SoftwareID, f.State, f.Resolution, f.ResolvedBy, f.Note)
			}
			if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 1 {
				t.Errorf("%d findings, want the one that moved", n)
			}
			if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = '` + id + `' AND actor = 'anna'`); n == 0 {
				t.Error("the person's decision left the finding's history")
			}
			for _, ev := range e.pub.take() {
				if ev.Name == EventCreated {
					t.Errorf("the move created a finding: %+v", ev)
				}
			}
			if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.moved_with_line' AND target = 'a-2' AND detail LIKE 'from a-1: 1 findings moved%'`); n != 1 {
				t.Errorf("%d audit rows of the move, want 1: %s", n, strings.Join(e.auditActions(), ", "))
			}
		})
	}
}
