package findings

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
)

// splitEnv is a finding a person handled on line s-1 of a-1, with an answered question on that line, and the device split off (a-2)
// with its line s-9 in the database, as inventory's split leaves them before it calls the lifecycle. It returns the finding's id and
// the FindingMoved calls the modules that keep a device id next to a finding id are given.
func splitEnv(t *testing.T) (*env, string, *[]lifecycle.FindingMove) {
	t.Helper()
	e := newEnv(t)
	id := e.seed() // a-1, line s-1
	if _, err := e.svc.mark(t.Context(), id, "mitigated", "the web interface is off", "anna"); err != nil {
		t.Fatal(err)
	}
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO inv_asset (id, origin, first_seen, last_seen) VALUES ('a-2', 'discovered', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
			`INSERT INTO inv_software (id, asset_id, product_key, line, display, vendor, product, source, confidence, seen_at, first_seen, last_seen)
				VALUES ('s-9', 'a-2', 'test|s-9', '', 'Photo Station', 'qnap', 'photo station', 'nmap', 1, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
			`INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at)
				VALUES ('q-1', 'a-1', 's-1', NULL, 'platform', '{}', 1, '2026-01-01T00:00:00.000Z', 'linux', 'anna', '2026-01-01T00:00:00.000Z')`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	moves := &[]lifecycle.FindingMove{}
	e.svc.cfg.Lifecycle = &lifecycle.Hooks{}
	e.svc.cfg.Lifecycle.Register(lifecycle.Participant{Name: "keyed by finding and device", FindingMoved: func(_ context.Context, _ *sql.Tx, m lifecycle.FindingMove) error {
		*moves = append(*moves, m)
		return nil
	}})
	return e, id, moves
}

func (e *env) split(sp lifecycle.Split) {
	e.t.Helper()
	if err := e.db.Write(e.t.Context(), func(tx *sql.Tx) error { return e.svc.DeviceSplit(e.t.Context(), tx, sp) }); err != nil {
		e.t.Fatal(err)
	}
}

// A split that gives a line's readings back to the device split off as a line of a new id, leaving the kept device without the
// software, moves the finding inside the split's write: the same finding, with the person's decision, note and history, on the new
// device's new line, and the question on the line with its answer. The modules that keep a device id next to a finding id are told,
// one audit row names the move, and no row names a line of another device once the write commits.
func TestContract_ASplitMovesTheFindingToTheLinesNewID(t *testing.T) {
	t.Parallel()
	e, id, moves := splitEnv(t)
	e.split(lifecycle.Split{From: "a-1", Into: "a-2", Actor: "anna", IntoName: "camera-02", IntoIP: "192.0.2.42", Software: map[string]lifecycle.SplitLine{"s-1": {Into: "s-9", Gone: true}}})

	f, err := e.svc.Finding(t.Context(), id)
	if err != nil {
		t.Fatalf("the finding is gone: %v", err)
	}
	if f.AssetID != "a-2" || f.SoftwareID != "s-9" || f.State != StateHandled || f.Resolution != ResolutionMitigated || f.Note != "the web interface is off" || f.ResolvedBy != "anna" {
		t.Errorf("the finding after the split: %s on %s, %s %s by %s, note %q", f.AssetID, f.SoftwareID, f.State, f.Resolution, f.ResolvedBy, f.Note)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = '` + id + `' AND actor = 'anna'`); n == 0 {
		t.Error("the person's decision left the finding's history")
	}
	var qAsset, qLine, answer string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT asset_id, software_id, ifnull(answer, '') FROM fnd_question WHERE id = 'q-1'`).Scan(&qAsset, &qLine, &answer); err != nil ||
		qAsset != "a-2" || qLine != "s-9" || answer != "linux" {
		t.Errorf("the question after the split: %s/%s answered %q (%v), want a-2/s-9 with its answer", qAsset, qLine, answer, err)
	}
	// the participants get the new device's name and address from the split: they cannot read the device inside its write
	if want := []lifecycle.FindingMove{{Finding: id, From: "a-1", Into: "a-2", IntoName: "camera-02", IntoIP: "192.0.2.42"}}; !slices.Equal(*moves, want) {
		t.Errorf("lifecycle FindingMoved calls %+v, want %+v", *moves, want)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.moved_with_line' AND target = 'a-2' AND detail LIKE 'from a-1: 1 findings moved with their software line after the device was split%'`); n != 1 {
		t.Errorf("%d audit rows of the move, want 1", n)
	}
	if n := e.count(`SELECT (SELECT count(*) FROM fnd_finding f JOIN inv_software s ON s.id = f.software_id WHERE s.asset_id <> f.asset_id)
		+ (SELECT count(*) FROM fnd_question q JOIN inv_software s ON s.id = q.software_id WHERE s.asset_id <> q.asset_id)`); n != 0 {
		t.Errorf("%d rows name a software line of another device right after the split", n)
	}
}

// A line the kept device still has (another source still reads the software there) keeps its finding: the kept device still runs the
// software, and the device split off gets its own at its match after the commit.
func TestContract_ASplitLeavesTheFindingOfALineTheKeptDeviceStillHas(t *testing.T) {
	t.Parallel()
	e, id, moves := splitEnv(t)
	e.split(lifecycle.Split{From: "a-1", Into: "a-2", Actor: "anna", Software: map[string]lifecycle.SplitLine{"s-1": {Into: "s-9"}}})
	f, err := e.svc.Finding(t.Context(), id)
	if err != nil || f.AssetID != "a-1" || f.SoftwareID != "s-1" {
		t.Errorf("the finding of a line the kept device still has: %+v %v", f, err)
	}
	if len(*moves) != 0 || e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.moved_with_line'`) != 0 {
		t.Errorf("a finding that stayed was announced as moved: %+v", *moves)
	}
}

// When the device split off already holds a finding of the CVE on the line the readings went to, the two fold into one: the one a
// person decided stays, with the history of both.
func TestContract_ASplitFoldsTheMovedFindingIntoOneOnTheNewLine(t *testing.T) {
	t.Parallel()
	e, id, _ := splitEnv(t)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		return writeTestFinding(t.Context(), tx, Finding{ID: "f-held", AssetID: "a-2", CVE: "CVE-2022-27593", SoftwareID: "s-9", FirstSeen: t0})
	}); err != nil {
		t.Fatal(err)
	}
	e.split(lifecycle.Split{From: "a-1", Into: "a-2", Software: map[string]lifecycle.SplitLine{"s-1": {Into: "s-9", Gone: true}}})
	if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 1 {
		t.Fatalf("%d findings, want one", n)
	}
	f, err := e.svc.Finding(t.Context(), id)
	if err != nil || f.AssetID != "a-2" || f.SoftwareID != "s-9" || f.State != StateHandled {
		t.Errorf("the decided finding after the fold: %+v %v", f, err)
	}
}
