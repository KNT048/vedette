package findings

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/lifecycle"
)

// pruneLines deletes software lines for good as the inventory's retention does: the participant first, then the lines, in one write.
func (e *env) pruneLines(t *testing.T, ids ...string) {
	t.Helper()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		if err := e.svc.LinesDeleted(t.Context(), tx, lifecycle.LinesDelete{Lines: ids}); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM inv_software WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Software lines that go for good leave their findings on no line. Two findings that would meet there are folded first, the one a
// person decided staying with the other's events: two removed lines of one CVE (Java 8 and Java 21 both uninstalled), or a removed line
// beside a finding on no line (a safe check's hit).
func TestLinesDeleted_FoldsWhatWouldCollide(t *testing.T) {
	t.Parallel()
	for name, seed := range map[string][]Finding{
		"two lines of one CVE": {
			{ID: "f-8", AssetID: "a-1", CVE: "CVE-2026-1001", SoftwareID: "s-8", FirstSeen: t0},
			{ID: "f-21", AssetID: "a-1", CVE: "CVE-2026-1001", SoftwareID: "s-21", FirstSeen: t0},
		},
		"a line beside no line": {
			{ID: "f-8", AssetID: "a-1", CVE: "CVE-2026-1001", SoftwareID: "s-8", FirstSeen: t0},
			{ID: "f-21", AssetID: "a-1", CVE: "CVE-2026-1001", FirstSeen: t0, Basis: DetectScan, Verified: VerifiedScan},
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			other := Finding{ID: "f-other", AssetID: "a-1", CVE: "CVE-2026-1002", SoftwareID: "s-8", FirstSeen: t0}
			if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
				for _, f := range append(seed, other) {
					if err := writeTestFinding(t.Context(), tx, f); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := e.svc.Handle(t.Context(), []string{"f-8"}, ResolutionFalsePositive, "lab copy", time.Time{}, "anna@example.com"); err != nil {
				t.Fatal(err)
			}
			e.pruneLines(t, "s-8", "s-21")
			fs, err := e.svc.Findings(t.Context(), "a-1")
			if err != nil || len(fs) != 2 {
				t.Fatalf("%+v %v", fs, err)
			}
			for _, f := range fs {
				if f.SoftwareID != "" {
					t.Errorf("%s still names a line: %q", f.ID, f.SoftwareID)
				}
			}
			kept, err := e.svc.Finding(t.Context(), "f-8")
			if err != nil || kept.Resolution != ResolutionFalsePositive {
				t.Fatalf("the person's decision: %+v %v", kept, err)
			}
			if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = 'f-8' AND actor = 'anna@example.com'`); n != 1 {
				t.Fatalf("%d of the person's events kept", n)
			}
		})
	}
}

// A person's decision on software that went never covers a live flaw: a removed line's finding marked false positive, beside a finding
// on no line a safe check confirms now, folds into the confirmed one, which stays open with the decision as history.
func TestLinesDeleted_ALiveFindingStays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, f := range []Finding{
			{ID: "f-n", AssetID: "a-1", CVE: "CVE-2026-1001", FirstSeen: t0, Basis: DetectScan, Verified: VerifiedScan},
			{ID: "f-8", AssetID: "a-1", CVE: "CVE-2026-1001", SoftwareID: "s-8", FirstSeen: t0},
		} {
			if err := writeTestFinding(t.Context(), tx, f); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Handle(t.Context(), []string{"f-8"}, ResolutionFalsePositive, "old install", time.Time{}, "anna@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { // the line went: not detected any more
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET detected = 0 WHERE id = 'f-8'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.pruneLines(t, "s-8")
	f := e.only(t)
	if f.ID != "f-n" || f.State != StateOpen || f.Verified != VerifiedScan {
		t.Fatalf("the live finding: %+v", f)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = 'f-n' AND actor = 'anna@example.com'`); n != 1 {
		t.Fatalf("the person's decision as history: %d events", n)
	}
}
