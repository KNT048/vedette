package findings

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/lifecycle"
)

// A merge that folds a software line of the merged device into the kept device's line moves the findings on it to the kept line;
// for a (CVE, line) both held, the finding a person decided stays and the other's events join it; other lines move as they are.
func TestDeviceMerged_FindingsFollowAFoldedLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	seed := []Finding{
		{ID: "f-from-fp", AssetID: "a-1", CVE: "CVE-2026-1001", SoftwareID: "s-gone", FirstSeen: t0},     // decided by a person below
		{ID: "f-into", AssetID: "a-2", CVE: "CVE-2026-1001", SoftwareID: "s-kept", FirstSeen: t0},        // the same CVE on the kept line
		{ID: "f-from-2", AssetID: "a-1", CVE: "CVE-2026-1002", SoftwareID: "s-gone", FirstSeen: t0},      // only from has it: follows the line
		{ID: "f-from-other", AssetID: "a-1", CVE: "CVE-2026-1003", SoftwareID: "s-other", FirstSeen: t0}, // a line not folded: moves as it is
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, f := range seed {
			if err := writeTestFinding(t.Context(), tx, f); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Handle(t.Context(), []string{"f-from-fp"}, ResolutionFalsePositive, "lab copy", time.Time{}, "anna@example.com"); err != nil {
		t.Fatal(err)
	}
	e.mergeDevices(t, lifecycle.Merge{From: "a-1", Into: "a-2", Software: map[string]string{"s-gone": "s-kept"}})
	fs, err := e.svc.Findings(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.ID] = f.AssetID + " " + f.CVE + " " + f.SoftwareID + " " + string(f.State) + " " + string(f.Resolution)
	}
	want := map[string]string{
		"f-from-fp":    "a-2 CVE-2026-1001 s-kept handled false_positive",
		"f-from-2":     "a-2 CVE-2026-1002 s-kept open ",
		"f-from-other": "a-2 CVE-2026-1003 s-other open ",
	}
	if len(got) != len(want) {
		t.Fatalf("findings %v", got)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %q, want %q", id, got[id], w)
		}
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = 'f-from-fp' AND actor = 'anna@example.com'`); n != 1 {
		t.Errorf("the person's handling: %d events", n)
	}
}

// Deleting a device removes its findings, their events and its questions, and nothing of another device.
func TestDeviceDeleted_RemovesFindingsEventsAndQuestions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, id := range []string{"a-1", "a-2"} {
		sw := Software{ID: "s-" + id, Display: "App", Vendor: "Acme", Product: "App", Version: "1.0", Source: "agent", SeenAt: t0}
		e.matchPass(t, Asset{ID: id, Software: []Software{sw}}, MatchResult{New: []Match{versionMatch(sw)},
			NeedVersion: []VersionNeeded{{SoftwareID: sw.ID, Software: "App", CVEs: []string{"CVE-2026-1002"}}}})
	}
	e.deleteDevice(t, "a-1")
	if e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-1'`)+e.count(`SELECT count(*) FROM fnd_question WHERE asset_id = 'a-1'`) != 0 ||
		e.count(`SELECT count(*) FROM fnd_finding_event e JOIN fnd_finding f ON f.id = e.finding_id WHERE f.asset_id = 'a-2'`) != 1 ||
		e.count(`SELECT count(*) FROM fnd_finding_event`) != 1 || e.count(`SELECT count(*) FROM fnd_question`) != 1 {
		t.Fatal("wrong rows removed")
	}
}

// After a merge, a finding on no line (the merged device's safe check hit) beside a finding on a line of the same CVE folds into one
// on that line; the confirmed one keeps its id.
func TestDeviceMerged_ANoLineFindingJoinsTheLineFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, f := range []Finding{
			{ID: "f-scan", AssetID: "a-1", CVE: "CVE-2026-1001", FirstSeen: t0, Basis: DetectScan, Verified: VerifiedScan},
			{ID: "f-line", AssetID: "a-2", CVE: "CVE-2026-1001", SoftwareID: "s-1", FirstSeen: t0},
		} {
			if err := writeTestFinding(t.Context(), tx, f); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.mergeDevices(t, lifecycle.Merge{From: "a-1", Into: "a-2"})
	fs, err := e.svc.Findings(t.Context(), "a-2")
	if err != nil || len(fs) != 1 || fs[0].ID != "f-scan" || fs[0].SoftwareID != "s-1" || fs[0].Verified != VerifiedScan {
		t.Fatalf("%+v %v", fs, err)
	}
}
