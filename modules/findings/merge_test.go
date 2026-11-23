package findings

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
)

// deleteDevice runs findings' part of an inventory delete in a write of its own, as the inventory does in its write.
func (e *env) deleteDevice(t testing.TB, id string) {
	t.Helper()
	d := lifecycle.Delete{Device: id}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return e.svc.DeviceDeleted(t.Context(), tx, d) }); err != nil {
		t.Fatal(err)
	}
	e.svc.DeleteCommitted(t.Context(), d)
}

// mergeDevices runs findings' part of an inventory merge in a write of its own, as the inventory does in its write.
func (e *env) mergeDevices(t testing.TB, m lifecycle.Merge) {
	t.Helper()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return e.svc.DeviceMerged(t.Context(), tx, m) }); err != nil {
		t.Fatal(err)
	}
	e.svc.MergeCommitted(t.Context(), m)
}

// A device the inventory merged into another hands its findings over with their status and history; for a
// CVE both hold, the finding a person decided stays and the other's history joins it. Matching the kept device afterwards creates and
// announces nothing.
func TestContract_DeviceMergedMovesTheFindings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fp := e.seed() // a-1: the LLDP row
	if _, err := e.svc.SetStatus(t.Context(), fp, ActionFalsePositive, "lab switch, the EX flaw needs J-Web which is off", "anna"); err != nil {
		t.Fatal(err)
	}
	kept := Asset{ID: "a-2", Name: "sw .47", Software: nas("6.1.1").Software} // the IP row holds the same CVE, untouched
	if _, err := e.svc.UpsertFromMatch(t.Context(), kept, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	history := e.count(`SELECT count(*) FROM fnd_finding_event`) // both copies' rows: none is lost
	e.pub.take()
	e.mergeDevices(t, lifecycle.Merge{From: "a-1", Into: "a-2"})
	r, err := e.svc.Get(t.Context(), fp)
	if err != nil || r.AssetID != "a-2" || r.Status != StatusFalsePositive || len(r.History) != history {
		t.Fatalf("moved finding %+v (%v), want a-2, false positive, %d history rows", r, err, history)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 1 {
		t.Fatalf("%d findings, want the person's one", n)
	}
	if _, err := e.svc.UpsertFromMatch(t.Context(), kept, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	for _, ev := range e.pub.take() {
		if ev.Name == EventCreated {
			t.Errorf("a finding was created again: %+v", ev)
		}
	}
	if r, _ := e.svc.Get(t.Context(), fp); r.Status != StatusFalsePositive {
		t.Errorf("status after the match: %s", r.Status)
	}
}

// Review L3/L4 (round 2) of #722: for a CVE both devices hold, decided (a person's history or an applied mitigation item) beats
// confirmed beats suspected, and a tie keeps the kept device's finding; the other copy is folded into it: every history row moves,
// the seen times widen, the modules keyed by finding id are told (FindingFolded). One audit row names both devices, the moved count
// and every CVE both held a decided finding for.
func TestContract_DeviceMergedKeepsTheBetterFinding(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		from, into func(e *env, id string) // what happens to each device's finding before the merge
		applied    bool                    // the from finding has an applied mitigation item
		fromWins   bool
		lost       bool
	}{
		"confirmed beats suspected": {from: confirm, fromWins: true},
		"suspected loses":           {into: confirm},
		"an applied item decides":   {into: confirm, applied: true, fromWins: true},
		"a person's reopen decides": {from: personReopens, into: confirm, fromWins: true},
		"two decided: into stays":   {from: falsePositive, into: falsePositive, lost: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			fromID := e.seed()
			res, err := e.svc.UpsertFromMatch(t.Context(), Asset{ID: "a-2", Name: "sw .47", Software: nas("6.1.1").Software}, e.feeds.vulns)
			if err != nil || len(res.Created) != 1 {
				t.Fatalf("into: %+v %v", res, err)
			}
			intoID := res.Created[0]
			if c.from != nil {
				c.from(e, fromID)
			}
			if c.into != nil {
				c.into(e, intoID)
			}
			e.svc.cfg.Applied = func(context.Context, *sql.Tx, []string) (map[string]bool, error) {
				return map[string]bool{fromID: c.applied}, nil
			}
			var folds []lifecycle.FindingFold
			e.svc.cfg.Lifecycle = &lifecycle.Hooks{}
			e.svc.cfg.Lifecycle.Register(lifecycle.Participant{Name: "keyed by finding", FindingFolded: func(_ context.Context, _ *sql.Tx, f lifecycle.FindingFold) error {
				folds = append(folds, f)
				return nil
			}})
			history := e.count(`SELECT count(*) FROM fnd_finding_event`)
			e.mergeDevices(t, lifecycle.Merge{From: "a-1", Into: "a-2"})
			want, gone := intoID, fromID
			if c.fromWins {
				want, gone = fromID, intoID
			}
			if r, err := e.svc.Get(t.Context(), want); err != nil || r.AssetID != "a-2" {
				t.Errorf("the winner %s: %+v %v", want, r, err)
			}
			if _, err := e.svc.Get(t.Context(), gone); err == nil {
				t.Errorf("the loser %s is still there", gone)
			}
			if len(folds) != 1 || folds[0] != (lifecycle.FindingFold{From: gone, Into: want}) {
				t.Errorf("folds told %+v, want %s into %s", folds, gone, want)
			}
			if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = '` + want + `'`); n != history {
				t.Errorf("%d history rows on the kept finding, want every row of both copies (%d)", n, history)
			}
			if c.lost { // both decided: the person's note on the copy that went is on the kept one
				if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE finding_id = '` + want + `' AND actor = 'anna'`); n != 2 {
					t.Errorf("%d of the person's history rows on the kept finding, want both copies' 2", n)
				}
			}
			var detail string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'findings.merged_with_asset' AND target = 'a-2'`).Scan(&detail); err != nil {
				t.Fatalf("no audit row: %v", err)
			}
			if !strings.Contains(detail, "from a-1") || strings.Contains(detail, "decided on both") != c.lost || (c.lost && !strings.Contains(detail, want)) {
				t.Errorf("audit detail %q", detail)
			}
		})
	}
}

func confirm(e *env, id string) {
	e.t.Helper()
	r, err := e.svc.Get(e.t.Context(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.ConfirmFromScan(e.t.Context(), r.AssetID, r.CVE, scanEv("t1")); err != nil {
		e.t.Fatal(err)
	}
}

func falsePositive(e *env, id string) {
	e.t.Helper()
	if _, err := e.svc.SetStatus(e.t.Context(), id, ActionFalsePositive, "not exposed on this device", "anna"); err != nil {
		e.t.Fatal(err)
	}
}

func personReopens(e *env, id string) {
	e.t.Helper()
	falsePositive(e, id)
	if _, err := e.svc.SetStatus(e.t.Context(), id, ActionReopen, "checked again, it is exposed", "anna"); err != nil {
		e.t.Fatal(err)
	}
}
