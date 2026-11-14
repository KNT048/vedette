package findings

import (
	"context"
	"strings"
	"testing"
)

// D-515, review H2 of #722: a device the inventory merged into another hands its findings over with their status and history; for a
// CVE both hold, the finding a person decided stays. Matching the kept device afterwards creates and announces nothing.
func TestContract_D515_OnAssetMergedMovesTheFindings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fp := e.seed() // a-1: the LLDP row
	if _, err := e.svc.SetStatus(t.Context(), fp, ActionFalsePositive, "lab switch, the EX flaw needs J-Web which is off", "kien"); err != nil {
		t.Fatal(err)
	}
	kept := Asset{ID: "a-2", Name: "sw .47", Software: nas("6.1.1").Software} // the IP row holds the same CVE, untouched
	if _, err := e.svc.UpsertFromMatch(t.Context(), kept, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	history := e.count(`SELECT count(*) FROM fnd_finding_history WHERE finding_id = '` + fp + `'`)
	e.pub.take()
	if _, err := e.svc.OnAssetMerged(t.Context(), "a-1", "a-2"); err != nil {
		t.Fatal(err)
	}
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
// confirmed beats suspected, and a tie keeps the kept device's finding; one audit row names both devices, the moved count and a
// decided finding that lost to another decided one; the people's history rows of that lost finding move onto the kept one.
func TestContract_D515_OnAssetMergedKeepsTheBetterFinding(t *testing.T) {
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
			e.svc.cfg.Applied = func(context.Context, []string) (map[string]bool, error) {
				return map[string]bool{fromID: c.applied}, nil
			}
			if _, err := e.svc.OnAssetMerged(t.Context(), "a-1", "a-2"); err != nil {
				t.Fatal(err)
			}
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
			if c.lost { // both decided: the person's note on the copy that went is on the kept one
				if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE finding_id = '` + want + `' AND user = 'kien'`); n != 2 {
					t.Errorf("%d of the person's history rows on the kept finding, want both copies' 2", n)
				}
			}
			var detail string
			if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'findings.merged_with_asset' AND target = 'a-2'`).Scan(&detail); err != nil {
				t.Fatalf("no audit row: %v", err)
			}
			if !strings.Contains(detail, "from a-1") || strings.Contains(detail, "decided findings removed") != c.lost || (c.lost && !strings.Contains(detail, gone)) {
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
	if _, err := e.svc.SetStatus(e.t.Context(), id, ActionFalsePositive, "not exposed on this device", "kien"); err != nil {
		e.t.Fatal(err)
	}
}

func personReopens(e *env, id string) {
	e.t.Helper()
	falsePositive(e, id)
	if _, err := e.svc.SetStatus(e.t.Context(), id, ActionReopen, "checked again, it is exposed", "kien"); err != nil {
		e.t.Fatal(err)
	}
}
