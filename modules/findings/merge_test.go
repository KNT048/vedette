package findings

import (
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
