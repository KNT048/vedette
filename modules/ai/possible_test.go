package ai_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
)

// One proposal call for a possible CVE runs as the explain-finding job: one activity row, the verdicts as the AI gave them, and the
// request carries only what findings sent (the CVE, the product, the version, the public text).
func TestProposePossible_OneCallOneActivityRow(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"items":[{"index":0,"verdict":"affected","reason":"15.1 is before 15.1R7-S13.","quote":"15.1 versions before 15.1R7-S13 are affected","source":1}]}`)
	ans, err := a.svc.ProposePossible(a.ctx(), "it@acme.example", ai.PossibleRequest{CVE: "CVE-2099-72001", Description: "A flaw in Junos OS.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "juniper", Product: "Junos OS", Version: "15.1R7.9", Line: "15.1"}},
		Pages: []ai.RefPage{{URL: "https://supportportal.example/JSA1", Status: "ok", Text: "Junos OS: 15.1 versions before 15.1R7-S13 are affected."}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Verdicts) != 1 || ans.Verdicts[0].Verdict != "affected" || ans.Model == "" || ans.ActivityID == "" {
		t.Fatalf("answer %+v", ans)
	}
	rows := a.activity()
	if len(rows) != 1 || rows[0].Job != "explain-finding" || !strings.Contains(rows[0].Summary, "CVE-2099-72001") {
		t.Fatalf("activity %+v", rows)
	}
	if got := a.fake.reqs[len(a.fake.reqs)-1]; !strings.Contains(got.System+got.Messages[0].Text, "15.1R7.9") {
		t.Errorf("the request does not carry the version")
	}
}
