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

// A proposal call is public text only: it never carries an administrator's memory or a passage of a knowledge document, whatever job
// settings it borrows (the privacy page promises no data of the network goes with it).
func TestProposePossible_NoMemoryNoDocuments(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.addMemory("Our core router CORE-RTR-01 runs Junos OS 21.4R3-S6 at 10.20.0.1")
	a.kbIndexProfile()
	a.kbAdd("routers.md", []byte("# Routers\n\nCORE-RTR-01 runs Junos OS 21.4 and is reachable on the management VLAN.\n"), "[]")
	a.fake.setAnswer(`{"items":[{"index":0,"verdict":"unsure","reason":"No range for 21.4.","quote":"","source":0}]}`)
	if _, err := a.svc.ProposePossible(a.ctx(), "it@acme.example", ai.PossibleRequest{CVE: "CVE-2099-72001", Description: "A flaw in Junos OS.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "juniper", Product: "Junos OS", Version: "21.4R3-S6", Line: "21.4"}},
		Pages: []ai.RefPage{{URL: "https://supportportal.example/JSA1", Status: "ok", Text: "Junos OS 21.4 is affected by this issue."}}}); err != nil {
		t.Fatal(err)
	}
	req := a.fake.reqs[len(a.fake.reqs)-1]
	all := req.System + req.Messages[0].Text
	for _, never := range []string{"CORE-RTR-01", "10.20.0.1", "management VLAN", "kind=memory", "kind=document"} {
		if strings.Contains(all, never) {
			t.Errorf("%q reached the provider of a possible-findings check", never)
		}
	}
}
