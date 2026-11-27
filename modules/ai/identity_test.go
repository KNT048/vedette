package ai_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
)

func identifyItems() []ai.IdentifyItem {
	return []ai.IdentifyItem{{Index: 1, Publisher: "Cisco Systems, Inc.", Name: "Cisco Packet Tracer 8.2.1 64Bit", Version: "8.2.1.118",
		Candidates: []ai.IdentifyCandidate{{ID: "c1", Title: "cisco packet tracer", Product: "cisco:packet_tracer", CVEs: 1}}}}
}

// One identification call runs as the explain-finding job with the product_identity schema: one activity row, the choices as the AI
// gave them (with whether the program is the product itself or a part of its family), the programs and candidates sent as fenced data,
// and no memory of the box. The automatic identification shares the daily number of automatic reads with the reading of advisories.
func TestIdentifyProducts_OneCallSharesTheDailyReads(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.addMemory("Our core router CORE-RTR-01 runs Junos OS 21.4R3-S6 at 10.20.0.1")
	a.fake.setAnswer(`{"items":[{"index":1,"choice":"c1","match":"exact","reason":"Same publisher and name."}]}`)
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":true,"daily_reads":2}`, 200, "")
	ans, err := a.svc.IdentifyProducts(a.ctx(), "system", identifyItems())
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Choices) != 1 || ans.Choices[0].Choice != "c1" || ans.Choices[0].Match != "exact" || ans.Model == "" || ans.ActivityID == "" {
		t.Fatalf("answer %+v", ans)
	}
	req := a.fake.reqs[len(a.fake.reqs)-1]
	all := req.System + req.Messages[0].Text
	if req.Schema == nil || req.Schema.Name != "product_identity" || !strings.Contains(all, "cisco:packet_tracer") || !strings.Contains(all, "8.2.1.118") {
		t.Errorf("request: schema %+v, want product_identity with the candidates and the version", req.Schema)
	}
	if strings.Contains(all, "CORE-RTR-01") {
		t.Error("an administrator's memory reached the provider of an identification")
	}
	if st := a.svc.AutoReadState(a.ctx()); st.Used != 1 || st.IdentifyUsed != 1 || st.Left != 1 || st.IdentifyLeft != 0 {
		t.Errorf("daily reads %+v: the identification counts as one automatic read, and may use half of them", st)
	}
	sent := len(a.fake.reqs)
	if _, err := a.svc.IdentifyProducts(a.ctx(), "system", identifyItems()); err == nil || !strings.Contains(err.Error(), "used up") {
		t.Errorf("an identification past its half of the daily number: %v, want budget_reached", err)
	}
	if len(a.fake.reqs) != sent {
		t.Error("a call past the identification's share was sent")
	}
	if rows := a.activity(); rows[0].Job != "explain-finding" || !strings.HasPrefix(rows[0].Summary, "Identify software: chose the product of 1 program") {
		t.Errorf("activity %+v", rows[0])
	}
}

// A call whose answer does not fit the schema reached the provider: it counts toward the daily number like an answered one.
func TestIdentifyProducts_AFailedCallCountsTowardTheDailyReads(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":true,"daily_reads":10}`, 200, "")
	a.fake.setAnswer(`{"items":[{"index":1,"choice":"c1","match":"maybe","reason":"x"}]}`)
	if _, err := a.svc.IdentifyProducts(a.ctx(), "system", identifyItems()); err == nil {
		t.Fatal("an answer outside the schema was accepted")
	}
	if st := a.svc.AutoReadState(a.ctx()); st.Used != 1 || st.IdentifyUsed != 1 {
		t.Errorf("daily reads %+v: a failed call that reached the provider counts", st)
	}
	if rows := a.activity(); !strings.HasPrefix(rows[0].Summary, "Identify software: ") {
		t.Errorf("the failed call's row %q does not carry the identification's tag", rows[0].Summary)
	}
}
