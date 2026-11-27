package ai_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
)

// One identification call runs as the explain-finding job with the product_identity schema: one activity row, the choices as the AI
// gave them, the programs and candidates sent as fenced data, and no memory of the box. The automatic identification shares the daily
// number of automatic reads with the reading of advisories.
func TestIdentifyProducts_OneCallSharesTheDailyReads(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.addMemory("Our core router CORE-RTR-01 runs Junos OS 21.4R3-S6 at 10.20.0.1")
	a.fake.setAnswer(`{"items":[{"index":1,"choice":"c1","reason":"Same publisher and name."}]}`)
	items := []ai.IdentifyItem{{Index: 1, Publisher: "Cisco Systems, Inc.", Name: "Cisco Packet Tracer 8.2.1 64Bit", Version: "8.2.1.118",
		Candidates: []ai.IdentifyCandidate{{ID: "c1", Title: "cisco packet tracer", Product: "cisco:packet_tracer", CVEs: 1}}}}
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":true,"daily_reads":1}`, 200, "")
	ans, err := a.svc.IdentifyProducts(a.ctx(), "system", items)
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Choices) != 1 || ans.Choices[0].Choice != "c1" || ans.Model == "" || ans.ActivityID == "" {
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
	if st := a.svc.AutoReadState(a.ctx()); st.Used != 1 || st.Left != 0 {
		t.Errorf("daily reads %+v: the identification counts as one automatic read", st)
	}
	sent := len(a.fake.reqs)
	if _, err := a.svc.IdentifyProducts(a.ctx(), "system", items); err == nil || !strings.Contains(err.Error(), "used up") {
		t.Errorf("an identification past the daily number: %v, want budget_reached", err)
	}
	if len(a.fake.reqs) != sent {
		t.Error("a call past the daily number was sent")
	}
	if rows := a.activity(); rows[0].Job != "explain-finding" || !strings.Contains(rows[0].Summary, "Identified the product of 1 program") {
		t.Errorf("activity %+v", rows[0])
	}
}
