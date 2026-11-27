package ai_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai"
)

// One proposal call for a possible CVE runs as the explain-finding job: one activity row, the verdicts as the AI gave them, and the
// request carries only what findings sent (the CVE, the product, the version, the public text).
func TestProposePossible_OneCallOneActivityRow(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"items":[{"index":0,"status":"fixed","introduced":"","fixed_in":"15.1R7-S13","last_affected":"","line":"15.1","reason":"15.1 is before 15.1R7-S13.","quote":"15.1 versions before 15.1R7-S13 are affected","source":1}]}`)
	ans, err := a.svc.ProposePossible(a.ctx(), "it@acme.example", ai.PossibleRequest{CVE: "CVE-2099-72001", Description: "A flaw in Junos OS.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "juniper", Product: "Junos OS", Version: "15.1R7.9", Line: "15.1"}},
		Pages: []ai.RefPage{{URL: "https://supportportal.example/JSA1", Status: "ok", Text: "Junos OS: 15.1 versions before 15.1R7-S13 are affected."}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Verdicts) != 1 || ans.Verdicts[0].Status != "fixed" || ans.Verdicts[0].FixedIn != "15.1R7-S13" || ans.Verdicts[0].Line != "15.1" || ans.Model == "" || ans.ActivityID == "" {
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
	a.fake.setAnswer(`{"items":[{"index":0,"status":"unsure","introduced":"","fixed_in":"","last_affected":"","line":"","reason":"No range for 21.4.","quote":"","source":0}]}`)
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

// The automatic reading (actor system) runs only while the AI settings have it on, and makes at most the set number of calls a day: past
// it, 429 budget_reached and nothing is sent; a person's check is not held by it. GET /ai/config says how many it made today.
func TestProposePossible_AutomaticReadingHasItsSwitchAndDailyNumber(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"items":[{"index":0,"status":"unsure","introduced":"","fixed_in":"","last_affected":"","line":"","reason":"No range.","quote":"","source":0}]}`)
	req := ai.PossibleRequest{CVE: "CVE-2099-72001", Description: "A flaw in Junos OS.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "juniper", Product: "Junos OS", Version: "21.4R3-S6", Line: "21.4"}},
		Pages: []ai.RefPage{{URL: "https://supportportal.example/JSA1", Status: "ok", Text: "Junos OS 21.4 is affected by this issue."}}}
	if m := a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":true,"daily_reads":1}`, 200, ""); m["daily_reads"] != 1.0 {
		t.Fatalf("config %v: want daily_reads 1", m)
	}
	if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err != nil {
		t.Fatal(err)
	}
	sent := len(a.fake.reqs)
	if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err == nil || !strings.Contains(err.Error(), "used up") {
		t.Errorf("the second automatic call of a day of 1: %v, want budget_reached", err)
	}
	if len(a.fake.reqs) != sent {
		t.Error("a call past the daily number was sent")
	}
	if _, err := a.svc.ProposePossible(a.ctx(), "it@acme.example", req); err != nil {
		t.Errorf("a person's check is held by the automatic reading's daily number: %v", err)
	}
	if m := a.want("GET", "/ai/config", "viewer", "", 200, ""); m["reads_today"] != 1.0 || m["auto_read"] != true {
		t.Errorf("config %v: want one read today, on", m)
	}
	// a PUT without the fields keeps them; off stops the automatic reading
	if m := a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true}`, 200, ""); m["daily_reads"] != 1.0 {
		t.Errorf("a PUT without daily_reads changed it: %v", m)
	}
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":false}`, 200, "")
	if st := a.svc.AutoReadState(a.ctx()); st.Auto {
		t.Error("the automatic reading is still on")
	}
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":false,"daily_reads":50}`, 200, "")
	sent = len(a.fake.reqs)
	if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Errorf("an automatic call while switched off: %v, want it refused", err)
	}
	if len(a.fake.reqs) != sent {
		t.Error("an automatic call was sent while switched off")
	}
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"daily_reads":0}`, 400, "")
}

// The CVE record and the reference pages are public text the box fetched itself: the built-in hooks, which guard customer data and the
// topic of a request, do not read them, so a vendor's office phone number, a diff's line numbers or an email address on the page neither
// stop nor mask the reading (on a real box the CERT/CC page of a CVE was refused as "an ID number" and stalled every hourly reading).
// The question, which carries the customer's products and versions, still goes through every hook, and the customer's own hooks still
// read the pages.
func TestProposePossible_PublicPagesGoThroughTheCustomersHooksOnly(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"items":[{"index":0,"status":"unsure","introduced":"","fixed_in":"","last_affected":"","line":"","reason":"No range.","quote":"","source":0}]}`)
	page := "Vulnerability Note VU#644655. Widget 3.4 is affected. Contact cert@cert.org.\n\nSoftware Engineering Institute\n\n4500 Fifth Avenue\n\n" +
		"Pittsburgh, PA 15213-2612\n\n412-268-5800\n\nOffice Locations\n\n322\n\n322\n\nat = next ;\n\n323\n\n323\n\n324\n\n324\n\nRelease songs and movies."
	req := ai.PossibleRequest{CVE: "CVE-2099-72002", Description: "A flaw in Widget. Call 412-268-5800 for help.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "acme", Product: "Widget", Version: "3.4.1", Line: "3.4"}},
		Pages: []ai.RefPage{{URL: "https://www.kb.cert.org/vuls/id/644655", Status: "ok", Text: page}}}
	if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err != nil {
		t.Fatalf("a public page was refused: %v", err)
	}
	sent := a.fake.reqs[len(a.fake.reqs)-1]
	for _, want := range []string{"412-268-5800", "324\n\n324", "cert@cert.org", "songs"} {
		if !strings.Contains(sent.Messages[0].Text, want) {
			t.Errorf("%q of the public page did not reach the provider as the page states it", want)
		}
	}

	// the question carries the customer's inventory: an ID number in it still stops the call, nothing is sent
	n := len(a.fake.reqs)
	idReq := req
	idReq.Items = []ai.PossibleItem{{Index: 0, Vendor: "acme", Product: "Widget 079201234567", Version: "3.4.1", Line: "3.4"}}
	if _, err := a.svc.ProposePossible(a.ctx(), "system", idReq); err == nil || !strings.Contains(err.Error(), "ID number") {
		t.Errorf("an ID number in the products asked about: %v, want the call stopped", err)
	}
	// a customer's own hook still reads the public pages
	a.addBlockHook("No VU notes", "before_ai", "VU#644655")
	if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err == nil || !strings.Contains(err.Error(), "hook") {
		t.Errorf("a customer's hook matching the page: %v, want the call stopped", err)
	}
	if len(a.fake.reqs) != n {
		t.Error("a call a hook stopped was sent")
	}
}

// The automatic reading shares the explain-finding job's runaway fuse with a person's Explain: it is paced below the fuse, so a fast
// provider never lets a background run use up the minute. Its calls are spread out (never more than the background share in any
// minute) and a person's call between them is never refused.
func TestProposePossible_TheAutomaticReadingLeavesAPersonRoomInEveryMinute(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"items":[{"index":0,"status":"unsure","introduced":"","fixed_in":"","last_affected":"","line":"","reason":"No range.","quote":"","source":0}]}`)
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":6000000,"redact_pii":true,"auto_read":true,"daily_reads":500}`, 200, "")
	req := ai.PossibleRequest{CVE: "CVE-2099-72001", Description: "A flaw in Junos OS.",
		Items: []ai.PossibleItem{{Index: 0, Vendor: "juniper", Product: "Junos OS", Version: "21.4R3-S6", Line: "21.4"}},
		Pages: []ai.RefPage{{URL: "https://supportportal.example/JSA1", Status: "ok", Text: "Junos OS 21.4 is affected by this issue."}}}
	const background = 70
	var at []time.Time
	for i := range background {
		if _, err := a.svc.ProposePossible(a.ctx(), "system", req); err != nil {
			t.Fatalf("automatic call %d: %v", i+1, err)
		}
		at = append(at, a.clock.Now())
		if i%3 == 2 { // a person explains a finding now and then while the reading runs
			if _, err := a.svc.ProposePossible(a.ctx(), "it@acme.example", req); err != nil {
				t.Fatalf("a person's call after %d automatic calls was refused: %v", i+1, err)
			}
		}
	}
	// the background share of a minute: two thirds of the fuse, the rest is a person's
	for i := 20; i < len(at); i++ {
		if d := at[i].Sub(at[i-20]); d < time.Minute {
			t.Fatalf("21 automatic calls within %s (calls %d to %d): want at most 20 in any minute", d, i-19, i+1)
		}
	}
}
