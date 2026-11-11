package response_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-11 (S-RESP-1, INV-14e, FORBID-5): the AI writes plans, response checks every proposal, nothing runs without a person.

type fakePlanner struct {
	mu    sync.Mutex
	on    bool
	err   error
	steps func(t response.PlanTarget) []response.DraftStep
	asked []string
	acts  [][]response.AIAction
}

func (f *fakePlanner) Available(context.Context) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.on }

func (f *fakePlanner) Plan(_ context.Context, a response.PlanAsk) (response.PlanDraft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, a.Target.FindingID)
	f.acts = append(f.acts, a.Actions)
	if f.err != nil {
		return response.PlanDraft{}, f.err
	}
	return response.PlanDraft{Model: "fake-model", Profile: "Fake profile", Steps: f.steps(a.Target)}, nil
}

func goodSteps(response.PlanTarget) []response.DraftStep {
	return []response.DraftStep{
		{Kind: "contain", Title: "Block the address", Detail: "Add it to the block list.", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "192.168.10.21"}}},
		{Kind: "check", Title: "Check", Detail: "Look for signs of compromise."},
		{Kind: "patch", Title: "Patch", Detail: "Install the vendor fix."},
	}
}

// planEnv has three open critical findings (f1..f3) on one device; f1 already has a plan.
func aiPlanEnv(t *testing.T) (*env, *fakePlanner, *[]response.PlanTarget) {
	t.Helper()
	fp := &fakePlanner{on: true, steps: goodSteps}
	targets := &[]response.PlanTarget{}
	e := newEnv(t, func(c *response.Config) {
		c.Planner = fp
		c.Critical = func(context.Context) ([]response.PlanTarget, error) { return *targets, nil }
	})
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: "192.168.10.21", Approved: true}
	for _, id := range []string{"f1", "f2", "f3"} {
		e.dir.findings[id] = response.FindingInfo{ID: id, AssetID: "a1", CVE: "CVE-2024-000" + id[1:], Severity: "critical", Status: "confirmed"}
		*targets = append(*targets, response.PlanTarget{FindingID: id, CVE: "CVE-2024-000" + id[1:], AssetID: "a1", AssetName: "NAS", AssetIP: "192.168.10.21", AssetKind: "nas"})
	}
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES ('plan-f1','f1','CVE-2024-0001','a1','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]','[]')`)
	return e, fp, targets
}

func TestPlanJobPicksOpenCriticalFindingsWithoutAPlan(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 2 || strings.Join(fp.asked, ",") != "f2,f3" {
		t.Fatalf("saved %d, asked %v: want f2 and f3 only", n, fp.asked)
	}
	if e.count(`SELECT COUNT(*) FROM resp_plans`) != 3 {
		t.Fatal("two plans were not stored")
	}
	for _, a := range fp.acts[0] {
		if !a.Available {
			t.Fatalf("an action that is not available was offered: %+v", a)
		}
	}
	if _, err := e.svc.PlanOpen(e.ctx()); err != nil || len(fp.asked) != 2 {
		t.Fatalf("a finding with a plan was asked again: %v %v", err, fp.asked)
	}
	pl, err := e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	if !pl.AIAvailable || len(pl.Items) != 1 || pl.Items[0].Model != "fake-model" || pl.Items[0].Profile != "Fake profile" || len(pl.Items[0].Steps) != 3 {
		t.Fatalf("plan: %+v", pl)
	}
	if _, d := e.newest("proposal"); !strings.Contains(d, "AI-generated") {
		t.Fatalf("the log line does not say the plan is AI-generated: %q", d)
	}
}

func TestPlanJobAtMostThreePerRun(t *testing.T) {
	e, fp, targets := aiPlanEnv(t)
	for _, id := range []string{"f4", "f5", "f6", "f7"} {
		*targets = append(*targets, response.PlanTarget{FindingID: id, CVE: "CVE-2024-0009", AssetID: "a1", AssetName: "NAS", AssetIP: "192.168.10.21"})
	}
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 3 || len(fp.asked) != 3 {
		t.Fatalf("saved %d asked %d, want 3 and 3", n, len(fp.asked))
	}
}

func TestPlanStoresActionIDAndCheckedValuesOnly(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	fp.steps = func(response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{{Kind: "contain", Title: "Block", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: " 192.168.10.21 "}}}}
	}
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	var raw string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT steps FROM resp_plans WHERE finding_id = 'f2'`).Scan(&raw))
	var st []map[string]any
	e.must(json.Unmarshal([]byte(raw), &st))
	p := st[0]["proposal"].(map[string]any)
	keys := []string{}
	for k := range p {
		keys = append(keys, k)
	}
	for _, k := range keys {
		switch k {
		case "id", "action_id", "params", "ttl_min", "asset_id", "asset_name":
		default:
			t.Fatalf("a proposal holds the field %q", k)
		}
	}
	if p["action_id"] != "blocklist_add" || p["params"].(map[string]any)["ip"] != "192.168.10.21" {
		t.Fatalf("proposal: %v", p)
	}
}

func TestPlanRefusedAndAudited(t *testing.T) {
	cases := map[string][]response.DraftStep{
		"unknown action":         {{Kind: "contain", Title: "t", Detail: "d", ActionID: "rm_rf", Params: nil}},
		"bad type":               {{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "1.2.3.4; reboot"}}}},
		"reference":              {{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "{{ip}}"}}}},
		"unknown param":          {{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "203.0.113.50"}, {Name: "command", Value: "reboot"}}}},
		"missing param":          {{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add"}},
		"params no action":       {{Kind: "check", Title: "t", Detail: "d", Params: []response.DraftParam{{Name: "ip", Value: "203.0.113.50"}}}},
		"action on a check step": {{Kind: "check", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "203.0.113.50"}}}},
		"no steps":               {},
		"bad kind":               {{Kind: "wipe", Title: "t", Detail: "d"}},
		"never touch":            {{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: "192.168.10.1"}}}},
	}
	for name, steps := range cases {
		t.Run(name, func(t *testing.T) {
			e, fp, _ := aiPlanEnv(t)
			e.dir.devices["gw"] = response.DeviceInfo{ID: "gw", Name: "GW", IP: "192.168.10.1", Kind: "router"}
			fp.steps = func(response.PlanTarget) []response.DraftStep { return steps }
			n, err := e.svc.PlanOpen(e.ctx())
			e.must(err)
			if n != 0 || e.count(`SELECT COUNT(*) FROM resp_plans`) != 1 { // only the seeded plan of f1
				t.Fatalf("saved %d, plans %d: a refused plan was stored", n, e.count(`SELECT COUNT(*) FROM resp_plans`))
			}
			if !e.logHas("refused", "plan_invalid") || e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.plan_refused'`) == 0 {
				t.Fatal("the refusal is not in the response log and the audit")
			}
		})
	}
}

func TestPlanAIOffAsksNothingAndTheRestWorks(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	fp.on = false
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 0 || len(fp.asked) != 0 {
		t.Fatalf("AI off: saved %d, asked %v", n, fp.asked)
	}
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	if pl.AIAvailable || len(pl.Items) != 1 { // the plan stored before stays visible
		t.Fatalf("plans with AI off: %+v", pl)
	}
	e.must(e.svc.Sweep(e.ctx()))
	if _, err := e.svc.Catalog(e.ctx(), false); err != nil {
		t.Fatal(err)
	}
	// no Planner at all: the same, and the job list still has the job
	e2 := newEnv(t)
	if n, err := e2.svc.PlanOpen(e2.ctx()); err != nil || n != 0 {
		t.Fatalf("nil planner: %d %v", n, err)
	}
	if pl, err := e2.svc.Plans(e2.ctx(), ""); err != nil || pl.AIAvailable {
		t.Fatalf("nil planner plans: %+v %v", pl, err)
	}
}

func TestPlanUnavailableStopsAndFailureWaits(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	fp.err = response.ErrPlanUnavailable
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 0 || len(fp.asked) != 1 {
		t.Fatalf("unavailable: saved %d asked %v, want the run to stop after one call", n, fp.asked)
	}
	fp.err = errors.New("the answer did not fit the format")
	fp.asked = nil
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	first := len(fp.asked)
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if first == 0 || len(fp.asked) != first {
		t.Fatalf("a failed finding was asked again at once: %d then %d", first, len(fp.asked))
	}
	e.clock.t = e.clock.t.Add(61 * 60 * 1e9)
	if _, err = e.svc.PlanOpen(e.ctx()); err != nil || len(fp.asked) == first {
		t.Fatalf("a failed finding is never asked again: %v", fp.asked)
	}
}

// A plan is text and proposals. Writing it changes nothing and runs nothing; a proposal becomes a request only when a person asks, and a
// request still waits for approval (FORBID-5).
func TestPlanNeverExecutesWithoutTheApprovalFlow(t *testing.T) {
	e, _, _ := aiPlanEnv(t)
	e.turnOn()
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || len(e.exec.steps) != 0 {
		t.Fatal("writing a plan created a request or touched a device")
	}
	pl, err := e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	pr := pl.Items[0].Steps[0].Proposal
	if pr == nil || pr.State != "ready" || pr.RequestID != nil {
		t.Fatalf("proposal: %+v", pr)
	}
	req, err := e.svc.RequestProposal(e.ctx(), oper, pr.ID)
	e.must(err)
	if req.Status != response.StatusPending || req.Source != "ai" || len(e.exec.steps) != 0 {
		t.Fatalf("a requested proposal must wait for a person: %+v", req)
	}
}

func (e *env) aiMayPropose(id string, on bool) {
	e.t.Helper()
	_, err := e.svc.ChangeAction(e.ctx(), admin, id, response.CatalogUpdate{AIMayPropose: &on, Present: map[string]bool{"ai_may_propose": true}})
	e.must(err)
}

func (e *env) planRefused(why string) {
	e.t.Helper()
	if n := e.count(`SELECT COUNT(*) FROM resp_plans`); n != 1 { // only the seeded plan of f1
		e.t.Fatalf("a refused plan was stored (%d plans)", n)
	}
	if !e.logHas("refused", why) || e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.plan_refused'`) == 0 {
		e.t.Fatalf("the refusal (%s) is not in the response log and the audit", why)
	}
}

// H1: the AI picks the values of an action, nothing else ties them to the device of the finding, so the plan must.
func TestPlanTargetMustBeTheDeviceOfTheFinding(t *testing.T) {
	cases := map[string]struct {
		action string
		param  response.DraftParam
		ip     string
	}{
		"another address":                 {action: "blocklist_add", param: response.DraftParam{Name: "ip", Value: "203.0.113.50"}, ip: "192.168.10.21"},
		"another domain":                  {action: "pihole_block", param: response.DraftParam{Name: "domain", Value: "login.example.org"}, ip: "192.168.10.21"},
		"the uplink port":                 {action: "cisco_port_shut", param: response.DraftParam{Name: "interface", Value: "Gi1/0/48"}, ip: "192.168.10.21"},
		"no address known for the device": {action: "cisco_port_shut", param: response.DraftParam{Name: "interface", Value: "Gi1/0/1"}, ip: ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e, fp, targets := aiPlanEnv(t)
			e.firewall("pihole_block")
			e.aiMayPropose("pihole_block", true)
			e.conns.list = append(e.conns.list, response.ConnectionInfo{Connection: response.Connection{ID: "cn-sw", Name: "Core switch", Enabled: true, Kind: "ssh", WriteTools: []string{"write"}}, Target: "sw.lan"})
			cid, on := "cn-sw", true
			_, err := e.svc.ChangeAction(e.ctx(), admin, "cisco_port_shut", response.CatalogUpdate{ConnectionID: &cid, Enabled: &on, Present: map[string]bool{"connection_id": true, "enabled": true}})
			e.must(err)
			e.aiMayPropose("cisco_port_shut", true)
			for i := range *targets {
				(*targets)[i].AssetIP = c.ip
			}
			fp.steps = func(response.PlanTarget) []response.DraftStep {
				return []response.DraftStep{{Kind: "contain", Title: "t", Detail: "d", ActionID: c.action, Params: []response.DraftParam{c.param}}}
			}
			n, err := e.svc.PlanOpen(e.ctx())
			e.must(err)
			if n != 0 {
				t.Fatalf("a plan that targets something else was stored (%d)", n)
			}
			if c.ip == "" {
				e.planRefused("never_touch")
				return
			}
			e.planRefused("evidence_mismatch")
		})
	}
}

// The same check is made again when a proposal is requested, against the inventory's word about the device.
func TestRequestProposalRefusesAnotherTarget(t *testing.T) {
	e := newEnv(t)
	e.turnOn()
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "critical", Status: "confirmed"}
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: "192.168.10.21", Approved: true}
	steps := `[{"kind":"contain","title":"t","detail":"d","proposal":{"id":"pr-x","action_id":"blocklist_add","params":{"ip":"203.0.113.50"},"asset_id":"a1","asset_name":"NAS"}}]`
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES ('plan-f1','f1','CVE-2024-0001','a1','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]',?)`, steps)
	_, err := e.svc.RequestProposal(e.ctx(), oper, "pr-x")
	wantCode(t, err, 409, "evidence_mismatch")
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 {
		t.Fatal("a request was made")
	}
}

func TestPlanRefusedWhenTheActionIsNotAllowedOrTooBig(t *testing.T) {
	block := func(ip string) response.DraftStep {
		return response.DraftStep{Kind: "contain", Title: "t", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: ip}}}
	}
	advice := response.DraftStep{Kind: "check", Title: "t", Detail: "d"}
	cases := map[string]struct {
		arm   func(e *env)
		steps []response.DraftStep
	}{
		"ai_may_propose off": {arm: func(e *env) { e.aiMayPropose("blocklist_add", false) }, steps: []response.DraftStep{block("192.168.10.21")}},
		"action disabled": {arm: func(e *env) {
			off := false
			_, err := e.svc.ChangeAction(e.ctx(), admin, "blocklist_add", response.CatalogUpdate{Enabled: &off, Present: map[string]bool{"enabled": true}})
			e.must(err)
		}, steps: []response.DraftStep{block("192.168.10.21")}},
		"more than 3 actions": {steps: []response.DraftStep{block("192.168.10.21"), block("192.168.10.21"), block("192.168.10.21"), block("192.168.10.21")}},
		"more than 6 steps":   {steps: []response.DraftStep{advice, advice, advice, advice, advice, advice, advice}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e, fp, _ := aiPlanEnv(t)
			if c.arm != nil {
				c.arm(e)
			}
			fp.steps = func(response.PlanTarget) []response.DraftStep { return c.steps }
			n, err := e.svc.PlanOpen(e.ctx())
			e.must(err)
			if n != 0 {
				t.Fatalf("saved %d", n)
			}
			e.planRefused("plan_invalid")
		})
	}
}

func TestPlanBackoffAndDailyBudget(t *testing.T) {
	e, fp, targets := aiPlanEnv(t)
	*targets = (*targets)[1:2] // f2 alone
	fp.err = errors.New("the answer did not fit the format")
	step := func(wait time.Duration) int {
		e.clock.t = e.clock.t.Add(wait)
		before := len(fp.asked)
		_, err := e.svc.PlanOpen(e.ctx())
		e.must(err)
		return len(fp.asked) - before
	}
	if step(0) != 1 || step(59*time.Minute) != 0 || step(2*time.Minute) != 1 { // 1 h after the 1st failure
		t.Fatal("first back-off is not one hour")
	}
	if step(5*time.Hour) != 0 || step(2*time.Hour) != 1 { // 6 h after the 2nd
		t.Fatal("second back-off is not six hours")
	}
	if step(23*time.Hour) != 0 || step(2*time.Hour) != 1 { // 24 h after the 3rd
		t.Fatal("third back-off is not 24 hours")
	}
	if step(1000*time.Hour) != 0 {
		t.Fatal("a finding that failed four times is asked again")
	}
	// the day's budget: 20 calls, however many findings wait
	e2, fp2, targets2 := aiPlanEnv(t)
	fp2.err = errors.New("format")
	for i := 0; i < 40; i++ {
		*targets2 = append(*targets2, response.PlanTarget{FindingID: "g" + string(rune('A'+i%26)) + string(rune('a'+i/26)), CVE: "CVE-2024-0100", AssetID: "a1", AssetName: "NAS", AssetIP: "192.168.10.21"})
	}
	for i := 0; i < 15; i++ {
		_, err := e2.svc.PlanOpen(e2.ctx())
		e2.must(err)
	}
	if len(fp2.asked) != 20 {
		t.Fatalf("%d plan calls in one day, want 20", len(fp2.asked))
	}
	e2.clock.t = e2.clock.t.Add(24 * time.Hour)
	if _, err := e2.svc.PlanOpen(e2.ctx()); err != nil || len(fp2.asked) <= 20 {
		t.Fatalf("the next day starts a new budget: %d %v", len(fp2.asked), err)
	}
}

func TestPlanAndRequestStopWhileTheAIIsPaused(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	e.turnOn()
	if _, err := e.svc.PlanOpen(e.ctx()); err != nil {
		t.Fatal(err)
	}
	pl, err := e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	pid := pl.Items[0].Steps[0].Proposal.ID
	asked := len(fp.asked)
	e.setting("$.ai.paused_at", store.FormatTS(e.clock.Now()))
	e.setting("$.ai.paused_reason", "3 of the last 5 AI requests were rejected")
	if n, err := e.svc.PlanOpen(e.ctx()); err != nil || n != 0 || len(fp.asked) != asked {
		t.Fatalf("paused: saved %d asked %d: %v", n, len(fp.asked), err)
	}
	_, err = e.svc.RequestProposal(e.ctx(), oper, pid)
	wantCode(t, err, 409, "ai_paused")
}

func TestPlanDoesNotListChannelsItWasNotSentTo(t *testing.T) {
	e, _, _ := aiPlanEnv(t)
	e.exec1(`UPDATE resp_plans SET steps = '[]'`)
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	if len(pl.Items) != 1 || len(pl.Items[0].SentTo) != 0 {
		t.Fatalf("sent_to: %+v", pl.Items)
	}
}

// The live run once returned a plan with a message step (msg_send, one free-text value) that the text type refused, which dropped the whole plan.
// Such an action is no longer offered to the AI; one that still arrives is checked like any other.
func TestPlanDoesNotOfferActionsWithOnlyFreeText(t *testing.T) {
	e, fp, _ := aiPlanEnv(t)
	e.aiMayPropose("msg_send", true)
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if len(fp.acts) == 0 {
		t.Fatal("the planner was not asked")
	}
	offered := []string{}
	for _, a := range fp.acts[0] {
		offered = append(offered, a.ID)
	}
	if slices.Contains(offered, "msg_send") || !slices.Contains(offered, "blocklist_add") {
		t.Fatalf("offered %v", offered)
	}
	// the draft as the model returned it: the long, many-sentence text is refused by the type, and the plan is refused with it
	e2, fp2, _ := aiPlanEnv(t)
	e2.aiMayPropose("msg_send", true)
	fp2.steps = func(response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{
			{Kind: "contain", Title: "Limit exposure", Detail: "d"},
			{Kind: "check", Title: "Check", Detail: "d"},
			{Kind: "patch", Title: "Patch", Detail: "d"},
			{Kind: "contain", Title: "Tell the team", Detail: "d", ActionID: "msg_send", Params: []response.DraftParam{{Name: "text", Value: strings.Repeat("The NAS is exposed to CVE-2024-3400; please review it now. ", 12)}}},
		}
	}
	n, err := e2.svc.PlanOpen(e2.ctx())
	e2.must(err)
	if n != 0 || !e2.logHas("refused", "step 4 cannot be planned (invalid_target)") {
		t.Fatalf("saved %d", n)
	}
}
