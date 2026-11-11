package response_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// WP-31 review, slice R2: the execution path (D-179).

// L1: when the second approval completes a request, the first approver is read again. A first approver who was disabled since does not count:
// the second approval stays one approval and the request waits for another person.
func TestWP31_L1_ADisabledFirstApproverNoLongerCounts(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_policy_disable")
	e.turnOn()
	e.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	if a.RequiresApprovals != 2 {
		t.Fatalf("request: %+v", a)
	}
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	u := e.users.m["u-op"]
	u.Disabled = true
	e.users.m["u-op"] = u
	got, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, "")
	e.must(err)
	if got.Status != response.StatusPending || len(got.Approvals) != 1 || got.Approvals[0].UserID != oper2.ID || e.exec.count() != 0 {
		t.Fatalf("a disabled approver counted: status %s, approvals %+v, %d steps", got.Status, got.Approvals, e.exec.count())
	}
	if !e.logHas("approved", "no longer counts") {
		t.Error("the dropped approval is not in the log")
	}
	done, err := e.svc.Approve(e.ctx(), admin, a.ID, nil, "")
	e.must(err)
	if done.Status != response.StatusExecuted || len(done.Approvals) != 2 {
		t.Fatalf("after a second valid person: status %s, approvals %+v", done.Status, done.Approvals)
	}
}

// L1, the same for a demotion.
func TestWP31_L1_ADemotedFirstApproverNoLongerCounts(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_policy_disable")
	e.turnOn()
	e.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	u := e.users.m["u-op"]
	u.Role = "viewer"
	e.users.m["u-op"] = u
	got, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, "")
	e.must(err)
	if got.Status != response.StatusPending || e.exec.count() != 0 {
		t.Fatalf("a demoted approver counted: status %s, %d steps", got.Status, e.exec.count())
	}
}

// L2: a step whose outcome is not known (a time-out, a 5xx) may have changed the device, so it uses up the hourly limit like one that ran.
func TestWP31_L2_AnUnknownOutcomeUsesUpTheHourlyLimit(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	e.fire(e.trap("h2", "192.168.10.158"))
	l := e.actions()
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 1 })
	e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
	got, err := e.svc.Approve(e.ctx(), oper, l[1].ID, nil, "")
	e.must(err)
	if it := got.Items[0]; it.Status != response.ItemFailed || !it.StateUnknown {
		t.Fatalf("the premise: the item is %s, state unknown %v", it.Status, it.StateUnknown)
	}
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 429, "rate_limited")
}

// L3: the rollback that goes out is the one that was rendered when the request was made. The catalog entry is edited after the run, so the
// re-render check is not asked; the stored rollback is then altered: the TTL sweep must not send it.
func TestWP31_L3_AnUndoRefusesARollbackThatDoesNotMatchItsHash(t *testing.T) {
	e := banRequest(t)
	got := e.approveOnly()
	if it := got.Items[0]; it.Status != response.ItemExecuted {
		t.Fatalf("the premise: %+v", it)
	}
	e.exec1(`UPDATE resp_catalog SET run = json_set(run, '$.headers', 'X-Trace: edited') WHERE id = 'fgt_ban_ip'`)
	e.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].exec.rollback.body', '{"ip_addresses":["192.168.10.1"]}') WHERE id = ?`, got.ID)
	e.clock.Advance(31 * time.Minute)
	steps := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	it := e.only().Items[0]
	if e.exec.count() != steps || it.Status != response.ItemExecuted || !strings.Contains(resultOf(it), "hash") || !e.logHas("failed", "hash") {
		t.Fatalf("an altered rollback was sent or not explained: steps %s, item %s %q", e.phaseList(), it.Status, resultOf(it))
	}
}

// L5: the emergency stop cancels a step that is being sent. The item ends as "stopped", state unknown, and the log says why; it does not wait
// for the step's own time limit.
func TestWP31_L5_EmergencyStopCancelsAStepInFlight(t *testing.T) {
	e := banRequest(t)
	e.exec.hold = make(chan struct{}) // the device is slow to answer the run step
	e.svc.SetStepLimitForTest(20 * time.Second)
	id := e.only().ID
	type result struct {
		got response.ActionRequest
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
		done <- result{got, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for e.count(`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%"running_at"%'`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the step never started")
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-e.ctx().Done():
		}
	}
	start := time.Now()
	_, err := e.svc.EmergencyStop(e.ctx(), admin)
	e.must(err)
	select {
	case r := <-done:
		e.must(r.err)
		it := r.got.Items[0]
		if it.Status != response.ItemFailed || !it.StateUnknown || !strings.Contains(resultOf(it), "emergency stop") || !e.logHas("failed", "emergency stop") {
			t.Fatalf("item %s state unknown %v %q", it.Status, it.StateUnknown, resultOf(it))
		}
		if time.Since(start) > 5*time.Second {
			t.Error("the stop waited for the step")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the step in flight was not interrupted by the emergency stop")
	}
}

// Body credentials: D-174 covers headers; a JSON body key that names a credential may only hold exactly one placeholder (D-179 (7)).
func TestWP31_BodyCredentialKeyWithALiteralValueIsRefused(t *testing.T) {
	refused := []string{
		`{"api_key":"abc123"}`, `{"apiKey":"abc123"}`, `{"API-KEY":"abc123"}`, `{"token":"x"}`, `{"password":"hunter2"}`, `{"secret":12345}`,
		`{"auth":"x"}`, `{"session":"x"}`, `{"user":{"Password":"x"}}`, `{"a":[{"auth-token":"x"}]}`, `{"token":"Bearer {name}"}`, `{"token":"{name}x"}`,
		`{"auth":{"user":"admin"}}`, `{"password":""}`, `{"token":"8191919191919191919"}`,
	}
	for _, body := range refused {
		why := response.ValidateTpl(response.Tpl{Method: "POST", Path: "/d", Body: body}, "Run")
		if !strings.Contains(why, "looks like a credential") {
			t.Errorf("%s: %q", body, why)
		}
	}
	for _, body := range []string{`{"name":"vedette-{ip}"}`, `{"token":"{name}"}`, `{"api_key":"{name}"}`, `{"password":{id}}`, `{"ip_addresses":["{ip}"],"expiry":{expiry_s}}`, `{"auth":null,"session":false}`} {
		if why := response.ValidateTpl(response.Tpl{Method: "POST", Path: "/d", Body: body}, "Run"); why != "" {
			t.Errorf("%s was refused: %q", body, why)
		}
	}
	e := precheckEnv(t)
	in := apiAction()
	in.Run.Body = `{"api_key":"abc123","domain":"{domain}"}`
	if _, err := e.svc.AddAction(e.ctx(), admin, in); err == nil {
		t.Error("an action with a credential in its body was saved")
	}
}
