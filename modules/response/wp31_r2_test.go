package response_test

import (
	"context"
	"errors"
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
	e.exec.inRun = make(chan struct{}, 1)
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
	select { // the write itself is in flight, not only the read before it (D-356)
	case <-e.exec.inRun:
	case <-time.After(5 * time.Second):
		t.Fatal("the run step never started")
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
		`{"Cookie":"sid=1"}`, `{"cookies":{"a":"b"}}`,
	}
	for _, body := range refused {
		why := response.ValidateTpl(response.Tpl{Method: "POST", Path: "/d", Body: body}, "Run")
		if !strings.Contains(why, "looks like a credential") {
			t.Errorf("%s: %q", body, why)
		}
	}
	for body, key := range map[string]string{`{"a":1,"b":{"x":1,"x":2}}`: "x", `{"token":"x","token":"{name}"}`: "token", `{"a":[{"k":1},{"k":2}],"k":3,"k":4}`: "k"} {
		if why := response.ValidateTpl(response.Tpl{Method: "POST", Path: "/d", Body: body}, "Run"); !strings.Contains(why, "repeats the key "+key) {
			t.Errorf("%s: %q", body, why)
		}
	}
	for _, body := range []string{`{"a":{"k":1},"b":{"k":2}}`, `{"a":[{"k":1},{"k":2}]}`, `{"name":"vedette-{ip}"}`, `{"token":"{name}"}`, `{"api_key":"{name}"}`, `{"password":{id}}`, `{"ip_addresses":["{ip}"],"expiry":{expiry_s}}`, `{"auth":null,"session":false}`} {
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

// D-179 (8): the never-touch list fails closed. A box address source that cannot say (a host that never answered, an unreadable honeypot record)
// is a refusal, not a smaller list.
func TestWP31_L9_AnUnknownBoxAddressSetRefuses(t *testing.T) {
	fail := true
	e := newEnv(t, func(c *response.Config) {
		c.BoxAddrs = func() ([]netipAddr, error) {
			if fail {
				return nil, errors.New("vedette-host has not answered")
			}
			return nil, nil
		}
	})
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	if len(e.actions()) != 0 || !e.logHas("refused", "never_touch") {
		t.Fatalf("%d requests with an unknown box address set", len(e.actions()))
	}
	fail = false
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	if len(e.actions()) != 1 {
		t.Fatal("a known set refuses")
	}
}

// D-179 (8): the MACs of the decoys and of the cards are on the never-touch list (the MAC side), and an unreadable source refuses.
func TestWP31_L9_DecoyAndCardMACsAreNeverTouch(t *testing.T) {
	e := newEnv(t, func(c *response.Config) {
		c.BoxMACs = func() ([]string, error) { return []string{"02:11:22:33:44:55"}, nil }
	})
	e.svc.SetMACsForTest(func() ([]string, error) { return []string{"aa:bb:cc:00:00:01"}, nil })
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	if !hasEntry(l, "02:11:22:33:44:55") {
		t.Fatalf("the decoy MAC is not on the never-touch list: %+v", l)
	}
	e.svc.SetMACsForTest(func() ([]string, error) { return nil, errors.New("no interfaces") })
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	if len(e.actions()) != 0 || !e.logHas("refused", "never_touch") {
		t.Fatal("an unreadable MAC source did not refuse")
	}
}

// The card MACs come from the interfaces of the box itself.
func TestWP31_L9_CardMACsAreNeverTouch(t *testing.T) {
	e := newEnv(t)
	e.svc.SetMACsForTest(func() ([]string, error) { return []string{"aa:bb:cc:00:00:01"}, nil })
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	if !hasEntry(l, "aa:bb:cc:00:00:01") {
		t.Fatalf("the card MAC is not on the never-touch list: %+v", l)
	}
}

// D-179 (3): a change made before the steps were hashed still expires while its catalog entry is unchanged (the steps are re-rendered and
// compared, as before); once the entry was edited there is nothing to hold them to and the undo is not sent.
func TestWP31_L3_AChangeWithoutAHashUndoesWhileTheCatalogIsUnchanged(t *testing.T) {
	for name, edited := range map[string]bool{"unchanged": false, "edited": true} {
		e := banRequest(t)
		got := e.approveOnly()
		e.exec1(`UPDATE resp_actions SET items = json_remove(items, '$[0].exec_hash') WHERE id = ?`, got.ID)
		if edited {
			e.exec1(`UPDATE resp_catalog SET run = json_set(run, '$.headers', 'X-Trace: edited') WHERE id = 'fgt_ban_ip'`)
		}
		e.clock.Advance(31 * time.Minute)
		steps := e.exec.count()
		e.must(e.svc.Sweep(e.ctx()))
		it := e.only().Items[0]
		switch {
		case !edited && (it.Status != response.ItemRolledBack || e.exec.count() == steps):
			t.Errorf("%s: an in-force change from before the upgrade did not expire: %s %q", name, it.Status, resultOf(it))
		case edited && (it.Status != response.ItemExecuted || e.exec.count() != steps || !strings.Contains(resultOf(it), "hashed")):
			t.Errorf("%s: the undo of an unverifiable change was sent or not explained: %s %q", name, it.Status, resultOf(it))
		}
	}
}

// D-179 (4): a step whose context ended while the check before ran is not sent. The re-check right before the write refuses it as "not sent"
// (never "state unknown", and nothing is charged to the hourly limit); the stop flag still comes first.
func TestWP31_L5_AStepThatEndedBeforeItWasSentIsNotSent(t *testing.T) {
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	e.turnOn()
	ctx, cancel := context.WithCancel(e.ctx())
	if got := e.svc.RecheckForTest(ctx, false, "cisco_port_shut"); got != "" {
		t.Fatalf("a live step is refused: %s", got)
	}
	cancel()
	if got := e.svc.RecheckForTest(ctx, false, "cisco_port_shut"); got != "step_cancelled" {
		t.Fatalf("a step that ended is re-checked as %q", got)
	}
	_, err := e.svc.EmergencyStop(e.ctx(), admin)
	e.must(err)
	if got := e.svc.RecheckForTest(ctx, false, "cisco_port_shut"); got != "emergency_stop" {
		t.Fatalf("with the stop on: %q", got)
	}
}

// D-179 (6): the emergency stop cancels a run in flight but lets an undo already in flight finish (an undo is the safe direction, D-88 (4)).
func TestWP31_L5_AnUndoInFlightFinishesWhenTheStopIsPressed(t *testing.T) {
	var e *env
	e = newEnv(t, func(c *response.Config) {
		c.Executor = &afterExec{inner: c.Executor, after: func(s response.DeviceStep) {
			if s.Phase == "rollback" {
				_, err := e.svc.EmergencyStop(e.ctx(), admin)
				e.must(err)
			}
		}}
	})
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.exec.present = "198.51.100.7"
	e.approveOnly()
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	it := e.only().Items[0]
	if e.settings().StoppedAt == nil {
		t.Fatal("the stop did not take")
	}
	if it.Status != response.ItemRolledBack {
		t.Fatalf("the undo in flight was cut off by the stop: %s %q", it.Status, resultOf(it))
	}
}
