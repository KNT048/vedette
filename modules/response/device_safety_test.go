package response_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// Review of slice 13b-6, High and Medium findings: what the approver sees is what is sent; every write is re-checked right before it goes out; an
// outcome that is not clear is never "nothing changed" and has a way out; an undo survives edits of the connection; the texts the output is
// compared with are normalised like the output.

// banRequest makes one open request: fgt_ban_ip on the firewall with an undo time of 30 minutes.
func banRequest(t *testing.T, opts ...func(*response.Config)) *env {
	t.Helper()
	e := newEnv(t, opts...)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	return e
}

func (e *env) approveOnly() response.ActionRequest {
	e.t.Helper()
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	return got
}

func (e *env) phaseList() string { return strings.Join(e.exec.phases(), ",") }

// M3: the headers of a step, with their typed values filled in, are in the request the approver reads; so is {expiry_s} as the number that is sent.
func TestDevice_HeadersAreShownToTheApprover(t *testing.T) {
	e := precheckEnv(t)
	in := apiAction()
	in.Run.Headers = "X-Block-Scope: {domain}\nX-Commit: now"
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	req := e.only()
	rest := req.Items[0].Change.Rest
	if rest == nil || rest.Headers["X-Block-Scope"] != "bad.example.com" || rest.Headers["X-Commit"] != "now" || len(rest.Headers) != 2 {
		b, _ := json.Marshal(req.Items[0].Change)
		t.Fatalf("the request shows %s", b)
	}
	e.must(func() error { _, err := e.svc.Approve(e.ctx(), oper, req.ID, nil, ""); return err }())
	for _, s := range e.exec.steps {
		if s.Phase == "run" && (s.Headers["X-Block-Scope"] != rest.Headers["X-Block-Scope"] || s.Headers["X-Commit"] != "now" || len(s.Headers) != 2) {
			t.Fatalf("shown %v, sent %v", rest.Headers, s.Headers)
		}
	}
}

func TestDevice_ExpirySecondsAreShownAsTheNumberThatIsSent(t *testing.T) {
	e := banRequest(t)
	req := e.only()
	body := ""
	if r := req.Items[0].Change.Rest; r != nil && r.Body != nil {
		body = *r.Body
	}
	if body != `{"ip_addresses":["198.51.100.7"],"expiry":1800}` {
		t.Fatalf("the request shows the body %q", body)
	}
	e.approveOnly()
	if run := e.exec.runStep(); run.Body != body {
		t.Fatalf("shown %q, sent %q", body, run.Body)
	}
}

// L1: the stored steps are compared with what the catalog row renders; a row edited behind the API sends nothing.
func TestDevice_ExecThatDiffersFromTheApprovedChangeIsNotSent(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_vip_disable")
	e.turnOn()
	e.rule("VIP", "ioc_connection", []response.RuleAction{{ActionID: "fgt_vip_disable", Params: map[string]string{"name": "web-vip"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	req := e.only()
	e.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].exec.run.url', 'https://fw.lan/api/v2/cmdb/firewall/vip/payroll-vip') WHERE id = ?`, req.ID)
	got, err := e.svc.Approve(e.ctx(), oper, req.ID, nil, "")
	e.must(err)
	if e.exec.count() != 0 || got.Items[0].Status != response.ItemFailed || !strings.Contains(resultOf(got.Items[0]), "altered") {
		t.Fatalf("steps %v, item %+v", e.phaseList(), got.Items[0])
	}
}

func TestDevice_ExecAlteredAfterTheRunIsNotSentAsAnUndo(t *testing.T) {
	e := banRequest(t)
	got := e.approveOnly()
	e.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].exec.rollback.body', '{"ip_addresses":["192.168.10.1"]}') WHERE id = ?`, got.ID)
	e.clock.Advance(31 * time.Minute)
	steps := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	if e.exec.count() != steps || e.only().Items[0].Status != response.ItemExecuted || !strings.Contains(resultOf(e.only().Items[0]), "altered") {
		t.Fatalf("an altered rollback was sent: %v, %+v", e.phaseList(), e.only().Items[0])
	}
}

// panicky panics in the run step: the least known outcome there is.
type panicky struct{ inner response.Executor }

func (p panicky) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	if s.Phase == "run" {
		if f, ok := p.inner.(*fakeExecutor); ok { // the write reached the device before the crash: the fake reads back as after a run
			f.mu.Lock()
			f.last = "run"
			f.mu.Unlock()
		}
		panic("writer bug after the request was sent")
	}
	return p.inner.Execute(ctx, s)
}

// M1: a crash during a write is state unknown, in force, never "Nothing was changed". Read back at once: the device shows the change, shows something
// else, or cannot tell.
func TestDevice_PanicDuringAWriteIsUnknownAndSettledByTheReadBack(t *testing.T) {
	for name, tc := range map[string]struct {
		verify   map[string]response.StepStatus
		present  string
		wantItem response.ItemStatus
		inForce  bool
	}{
		"the read-back cannot tell":   {map[string]response.StepStatus{"readback": response.StepUnknown}, "", response.ItemFailed, true},
		"the read-back shows it":      {nil, "198.51.100.7", response.ItemExecuted, true},
		"the read-back does not show": {nil, "nothing listed", response.ItemFailed, false},
	} {
		e := banRequest(t, func(c *response.Config) { c.Executor = panicky{c.Executor} })
		e.exec.status, e.exec.present = tc.verify, tc.present
		got := e.approveOnly()
		it := got.Items[0]
		in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw")
		e.must(err)
		if it.Status != tc.wantItem || in != tc.inForce {
			t.Errorf("%s: item %s %q, in force %v", name, it.Status, resultOf(it), in)
		}
		if tc.inForce && it.Status == response.ItemFailed && (strings.Contains(resultOf(it), "Nothing was changed") || !it.StateUnknown) {
			t.Errorf("%s: an unknown outcome is described as %q (state_unknown %v)", name, resultOf(it), it.StateUnknown)
		}
	}
}

// L2: an undo whose read-back prints nothing proves nothing: the item stays in force and says so.
func TestDevice_SilentReadBackAfterTheUndoIsNotProof(t *testing.T) {
	e := switchRequest(t)
	e.exec.pre, e.exec.present = staticAccess, "Gi1/0/12 disabled"
	e.approveOnly()
	e.exec.after = " \r\n\x1b[0m"
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	it := e.only().Items[0]
	if it.Status != response.ItemExecuted || strings.Contains(resultOf(it), "the change is gone") {
		t.Fatalf("a read-back that printed nothing is reported as proof: %s %q", it.Status, resultOf(it))
	}
	if in, _ := e.svc.ChangesInForce(e.ctx(), "cn-sw"); !in {
		t.Fatal("the item left ChangesInForce on a read-back that proved nothing")
	}
}

// L3: the retry of an undo whose outcome is not clear reads first. Unclear: wait (the rollback is not sent again). Gone: done. Present: send again.
func TestDevice_RetryOfAnUnclearUndoReadsFirst(t *testing.T) {
	e := switchRequest(t)
	e.exec.pre, e.exec.present = staticAccess, "Gi1/0/12 disabled"
	e.approveOnly()
	e.exec.after = " "
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx())) // rollback + a silent read-back: unclear
	mark := e.exec.count()
	e.must(e.svc.Sweep(e.ctx())) // still silent: wait, only a read
	if got := strings.Join(e.exec.phases()[mark:], ","); got != "verify" {
		t.Fatalf("an unclear undo was retried with %q, want only a read-back", got)
	}
	mark = e.exec.count()
	e.exec.last, e.exec.after = "rollback", "nothing listed"
	e.exec.present = "Gi1/0/12 disabled"
	// The device now answers and the text is gone: the undo is done without sending anything again.
	e.exec.last = "rollback"
	e.must(e.svc.Sweep(e.ctx()))
	if got := strings.Join(e.exec.phases()[mark:], ","); got != "verify" || e.only().Status != response.StatusRolledBack {
		t.Fatalf("gone: steps %q, request %s", got, e.only().Status)
	}
}

func TestDevice_RetryOfAnUnclearUndoSendsAgainWhenTheChangeIsStillThere(t *testing.T) {
	e := switchRequest(t)
	e.exec.pre, e.exec.present = staticAccess, "Gi1/0/12 disabled"
	e.approveOnly()
	e.exec.after = " "
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	mark := e.exec.count()
	e.exec.last = "run" // the device shows the change again
	e.must(e.svc.Sweep(e.ctx()))
	if got := strings.Join(e.exec.phases()[mark:], ","); got != "verify,rollback,verify" {
		t.Fatalf("steps %q, want a read, the rollback again and its read-back", got)
	}
}

// H2: a refusal text written the way a device pretty-prints JSON still refuses; the text is saved in the form it is compared in.
func TestDevice_JSONRefusalTextWithASpaceStillRefuses(t *testing.T) {
	e := precheckEnv(t)
	act, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Shut a port (API)", Description: "d", ConnectionID: "cn-http", Risk: response.RiskMedium, Enabled: true,
		Run: response.Tpl{Method: "PUT", Path: "/api/ports/{interface}", Body: `{"enabled":false}`}, Rollback: response.Tpl{Method: "PUT", Path: "/api/ports/{interface}", Body: `{"enabled":true}`},
		Precheck: response.Tpl{Method: "GET", Path: "/api/ports/{interface}"}, PrecheckRefuse: []string{`"mode": "trunk"`}, PrecheckExpect: `"enabled": true`})
	e.must(err)
	if len(act.PrecheckRefuse) != 1 || act.PrecheckRefuse[0] != `"mode":"trunk"` || act.PrecheckExpect != `"enabled":true` {
		t.Fatalf("saved %v %q: the texts are stored in the compacted form", act.PrecheckRefuse, act.PrecheckExpect)
	}
	e.turnOn()
	e.rule("Shut", "honeypot", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"interface": "1-1"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	e.exec.pre = `{"name": "1-1", "mode": "trunk", "enabled": true}`
	got := e.approveOnly()
	if strings.Contains(e.phaseList(), "run") || got.Items[0].Status != response.ItemFailed {
		t.Fatalf("the check printed %s and the run went out anyway: %s (item %s)", e.exec.pre, e.phaseList(), got.Items[0].Status)
	}
}

// H2: an expect written with spaces is found in compacted JSON output after the run, and is absent from it after the undo.
func TestDevice_JSONExpectWithSpacesIsFoundInTheReadBack(t *testing.T) {
	e := precheckEnv(t)
	in := apiAction()
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Expect: `"domain": "{domain}"`}
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	if act.Verify.Expect != `"domain":"{domain}"` {
		t.Fatalf("saved expect %q", act.Verify.Expect)
	}
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(30)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	e.exec.present = `{"domain": "bad.example.com", "enabled": true}`
	got := e.approveOnly()
	if v := got.Items[0].Verified; v == nil || !v.OK {
		t.Fatalf("the read-back did not find the text: %+v", got.Items[0].Verified)
	}
	e.exec.after = `{"results": []}`
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	if e.only().Status != response.StatusRolledBack {
		t.Fatalf("the undo was not confirmed: %+v", e.only().Items[0])
	}
}

// H3: a stop pressed while the check before runs stops the write. The run is re-checked right before it goes out: the stop, the execution
// switch, the breaker and the action still being enabled.
func TestDevice_EmergencyStopDuringTheCheckBeforeStopsTheWrite(t *testing.T) {
	var e *env
	e = newEnv(t, func(c *response.Config) {
		c.Executor = &afterExec{inner: c.Executor, after: func(s response.DeviceStep) {
			if s.Phase == "precheck" {
				_, err := e.svc.EmergencyStop(e.ctx(), admin)
				e.must(err)
			}
		}}
	})
	e.sshSwitch("cisco_port_shut")
	e.turnOn()
	e.rule("Shut the port", "honeypot", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	e.exec.pre = staticAccess
	got := e.approveOnly()
	if e.phaseList() != "precheck" || got.Items[0].Status != response.ItemFailed || !e.logHas("refused", "emergency_stop") {
		t.Fatalf("steps %s, item %+v", e.phaseList(), got.Items[0])
	}
}

func TestDevice_SwitchOffOrActionDisabledDuringTheCheckBeforeStopsTheWrite(t *testing.T) {
	for name, act := range map[string]func(e *env){
		"execution switched off": func(e *env) { _, err := e.svc.SetExecution(e.ctx(), admin, false, ""); e.must(err) },
		"action disabled": func(e *env) {
			off := false
			_, err := e.svc.ChangeAction(e.ctx(), admin, "cisco_port_shut", response.CatalogUpdate{Enabled: &off, Present: map[string]bool{"enabled": true}})
			e.must(err)
		},
	} {
		var e *env
		e = newEnv(t, func(c *response.Config) {
			c.Executor = &afterExec{inner: c.Executor, after: func(s response.DeviceStep) {
				if s.Phase == "precheck" {
					act(e)
				}
			}}
		})
		e.sshSwitch("cisco_port_shut")
		e.turnOn()
		e.rule("Shut the port", "honeypot", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(30)}}, nil)
		e.fire(e.trap("h1", "192.168.10.157"))
		e.exec.pre = staticAccess
		got := e.approveOnly()
		if e.phaseList() != "precheck" || got.Items[0].Status != response.ItemFailed { // not even the read before the run (D-356) goes out
			t.Errorf("%s: steps %s, item %+v", name, e.phaseList(), got.Items[0])
		}
	}
}

// H3 and D-88 (4): an undo is not blocked by the execution switch (the sweep removes a change at the end of its time with the switch off), but
// the emergency stop blocks it until an admin resumes.
func TestDevice_UndoIsBlockedByTheEmergencyStopNotByTheExecutionSwitch(t *testing.T) {
	e := banRequest(t)
	e.exec.present = "198.51.100.7"
	e.approveOnly()
	_, err := e.svc.SetExecution(e.ctx(), admin, false, "")
	e.must(err)
	e.clock.Advance(31 * time.Minute)
	steps := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	if e.only().Status != response.StatusRolledBack || e.exec.count() == steps {
		t.Fatalf("with the execution switch off the undo at the end of its time did not go out: %s", e.only().Status)
	}
	// The same with the emergency stop: nothing goes out, the item stays in force and the reason is in the result.
	e2 := banRequest(t)
	e2.exec.present = "198.51.100.7"
	e2.approveOnly()
	_, err = e2.svc.EmergencyStop(e2.ctx(), admin)
	e2.must(err)
	e2.clock.Advance(31 * time.Minute)
	steps = e2.exec.count()
	e2.must(e2.svc.Sweep(e2.ctx()))
	if e2.exec.count() != steps || e2.only().Items[0].Status != response.ItemExecuted || !strings.Contains(resultOf(e2.only().Items[0]), "emergency stop") {
		t.Fatalf("an undo went out during the emergency stop (%d new steps): %+v", e2.exec.count()-steps, e2.only().Items[0])
	}
	if _, err := e2.svc.ResetBreaker(e2.ctx(), admin); err != nil {
		t.Fatal(err)
	}
	e2.must(e2.svc.Sweep(e2.ctx()))
	if e2.only().Status != response.StatusRolledBack {
		t.Fatalf("after the admin resumed: %s", e2.only().Status)
	}
}

// M2(a): a rotated token (a new version of the connection) does not strand the undo; another address does. The result never says "Nothing was changed".
func TestDevice_UndoSurvivesAnEditedConnectionButNotAnotherAddress(t *testing.T) {
	e := banRequest(t)
	e.exec.present = "198.51.100.7"
	e.approveOnly()
	e.conns.list[0].UpdatedAt = "2026-11-09T09:59:00.000Z" // the token was rotated, a pin renewed: another fingerprint
	e.conns.list[0].WriteTools = []string{}                // and the write tool was switched off
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	if e.only().Status != response.StatusRolledBack {
		t.Fatalf("the undo was stranded by an edited connection: %+v", e.only().Items[0])
	}
	last := e.exec.steps[len(e.exec.steps)-2]
	if last.Phase != "rollback" || !last.ByIdentity || last.ConnIdentity == "" {
		t.Fatalf("the rollback step %+v is not held to the identity of the connection", last)
	}
	if !e.logHas("rolled_back", "write tool of the connection is off") && !e.logHas("ttl_removed", "write tool of the connection is off") {
		t.Error("an undo sent with the write tool off is not logged")
	}
	// Another address: not the device the change was made on.
	e2 := banRequest(t)
	e2.exec.present = "198.51.100.7"
	e2.approveOnly()
	e2.conns.list[0].Target = "https://other-fw.lan"
	e2.clock.Advance(31 * time.Minute)
	steps := e2.exec.count()
	e2.must(e2.svc.Sweep(e2.ctx()))
	it := e2.only().Items[0]
	if e2.exec.count() != steps || it.Status != response.ItemExecuted || strings.Contains(resultOf(it), "Nothing was changed") || !strings.Contains(resultOf(it), "not the device") {
		t.Fatalf("undo on another address: %+v", it)
	}
}

// M2(b): an unclear outcome is read back by the sweep. The text is there: in force, with its undo time. Another text: not in force.
func TestDevice_SweepSettlesAStateUnknownItemByReadingTheDevice(t *testing.T) {
	for name, tc := range map[string]struct {
		output  string
		want    response.ItemStatus
		inForce bool
	}{
		"present": {"198.51.100.7", response.ItemExecuted, true},
		"absent":  {"nothing listed", response.ItemFailed, false},
		"silent":  {" ", response.ItemFailed, true},
	} {
		e := banRequest(t)
		e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
		e.exec.present = " " // the read-back at once cannot tell
		got := e.approveOnly()
		if !got.Items[0].StateUnknown || got.Items[0].Status != response.ItemFailed {
			t.Fatalf("%s: item %+v", name, got.Items[0])
		}
		e.exec.present = tc.output
		e.must(e.svc.Sweep(e.ctx()))
		it := e.only().Items[0]
		in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw")
		e.must(err)
		if it.Status != tc.want || in != tc.inForce || (tc.want == response.ItemExecuted && it.RemoveAt == nil) || (tc.output != " " && it.StateUnknown) {
			t.Errorf("%s: item %s %q state_unknown %v remove_at %v, in force %v", name, it.Status, resultOf(it), it.StateUnknown, it.RemoveAt, in)
		}
		if tc.want == response.ItemExecuted && e.only().Status != response.StatusExecuted {
			t.Errorf("%s: the request is %s", name, e.only().Status)
		}
	}
}

// M2(b): a person can undo an item whose state is unknown: the rollback is sent and the read-back must no longer hold the text.
func TestDevice_StateUnknownItemCanBeUndone(t *testing.T) {
	e := banRequest(t)
	e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
	e.exec.present = " "
	got := e.approveOnly()
	e.exec.status = nil
	e.exec.after = "nothing listed"
	rb, err := e.svc.Rollback(e.ctx(), oper, got.ID)
	e.must(err)
	it := rb.Items[0]
	if it.Status != response.ItemRolledBack || it.StateUnknown || !strings.Contains(resultOf(it), "earlier outcome was not known") || rb.Status != response.StatusRolledBack {
		t.Fatalf("item %s %q state_unknown %v, request %s", it.Status, resultOf(it), it.StateUnknown, rb.Status)
	}
	if in, _ := e.svc.ChangesInForce(e.ctx(), "cn-fw"); in {
		t.Fatal("an undone item is still counted as in force")
	}
}

// L6: an action whose address is outside the allow-list of its connection could never be sent: it is not available, with the reason, when the
// request is made.
func TestDevice_AddressOutsideTheAllowListIsNotAvailable(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.conns.list[0].Allow = []string{"https://fw.lan/api/v2/cmdb/"} // the ban API lives under /monitor/
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	if len(e.actions()) != 0 || sum.Refused != 1 || !e.logHas("refused", "outside the allow-list") {
		t.Fatalf("a request that could never be sent was made: %+v %+v", e.actions(), sum)
	}
	e.conns.list[0].Allow = []string{"https://fw.lan/api/"}
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	if len(e.actions()) != 1 {
		t.Fatal("an address inside the allow-list was refused")
	}
}
