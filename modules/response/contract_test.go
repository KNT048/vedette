package response_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/response"
)

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "response", response.Migrations, "resp_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// The roles of the routes are the contract (INV-3, INV-5, INV-7, INV-8, INV-12, INV-17, FORBID-4).
func TestContract_Roles(t *testing.T) {
	t.Parallel()
	want := map[string]routes.Role{
		"response_post_response_actions_id_approve": routes.Operator, "response_post_response_actions_id_reject": routes.Operator, "response_post_response_actions_id_rollback": routes.Operator,
		"response_post_response_proposals_id_request": routes.Operator, "response_get_response_settings": routes.Admin, "response_put_response_settings": routes.Admin,
		"response_post_response_execution": routes.Admin, "response_post_response_emergency_stop": routes.Operator, "response_post_response_breaker_reset": routes.Admin,
		"response_post_response_rules": routes.Admin, "response_put_response_rules_id": routes.Admin, "response_delete_response_rules_id": routes.Admin,
		"response_post_response_rules_simulate": routes.Operator, "response_post_response_rules_id_manual": routes.Operator, "response_post_response_templates_id_clone": routes.Admin,
		"response_put_response_allowlist": routes.Admin, "response_get_response_blocklist": routes.Admin, "response_post_response_blocklist_token": routes.Admin,
		"response_get_response_blocklist_token_txt": routes.Public, "response_post_response_catalog": routes.Admin, "response_get_response_log": routes.Operator,
		"response_get_response_actions": routes.Viewer,
	}
	for id, role := range want {
		op, ok := routes.Operations[id]
		if !ok || op.MinRole != role {
			t.Errorf("%s: %+v, want role %s", id, op, role)
		}
	}
}

// INV-7: the switch is off by default; turning it on needs an admin with two-step sign-in and the exact phrase; PUT /settings never flips it.
func TestContract_INV7_ExecutionSwitch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if e.settings().Execution || e.settings().AcceptedBy != nil {
		t.Fatalf("the switch starts on: %+v", e.settings())
	}
	nofa := response.Actor{ID: "u-nofa", Email: "nofa@acme.example", Via: response.ViaApp}
	_, err := e.svc.SetExecution(e.ctx(), nofa, true, riskPhrase)
	wantCode(t, err, 409, "twofa_required")
	_, err = e.svc.SetExecution(e.ctx(), oper, true, riskPhrase)
	wantCode(t, err, 403, "forbidden")
	for _, bad := range []string{"", "i accept the risk", "I ACCEPT THE RISK ", "I ACCEPT"} {
		_, err = e.svc.SetExecution(e.ctx(), admin, true, bad)
		wantCode(t, err, 400, "phrase_mismatch")
	}
	if e.settings().Execution {
		t.Fatal("a refused request turned the switch on")
	}
	if !e.logHas("refused", "twofa_required") || !e.logHas("refused", "phrase_mismatch") {
		t.Fatal("the refusals are not in the response log")
	}
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 7 })
	if e.settings().Execution {
		t.Fatal("PUT /settings turned the switch on")
	}
	v, err := e.svc.SetExecution(e.ctx(), admin, true, riskPhrase)
	e.must(err)
	if !v.Execution || v.AcceptedBy == nil || *v.AcceptedBy != admin.Email || v.AcceptedAt == nil {
		t.Fatalf("settings = %+v", v.Settings)
	}
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 8 })
	if s := e.settings(); !s.Execution || s.MaxPerHour != 8 || s.AcceptedBy == nil {
		t.Fatalf("PUT /settings changed the switch or its record: %+v", s)
	}
	v, err = e.svc.SetExecution(e.ctx(), admin, false, "")
	e.must(err)
	if v.Execution {
		t.Fatal("the switch is still on")
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action IN ('response.execution.enable', 'response.execution.disable')`) != 2 {
		t.Fatal("the switch changes are not audited")
	}
}

// INV-8: the emergency stop turns execution off and cancels every pending request in one transaction, and returns the count.
func TestContract_INV8_EmergencyStop(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.rule("Block bad destinations", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	if n := e.count(`SELECT COUNT(*) FROM resp_actions WHERE status = 'pending'`); n != 2 {
		t.Fatalf("%d pending requests, want 2", n)
	}
	n, err := e.svc.EmergencyStop(e.ctx(), oper)
	e.must(err)
	if n != 2 || e.settings().Execution {
		t.Fatalf("cancelled %d, execution %v", n, e.settings().Execution)
	}
	for _, a := range e.actions() {
		if a.Status != response.StatusRejected || a.Note == nil || !contains(*a.Note, "emergency stop") || a.Items[0].Status != response.ItemSkipped {
			t.Fatalf("request after the stop: %+v", a)
		}
	}
	if !e.logHas("emergency_stop", "2 pending requests cancelled") || e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.emergency_stop'`) != 1 {
		t.Fatal("the stop is not logged and audited")
	}
	if got, err := e.svc.EmergencyStop(e.ctx(), oper); err != nil || got != 0 {
		t.Fatalf("a second stop = %d, %v", got, err)
	}
}

// INV-12: a per-rule limit, and a global breaker that pauses every rule until an admin resets it.
func TestContract_INV12_RuleLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("One an hour", "ioc_connection", blockAction(60), func(in *response.RuleInput) { in.MaxPerHour = 1 })
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	sum := e.fire(e.iocEvent("e2", "198.51.100.8"))
	if sum.Refused != 1 || len(e.actions()) != 1 || !e.logHas("refused", "rule_rate_limited") {
		t.Fatalf("summary %+v, %d requests", sum, len(e.actions()))
	}
	e.clock.Advance(61 * time.Minute)
	e.fire(e.iocEvent("e3", "198.51.100.9"))
	if len(e.actions()) != 2 {
		t.Fatal("the rule did not run again after an hour")
	}
}

func TestContract_INV12_Breaker(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.saveSettings(func(in *response.SettingsInput) { in.BreakerMaxPerHour = 2 })
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	e.fire(e.iocEvent("e3", "198.51.100.9")) // the third action passes the limit: the breaker trips
	s := e.settings()
	if s.BreakerTrippedAt == nil || len(e.actions()) != 2 || len(s.BreakerNotified) == 0 {
		t.Fatalf("breaker %+v, %d requests", s, len(e.actions()))
	}
	if !e.logHas("breaker", "Circuit breaker tripped") || e.seen.count(response.EventBreakerTripped) != 1 || len(e.note.msgs) == 0 {
		t.Fatal("the breaker is not logged, published and notified")
	}
	sum := e.fire(e.iocEvent("e4", "198.51.100.10"))
	if sum.Refused != 1 || len(e.actions()) != 2 || !e.logHas("refused", "circuit_open") {
		t.Fatalf("a rule ran while the breaker is open: %+v", sum)
	}
	// Approving an open request is also stopped (INV-9, FORBID-7: nothing runs while the breaker is open).
	a := e.actions()[0]
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("an item ran while the breaker is open: %+v", got.Items[0])
	}
	_, err = e.svc.ResetBreaker(e.ctx(), admin)
	e.must(err)
	if e.settings().BreakerTrippedAt != nil {
		t.Fatal("the breaker is still open")
	}
	e.clock.Advance(61 * time.Minute)
	if sum := e.fire(e.iocEvent("e5", "198.51.100.11")); sum.Requests != 1 {
		t.Fatalf("after the reset: %+v", sum)
	}
}

// INV-1, INV-6: a request is pending until someone approves; after its time it expires, nothing changes and approving is refused.
func TestContract_INV1_INV6_ExpiryAndNotPending(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if a.Status != response.StatusPending || a.RequiresApprovals != 1 || a.PreApproved || len(a.Approvals) != 0 || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("a rule request must wait for a person: %+v", a)
	}
	exp, _ := time.Parse(time.RFC3339, a.ExpiresAt)
	if d := exp.Sub(e.clock.Now()); d != 15*time.Minute {
		t.Fatalf("expires in %v, want the default 15 minutes", d)
	}
	e.clock.Advance(16 * time.Minute)
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 409, "expired")
	got := e.only()
	if got.Status != response.StatusExpired || got.Items[0].Status != response.ItemSkipped || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("after expiry: %+v", got)
	}
	if !e.logHas("expired", "nothing was changed") || len(e.note.msgs) == 0 {
		t.Fatal("expiry is not logged or notified")
	}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 409, "expired")
	// Another request: approved once, a second approval is refused.
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	var open string
	for _, x := range e.actions() {
		if x.Status == response.StatusPending {
			open = x.ID
		}
	}
	_, err = e.svc.Approve(e.ctx(), oper, open, nil, "")
	e.must(err)
	_, err = e.svc.Approve(e.ctx(), oper2, open, nil, "")
	wantCode(t, err, 409, "not_pending")
	_, err = e.svc.Reject(e.ctx(), oper, open, "late", "")
	wantCode(t, err, 409, "not_pending")
	_, err = e.svc.Approve(e.ctx(), oper, "no-such-request", nil, "")
	wantCode(t, err, 404, "not_found")
}

func TestExpirySettingsRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, bad := range []int{14, 31, 0} {
		st := e.settings()
		in := response.SettingsInput{MaxPerHour: 3, ExpiryMin: bad, ApprovalChannels: []string{}, BreakerMaxPerHour: st.BreakerMaxPerHour, MultiTargetMax: 5, Maintenance: []response.Window{}}
		in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = []string{}, 2, 5
		_, err := e.svc.SaveSettings(e.ctx(), admin, in)
		wantCode(t, err, 400, "invalid")
	}
	e.saveSettings(func(in *response.SettingsInput) { in.ExpiryMin = 30 })
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	exp, _ := time.Parse(time.RFC3339, e.only().ExpiresAt)
	if exp.Sub(e.clock.Now()) != 30*time.Minute {
		t.Fatalf("expiry = %v", exp.Sub(e.clock.Now()))
	}
}

// INV-1, POST-1: approving a box action runs it without the execution switch; the block list gets the entry; the result is read back.
func TestApproveBoxActionRunsWithoutTheSwitch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	it := got.Items[0]
	if got.Status != response.StatusExecuted || it.Status != response.ItemExecuted || it.Verified == nil || !it.Verified.OK || it.RemoveAt == nil || it.ExecutedAt == nil {
		t.Fatalf("after approval: %+v", got)
	}
	if len(got.Approvals) != 1 || got.Approvals[0].Email != oper.Email || got.Approvals[0].Via != response.ViaApp {
		t.Fatalf("approvals: %+v", got.Approvals)
	}
	if e.exec.count() != 0 || e.count(`SELECT COUNT(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Fatal("a box action went to the executor or missed the block list")
	}
	if e.seen.count(response.EventRequestCreated) != 1 || e.seen.count(response.EventDecisionMade) != 1 || e.seen.count(response.EventActionExecuted) != 1 {
		t.Fatalf("events: %v", e.seen.names)
	}
	if !e.logHas("approved", oper.Email) || !e.logHas("executed", "blocklist add 198.51.100.7") {
		t.Fatal("approval and execution are not in the log")
	}
}

// INV-2, INV-9: a high-risk request needs two different approvers; the second must approve the same actions; the same person twice is refused.
func TestContract_INV2_TwoApprovers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_policy_disable")
	e.turnOn()
	e.rule("Cut the policy", "honeypot", []response.RuleAction{
		{ActionID: "fgt_policy_disable", Params: map[string]string{"id": "12"}, TTLMin: intp(60)},
		{ActionID: "msg_send", Params: map[string]string{"text": "Trap touched on {{trigger.source_device}}"}},
	}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	if a.Risk != response.RiskHigh || a.RequiresApprovals != 2 || a.TwoBecause == nil || len(a.Items) != 2 {
		t.Fatalf("request: %+v", a)
	}
	dev, msg := a.Items[0].ID, a.Items[1].ID
	first, err := e.svc.Approve(e.ctx(), oper, a.ID, []string{dev}, "")
	e.must(err)
	if first.Status != response.StatusPending || len(first.Approvals) != 1 || e.exec.count() != 0 {
		t.Fatalf("after the first approval: %+v, %d steps", first, e.exec.count())
	}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 409, "same_approver")
	_, err = e.svc.Approve(e.ctx(), oper2, a.ID, []string{dev, msg}, "")
	wantCode(t, err, 409, "selection_differs")
	if e.exec.count() != 0 {
		t.Fatal("a refused approval reached the device")
	}
	done, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, "") // no pick: the same actions as the first
	e.must(err)
	if done.Status != response.StatusExecuted || done.Items[0].Status != response.ItemExecuted || done.Items[1].Status != response.ItemSkipped || len(done.Approvals) != 2 {
		t.Fatalf("after the second approval: %+v", done)
	}
	if got := e.exec.phases(); strings.Join(got, ",") != "precheck,run,verify" {
		t.Fatalf("executor steps = %v", got)
	}
	st := e.exec.steps[1]
	if st.ConnectionID != "cn-fw" || st.Method != "PUT" || st.URL != "https://fw.lan/api/v2/cmdb/firewall/policy/12" || len(st.Lines) != 0 || st.Body != `{"status":"disable"}` {
		t.Fatalf("the step is not the stored template rendered: %+v", st)
	}
	if pre := e.exec.steps[0]; pre.Method != "GET" || pre.URL != "https://fw.lan/api/v2/cmdb/firewall/policy/12" || pre.Body != "" {
		t.Fatalf("the check before: %+v", pre)
	}
}

func TestContract_INV2_MultiTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	e.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if a.RequiresApprovals != 2 || a.TwoBecause == nil || !contains(*a.TwoBecause, "more than the limit of 1") {
		t.Fatalf("request: %+v", a)
	}
}

// INV-7, INV-9: a device action is refused at approval while execution is off; the hourly limit counts approved device actions.
func TestContract_INV9_DeviceGates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	e.fire(e.trap("h2", "192.168.10.158"))
	l := e.actions()
	_, err := e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 409, "execution_off")
	if e.exec.count() != 0 || !e.logHas("refused", "execution_off") {
		t.Fatal("the refusal reached a device or is not logged")
	}
	e.turnOn()
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 1 })
	got, err := e.svc.Approve(e.ctx(), oper, l[1].ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemExecuted {
		t.Fatalf("item: %+v", got.Items[0])
	}
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 429, "rate_limited")
	// The catalog entry switched off between request and approval: 403 tool_not_allowed.
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 20 })
	off := false
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{Enabled: &off, Present: map[string]bool{"enabled": true}})
	e.must(err)
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 403, "tool_not_allowed")
	// A connection that is gone: 409 tool_unavailable.
	on := true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{Enabled: &on, Present: map[string]bool{"enabled": true}})
	e.must(err)
	e.conns.list = nil
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 409, "tool_unavailable")
}

// INV-9: the gates run again right before an item runs. The second approver approves after the address was put on the never-touch list.
func TestContract_INV9_GatesAgainRightBeforeRunning(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	e.rule("Two blocks", "ioc_connection", twoBlocks(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	_, err = e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "198.51.100.0/24", Label: "Declared service"}})
	e.must(err)
	got, err := e.svc.Approve(e.ctx(), oper2, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || got.Items[1].Status != response.ItemExecuted || got.Status != response.StatusExecuted {
		t.Fatalf("items: %+v / %+v, status %s", got.Items[0], got.Items[1], got.Status)
	}
	if !contains(*got.Items[0].Result, "never-touch") || !e.logHas("refused", "never_touch") {
		t.Fatalf("result %v", got.Items[0].Result)
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 0 {
		t.Fatal("a never-touch address reached the block list")
	}
}

// INV-10: never-touch at planning: a listed address, a range that holds it, the box itself, a domain and its subdomains.
func TestContract_INV10_NeverTouchAtPlanning(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *response.Config) {
		c.BoxAddrs = func() ([]netipAddr, error) { return []netipAddr{mustAddr("203.0.113.250")}, nil }
	})
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "1.1.1.1", Label: "Public DNS"}, {Value: "192.168.99.0/24", Label: "Management"}, {Value: "Mail.Acme.Example", Label: "Mail"}})
	e.must(err)
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	if !hasEntry(l, "203.0.113.250") || !hasEntry(l, "mail.acme.example") {
		t.Fatalf("the list = %+v: the box address must always be there and entries are lower case", l)
	}
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	for i, c := range []string{"1.1.1.1", "192.168.99.7", "203.0.113.250"} {
		e.fire(e.iocEvent("n"+string(rune('a'+i)), c))
	}
	if len(e.actions()) != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'never_touch:%'`) != 3 {
		t.Fatalf("%d requests; never-touch refusals: %d", len(e.actions()), e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`))
	}
	e.fire(e.iocEvent("ok", "198.51.100.7"))
	if len(e.actions()) != 1 {
		t.Fatal("a normal address was refused")
	}
}

// INV-14d: a new rule starts in dry run whatever the client sends; a match is logged and nothing is requested or run;
// simulate renders the exact requests and executes nothing.
func TestContract_INV14d_DryRunAndSimulate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, err := e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Block", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: blockAction(60), MaxPerHour: 5})
	e.must(err)
	if r.Live || !r.Enabled {
		t.Fatalf("a new rule must be in dry run: %+v", r)
	}
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	if sum.DryRun != 1 || sum.Requests != 0 || len(e.actions()) != 0 || !e.logHas("dry_run", "Would do") || e.exec.count() != 0 {
		t.Fatalf("summary %+v", sum)
	}
	sim, err := e.svc.Simulate(e.ctx(), oper, response.RuleInput{Name: "Block", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: blockAction(60), MaxPerHour: 5}, "")
	e.must(err)
	if sim.Executed != 0 || !sim.Matched || sim.Event == nil || sim.Event.ID != "e1" || len(sim.Steps) != 1 || !sim.Steps[0].OK || sim.Steps[0].Change == nil || sim.Steps[0].Change.CLI != "blocklist add 198.51.100.7" {
		t.Fatalf("simulation: %+v", sim)
	}
	if len(e.actions()) != 0 || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 || !e.logHas("simulated", "Nothing was executed") {
		t.Fatal("a simulation left a request or an entry, or is not logged")
	}
	// A trigger without an event uses the example values and says so.
	sim, err = e.svc.Simulate(e.ctx(), oper, response.RuleInput{Name: "Trap", Enabled: true, Trigger: "honeypot", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 5,
		Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}}, "")
	e.must(err)
	if len(sim.Notes) == 0 || !contains(sim.Notes[0], "No event of this trigger yet") || sim.Executed != 0 {
		t.Fatalf("notes %v", sim.Notes)
	}
}

// Even a simulation of a device action sends nothing to the executor.
func TestSimulateDeviceActionExecutesNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	sim, err := e.svc.Simulate(e.ctx(), oper, response.RuleInput{Name: "Ban", Enabled: true, Live: true, Trigger: "honeypot", Match: "all", Conditions: []response.Condition{}, MaxPerHour: 5,
		Actions: []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}}, "")
	e.must(err)
	if sim.Executed != 0 || e.exec.count() != 0 || len(sim.Steps) != 1 || !sim.Steps[0].OK || sim.Steps[0].Change.Rest == nil || sim.Steps[0].Change.Rest.Method != "POST" {
		t.Fatalf("simulation: %+v, %d steps", sim, e.exec.count())
	}
}

// Attacker-controlled trigger data: refused at run time and nothing is requested.
func TestContract_INV14a_TriggerDataIsTypeChecked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	bads := []string{"198.51.100.7; reboot", "198.51.100.7\nblocklist add 8.8.8.8", "$(id)", "198.51.100.7 && x", "127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "fe80::1%eth0", ""}
	for i, bad := range bads {
		e.fire(e.iocEvent("bad"+string(rune('a'+i)), bad))
	}
	if len(e.actions()) != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`) != len(bads) {
		t.Fatalf("%d requests, %d refusals", len(e.actions()), e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`))
	}
	// IPv4-mapped IPv6 is the same address, written the same way.
	e.fire(e.iocEvent("mapped", "::ffff:198.51.100.7"))
	a := e.only()
	if a.Items[0].Change.CLI != "blocklist add 198.51.100.7" {
		t.Fatalf("cli = %q", a.Items[0].Change.CLI)
	}
}

// A rule is checked when saved: unknown fields, wrong types, a mix of text and a trigger field in a typed parameter.
func TestRuleIsCheckedWhenSaved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	base := func() response.RuleInput {
		return response.RuleInput{Name: "R", Enabled: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: blockAction(60), MaxPerHour: 5}
	}
	one := blockAction(60)[0]
	bad := map[string]func(in *response.RuleInput){
		"name":       func(in *response.RuleInput) { in.Name = "bad; name" },
		"trigger":    func(in *response.RuleInput) { in.Trigger = "nope" },
		"no actions": func(in *response.RuleInput) { in.Actions = nil },
		"7 actions":  func(in *response.RuleInput) { in.Actions = []response.RuleAction{one, one, one, one, one, one, one} },
		"11 conds":   func(in *response.RuleInput) { in.Conditions = make([]response.Condition, 11) },
		"unknown field": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "nope", Op: "eq", Value: "x"}}
		},
		"unknown op": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "dest_kind", Op: "regex", Value: "x"}}
		},
		"wrong type": func(in *response.RuleInput) {
			in.Actions = []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.device}}"}}}
		},
		"unknown ref": func(in *response.RuleInput) {
			in.Actions = []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.nope}}"}}}
		},
		"mixed": func(in *response.RuleInput) {
			in.Actions = []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "x{{trigger.dest_ip}}"}}}
		},
		"bad fixed": func(in *response.RuleInput) {
			in.Actions = []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "1.2.3.4; id"}}}
		},
		"ttl": func(in *response.RuleInput) {
			in.Actions = []response.RuleAction{{ActionID: one.ActionID, Params: one.Params, TTLMin: intp(2)}}
		},
		"max":      func(in *response.RuleInput) { in.MaxPerHour = 101 },
		"schedule": func(in *response.RuleInput) { in.ScheduleMin = intp(60) },
		"cidr": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "dest_ip", Op: "in_cidr", Value: "10.0.0.0"}}
		},
		"count": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "dest_ip", Op: "count_window", Value: "", N: intp(0)}}
		},
		// D-390: a value outside the field's range or choices would match every event (-3) or none (7)
		"confidence 7": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "confidence", Op: "gte", Value: "7"}}
		},
		"confidence -3": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "confidence", Op: "lte", Value: "-3"}}
		},
		"confidence NaN": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "confidence", Op: "gte", Value: "NaN"}}
		},
		"confidence in 2": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "confidence", Op: "in", Value: "0.5, 2"}}
		},
		"at least on text": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "device", Op: "gte", Value: "3"}}
		},
		"choice": func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Field: "dest_kind", Op: "eq", Value: "ipv4"}}
		},
	}
	for name, mod := range bad {
		in := base()
		mod(&in)
		_, err := e.svc.AddRule(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v (%d %s), want 400 invalid", name, err, s, c)
		}
	}
	if len(mustRules(e)) != 0 {
		t.Fatal("a refused rule was saved")
	}
	ok := base() // the ends of the range and a choice in another case are accepted
	ok.Conditions = []response.Condition{{Field: "confidence", Op: "gte", Value: "0"}, {Field: "confidence", Op: "lte", Value: "1"}, {Field: "dest_kind", Op: "in", Value: "IP, domain"}}
	if _, err := e.svc.AddRule(e.ctx(), admin, ok); err != nil {
		t.Fatal(err)
	}
	// The schedule trigger needs an interval of 15 minutes to 7 days.
	in := base()
	in.Trigger, in.Actions = "schedule", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "Weekly digest"}}}
	_, err := e.svc.AddRule(e.ctx(), admin, in)
	wantCode(t, err, 400, "invalid")
	in.ScheduleMin = intp(10080)
	if _, err := e.svc.AddRule(e.ctx(), admin, in); err != nil {
		t.Fatal(err)
	}
}

// INV-5: pre-approved only for low-risk, reversible actions with an undo time of 24 hours or less; checked on save and when the rule runs.
func TestContract_INV5_PreApproved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	mk := func(actions []response.RuleAction) error {
		_, err := e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Pre", Enabled: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: actions, PreApproved: true, MaxPerHour: 5})
		return err
	}
	wantCode(t, mk([]response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}), 400, "invalid") // medium risk
	wantCode(t, mk(blockAction(1441)), 400, "invalid")                                                                                                         // more than 24 hours
	wantCode(t, mk([]response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}}}), 400, "invalid")                // no undo time
	wantCode(t, mk([]response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "hello"}, TTLMin: intp(60)}}), 400, "invalid")               // cannot be undone
	e.must(mk(blockAction(1440)))
	// The rule runs live and pre-approved: no person, via auto, and the entry is on the list.
	rules := mustRules(e)
	in := response.RuleInput{Name: "Pre", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: blockAction(1440), PreApproved: true, MaxPerHour: 5}
	_, err := e.svc.ChangeRule(e.ctx(), admin, rules[0].ID, in)
	e.must(err)
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if sum.Executed != 1 || a.Status != response.StatusExecuted || !a.PreApproved || len(a.Approvals) != 1 || a.Approvals[0].Via != response.ViaAuto || !strings.HasPrefix(a.Approvals[0].UserID, "rule:") {
		t.Fatalf("summary %+v, request %+v", sum, a)
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries WHERE value = '198.51.100.7'`) != 1 {
		t.Fatal("the pre-approved block is not on the list")
	}
	// Tampered rule (an undo time over 24 hours written behind the API): checked again when it runs, so it asks a person.
	e.exec1(`UPDATE resp_rules SET actions = ?`, `[{"action_id":"blocklist_add","params":{"ip":"{{trigger.dest_ip}}"},"ttl_min":3000}]`)
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	var pending int
	for _, x := range e.actions() {
		if x.Status == response.StatusPending && !x.PreApproved {
			pending++
		}
	}
	if pending != 1 || e.count(`SELECT COUNT(*) FROM resp_block_entries WHERE value = '198.51.100.8'`) != 0 {
		t.Fatal("a rule that no longer qualifies must ask a person")
	}
}

// INV-11: the same target and action already open or in force is merged; one run is one request.
func TestContract_INV11_Dedupe(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", append(blockAction(60), blockAction(60)...), nil)
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if sum.Requests != 1 || len(a.Items) != 1 {
		t.Fatalf("two identical actions in one run must merge: %+v, %d items", sum, len(a.Items))
	}
	sum = e.fire(e.iocEvent("e2", "198.51.100.7"))
	if sum.Deduped != 1 || sum.Requests != 0 || len(e.actions()) != 1 || !e.logHas("deduped", "already open or in force") {
		t.Fatalf("summary %+v", sum)
	}
	// In force (executed and not yet undone) counts too.
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if sum = e.fire(e.iocEvent("e3", "198.51.100.7")); sum.Deduped != 1 || len(e.actions()) != 1 {
		t.Fatalf("an address already on the list was asked again: %+v", sum)
	}
}

// INV-13: rollback undoes the change (a device action is refused when execution is off), the undo time undoes it by itself, and it is verified.
func TestContract_INV13_RollbackAndTTL(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(30), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	_, err := e.svc.Rollback(e.ctx(), oper, a.ID)
	wantCode(t, err, 409, "not_executed")
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	got := e.only()
	if got.Status != response.StatusRolledBack || got.Items[0].Status != response.ItemRolledBack || got.Items[0].RolledBackAt == nil ||
		e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 || !e.logHas("ttl_removed", "undo time of 30 minutes ended") {
		t.Fatalf("after the undo time: %+v", got)
	}
	// Manual rollback of a box action.
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	var id string
	for _, x := range e.actions() {
		if x.Status == response.StatusPending {
			id = x.ID
		}
	}
	_, err = e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	rb, err := e.svc.Rollback(e.ctx(), oper, id)
	e.must(err)
	if rb.Status != response.StatusRolledBack || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 || !e.logHas("rolled_back", "Undo") || e.seen.count(response.EventActionRolledBack) != 2 {
		t.Fatalf("rollback: %+v", rb)
	}
}

func TestContract_INV13_DeviceRollbackNeedsExecution(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	a := e.only()
	e.exec.present = `{"results":["192.168.10.157"]}`
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Verified == nil || !got.Items[0].Verified.OK {
		t.Fatalf("not read back: %+v", got.Items[0])
	}
	_, err = e.svc.SetExecution(e.ctx(), admin, false, "")
	e.must(err)
	_, err = e.svc.Rollback(e.ctx(), oper, a.ID)
	wantCode(t, err, 409, "execution_off")
	if got := e.exec.phases(); strings.Join(got, ",") != "verify,run,verify" { // the read before the run (D-356), the run, the read-back
		t.Fatalf("steps = %v", got)
	}
	// Removing the change at the end of its undo time is the safe direction: it does not wait for the switch.
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	if got := e.exec.phases(); strings.Join(got, ",") != "verify,run,verify,rollback,verify" || e.only().Status != response.StatusRolledBack {
		t.Fatalf("steps = %v, request %+v", got, e.only())
	}
}

// A device that does not answer: the item fails and nothing is claimed.
func TestDeviceThatDoesNotAnswerFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.exec.err = sql.ErrConnDone
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Status != response.StatusFailed || got.Items[0].Status != response.ItemFailed || !contains(*got.Items[0].Result, "Nothing was changed") || !e.logHas("failed", "did not answer") {
		t.Fatalf("%+v", got)
	}
}

// With no executor in the build nothing is sent to any device.
func TestNoExecutorSendsNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *response.Config) { c.Executor = nil })
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "honeypot", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || !contains(*got.Items[0].Result, "No device executor") {
		t.Fatalf("%+v", got.Items[0])
	}
}

// INV-19: the log is a hash chain with the shared formula, oldest first; there is no way to update or delete a line.
func TestContract_INV19_LogChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	_, _ = e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "") // refused: logged too
	l, err := e.svc.Log(e.ctx())
	e.must(err)
	if len(l) < 6 || l[0].PrevHash != chain.Genesis {
		t.Fatalf("%d lines, first prev_hash %q", len(l), l[0].PrevHash)
	}
	prev := chain.Genesis
	for i, x := range l {
		h, err := chain.HashCanonical(prev, map[string]any{"id": x.ID, "ts": x.TS, "kind": x.Kind, "actor": x.Actor, "detail": x.Detail})
		if err != nil || h != x.Hash || x.PrevHash != prev {
			t.Fatalf("line %d does not follow the shared formula", i)
		}
		prev = x.Hash
	}
	for _, k := range []string{"settings", "rule_fired", "request", "approved", "executed", "refused"} {
		if !hasKind(l, k) {
			t.Errorf("no %q line", k)
		}
	}
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK || r.Count != len(l) {
		t.Fatalf("verify = %+v, %v", r, err)
	}
	// No update, no delete, no replace (INSERT OR REPLACE deletes the old row without the delete trigger): the database refuses.
	for _, q := range []string{`UPDATE resp_log SET detail = 'x'`, `DELETE FROM resp_log`,
		`INSERT OR REPLACE INTO resp_log (seq, id, ts, kind, actor, detail, prev_hash, hash) SELECT seq, id, ts, kind, actor, 'rewritten', prev_hash, hash FROM resp_log WHERE seq = 1`,
		`INSERT OR REPLACE INTO resp_log (id, ts, kind, actor, detail, prev_hash, hash) SELECT id, ts, kind, actor, 'rewritten', prev_hash, hash FROM resp_log WHERE seq = 1`} {
		if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), q); return err }); err == nil {
			t.Fatalf("%s was accepted", q)
		}
	}
	// A line changed by someone who removes the guard is caught.
	e.exec1(`DROP TRIGGER resp_log_no_update`)
	e.exec1(`UPDATE resp_log SET detail = 'tampered' WHERE seq = 2`)
	if r, _ := e.svc.VerifyLog(e.ctx()); r.OK || r.BrokenAt != 2 {
		t.Fatalf("a changed line verifies: %+v", r)
	}
}

// INV-20 and SYS-4: every mutation is audited; no secret reaches the log or the audit.
func TestContract_INV20_AuditAndNoSecrets(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.saveSettings(func(in *response.SettingsInput) { in.MaxPerHour = 5 })
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "10.0.0.1", Label: "Gateway"}})
	e.must(err)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	_, err = e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	bl, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	token := bl.URL[strings.LastIndex(bl.URL, "/")+1 : len(bl.URL)-len(".txt")]
	_, err = e.svc.RegenerateToken(e.ctx(), admin)
	e.must(err)
	for _, a := range []string{"response.execution.enable", "response.settings", "response.allowlist", "response.rule.add", "response.rule.change", "response.request", "response.approve", "response.execute", "response.blocklist.token"} {
		if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = ?`, a) == 0 {
			t.Errorf("no audit row for %s", a)
		}
	}
	for _, q := range []string{`SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%' || ? || '%' OR target LIKE '%' || ? || '%'`, `SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%' || ? || '%' OR actor LIKE '%' || ? || '%'`} {
		if e.count(q, token, token) != 0 {
			t.Fatalf("the block list token is in %s", q)
		}
	}
	// Every refusal is audited and logged with its reason.
	_, _ = e.svc.Approve(e.ctx(), oper, "nope", nil, "")
	if !e.logHas("refused", "not_found") || e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.refused'`) == 0 {
		t.Fatal("a refusal is not recorded")
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	for i, ipv := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		e.fire(e.iocEvent("m"+string(rune('a'+i)), ipv))
	}
	l := e.actions()
	_, err := e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	e.must(err)
	_, err = e.svc.Reject(e.ctx(), oper, l[1].ID, "Our scanner", "")
	e.must(err)
	e.clock.Advance(20 * time.Minute)
	m, err := e.svc.Metrics(e.ctx())
	e.must(err)
	if m.Rules.Sent != 4 || m.Rules.Approved != 1 || m.Rules.Rejected != 1 || m.Rules.Expired != 2 || m.Rules.AcceptanceRate == nil || *m.Rules.AcceptanceRate != 0.5 || m.AI.Sent != 0 {
		t.Fatalf("metrics: %+v", m.Rules)
	}
	if len(m.Rejected) != 1 || !contains(m.Rejected[0].Reason, "Our scanner") {
		t.Fatalf("rejected: %+v", m.Rejected)
	}
}

func TestSettingsValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	base := func() response.SettingsInput {
		st := e.settings()
		in := response.SettingsInput{MaxPerHour: 3, ExpiryMin: 15, ApprovalChannels: []string{}, BreakerMaxPerHour: 20, MultiTargetMax: 5, Maintenance: []response.Window{}}
		in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, 2, 5
		return in
	}
	w := func(name, start, end string) []response.Window {
		return []response.Window{{ID: "w", Name: name, Start: start, End: end}}
	}
	cases := map[string]func(in *response.SettingsInput){
		"hour":    func(in *response.SettingsInput) { in.MaxPerHour = 21 },
		"breaker": func(in *response.SettingsInput) { in.BreakerMaxPerHour = 201 },
		"multi":   func(in *response.SettingsInput) { in.MultiTargetMax = 0 },
		"channel": func(in *response.SettingsInput) { in.ApprovalChannels = []string{"slack"} },
		"window order": func(in *response.SettingsInput) {
			in.Maintenance = w("Night", "2026-11-09T22:00:00Z", "2026-11-09T21:00:00Z")
		},
		"window name": func(in *response.SettingsInput) {
			in.Maintenance = w("bad;name", "2026-11-09T22:00:00Z", "2026-11-09T23:00:00Z")
		},
		"ai trigger":    func(in *response.SettingsInput) { in.AI.Triggers = []string{"nope"} },
		"ai budget":     func(in *response.SettingsInput) { in.AI.BudgetHour, in.AI.BudgetDay = 5, 3 },
		"ai budget day": func(in *response.SettingsInput) { in.AI.BudgetDay = 101 },
	}
	for name, f := range cases {
		in := base()
		f(&in)
		_, err := e.svc.SaveSettings(e.ctx(), admin, in)
		if s, c := apiCode(err); s != 400 || c != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A maintenance window holds rules (INV-12).
	in := base()
	in.Maintenance = w("Night work", "2026-11-09T09:00:00Z", "2026-11-09T11:00:00Z")
	_, err := e.svc.SaveSettings(e.ctx(), admin, in)
	e.must(err)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	if sum.Refused != 1 || len(e.actions()) != 0 || !e.logHas("refused", "maintenance") {
		t.Fatalf("a rule ran in a maintenance window: %+v", sum)
	}
}

func TestChannelsInSettings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.note.chs = []response.NotifyChannel{
		{Type: "slack", Label: "Slack #sec", Configured: true, Enabled: true, Approvals: true, Approvers: 1},
		{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: false},
		{Type: "webhook", Label: "Webhook", Configured: true, Enabled: true},
	}
	v, err := e.svc.Settings(e.ctx())
	e.must(err)
	if len(v.Channels) != 2 || !v.Channels[0].Ready || v.Channels[0].Type != "slack" || v.Channels[1].Ready || !v.Channels[1].Link {
		t.Fatalf("channels: %+v", v.Channels)
	}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"slack"} })
	in := response.SettingsInput{MaxPerHour: 3, ExpiryMin: 15, ApprovalChannels: []string{"email"}, BreakerMaxPerHour: 20, MultiTargetMax: 5, Maintenance: []response.Window{}}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = []string{}, 2, 5
	_, err = e.svc.SaveSettings(e.ctx(), admin, in)
	wantCode(t, err, 400, "invalid")
}
