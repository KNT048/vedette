package response_test

// Permanent tests of the findings of the independent security review of WP-13a (D-88 amendment 2026-11-09). Each test names
// the invariant it proves; see modules/response/CONTRACT.md.

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/response"
)

// ---- helpers ----

// sshSwitch adds an SSH connection and binds a built-in CLI action to it.
func (e *env) sshSwitch(actionID string) {
	e.t.Helper()
	e.conns.list = append(e.conns.list, response.ConnectionInfo{Connection: response.Connection{ID: "cn-sw", Name: "Core switch", Enabled: true, Kind: "ssh", WriteTools: []string{"cli"}}, Target: "ssh://sw.lan"})
	cid, on := "cn-sw", true
	_, err := e.svc.ChangeAction(e.ctx(), admin, actionID, response.CatalogUpdate{ConnectionID: &cid, Enabled: &on, Present: map[string]bool{"connection_id": true, "enabled": true}})
	e.must(err)
}

// planEnv is an environment with a firewall bound to the "disable a virtual IP" action, execution on, and an open critical finding.
func planEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.firewall("fgt_vip_disable")
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a-nas", CVE: "CVE-2024-3400", Severity: "critical", Status: "confirmed"}
	e.dir.devices["a-nas"] = response.DeviceInfo{ID: "a-nas", Name: "NAS", IP: "192.168.10.21", Approved: true}
	e.turnOn()
	return e
}

// plan stores a plan with one proposal (the JSON of the proposal as the plan job would write it).
func (e *env) plan(planID, proposal string) {
	e.t.Helper()
	steps := `[{"kind":"contain","title":"Switch off the virtual IP","detail":"d","proposal":` + proposal + `}]`
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES (?,'f1','CVE-2024-3400','a-nas','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]',?)`, planID, steps)
}

func (e *env) requests() int { return e.count(`SELECT COUNT(*) FROM resp_actions`) }

// tamperItems rewrites the first item of a request behind the API, as a crash at a given moment leaves it.
func (e *env) tamperItems(reqID, requestStatus, decidedAt, runningAt string) {
	e.t.Helper()
	var raw string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT items FROM resp_actions WHERE id = ?`, reqID).Scan(&raw))
	var items []map[string]any
	e.must(json.Unmarshal([]byte(raw), &items))
	for _, it := range items {
		it["status"] = "pending"
		delete(it, "executed_at")
		delete(it, "result")
		delete(it, "verified")
		delete(it, "remove_at")
		if runningAt != "" {
			it["running_at"] = runningAt
		}
	}
	b, err := json.Marshal(items)
	e.must(err)
	e.exec1(`UPDATE resp_actions SET items = ?, status = ?, decided_at = ? WHERE id = ?`, string(b), requestStatus, decidedAt, reqID)
}

func (e *env) at(d time.Duration) string { return store.FormatTS(e.clock.Now().Add(d)) }

// hookExec runs fn before it answers, so a test can look at the box while a step is on its way to a device.
type hookExec struct {
	fn    func(ctx context.Context, s response.DeviceStep) error
	steps *[]response.DeviceStep
}

func (h hookExec) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	*h.steps = append(*h.steps, s)
	if h.fn != nil {
		if err := h.fn(ctx, s); err != nil {
			return response.DeviceResult{}, err
		}
	}
	return response.DeviceResult{Status: response.StepOK, Detail: s.Phase + " done"}, nil
}

// banAndBlock is a rule with one device action and one box action: two items in one request.
func banAndBlock() []response.RuleAction {
	return []response.RuleAction{
		{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)},
		{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}, TTLMin: intp(60)},
	}
}

// ---- H1: plan proposals ----

// INV-14: a proposal of an AI plan holds a catalog action and typed values only. The request is rendered from the catalog
// templates, through the same planner as a rule, so text stored in the plan (a command, another host) never runs; the request
// carries AI data, so the AI gates apply to it (501 until part 13b), and it cannot be approved yet.
func TestContract_INV14_PlanProposalIsRenderedFromTheCatalog(t *testing.T) {
	e := planEnv(t)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_vip_disable","params":{"name":"NAS-PHOTO-443"},"asset_id":"a-nas","asset_name":"NAS",`+
		`"change":{"before":"b","after":"a","cli":"config system global; execute factoryreset","rest":{"method":"DELETE","url":"https://attacker.example/api/v2/cmdb/firewall/policy","body":null},"rollback":{"title":"Undo","cli":"u","rest":null},"verify":""}}`)
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	pv := pl.Items[0].Steps[0].Proposal
	if pv == nil || pv.State != "ready" || pv.ConnectorID != "cn-fw" || !strings.HasPrefix(pv.Change.Rest.URL, "https://fw.lan/api/v2/cmdb/firewall/vip/NAS-PHOTO-443") || response.HasShellChar(pv.Change.CLI) {
		t.Fatalf("the proposal is not shown as rendered from the catalog: %+v", pv)
	}
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	e.must(err)
	if a.AI == nil || a.Source != "ai" || a.Status != response.StatusPending {
		t.Fatalf("a request from an AI plan must carry AI data: %+v", a)
	}
	it := a.Items[0]
	if u, err := url.Parse(it.Change.Rest.URL); err != nil || u.Host != "fw.lan" || response.HasShellChar(it.Change.CLI) || strings.Contains(it.Change.CLI, "factoryreset") {
		t.Fatalf("the request holds text that did not come from the catalog template: %+v", it.Change)
	}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 501, "not_implemented") // the AI gates (INV-16) are part 13b: fail closed
	if e.exec.count() != 0 {
		t.Fatal("a step reached the device")
	}
}

// INV-14: whatever else a stored proposal holds is refused before a request exists: a proposal in the old shape (a stored
// command and call, no action), a value of the wrong type, a value that is a reference into an event, a missing value.
func TestContract_INV14_PlanProposalRefusesStoredText(t *testing.T) {
	e := planEnv(t)
	cases := []struct {
		id, json string
		status   int
		code     string
	}{
		{"pr-legacy", `{"id":"pr-legacy","title":"x","tool":"disable_virtual_ip","connector_id":"cn-fw","asset_id":"a-nas","change":{"cli":"config system global; execute factoryreset","rest":{"method":"DELETE","url":"https://attacker.example/x","body":null}}}`, 403, "tool_not_allowed"},
		{"pr-shell", `{"id":"pr-shell","action_id":"fgt_vip_disable","params":{"name":"x\"; execute reboot"},"asset_id":"a-nas"}`, 400, "invalid_target"},
		{"pr-ref", `{"id":"pr-ref","action_id":"fgt_vip_disable","params":{"name":"{{trigger.ip}}"},"asset_id":"a-nas"}`, 400, "invalid_target"},
		{"pr-missing", `{"id":"pr-missing","action_id":"fgt_vip_disable","params":{},"asset_id":"a-nas"}`, 400, "invalid_target"},
		{"pr-unknown", `{"id":"pr-unknown","action_id":"no_such_action","params":{"name":"x"},"asset_id":"a-nas"}`, 403, "tool_not_allowed"},
	}
	for _, c := range cases {
		e.plan("plan-"+c.id, c.json)
		_, err := e.svc.RequestProposal(e.ctx(), oper, c.id)
		if s, code := apiCode(err); s != c.status || code != c.code {
			t.Errorf("%s: %v (%d %s), want %d %s", c.id, err, s, code, c.status, c.code)
		}
	}
	if e.requests() != 0 || e.exec.count() != 0 {
		t.Fatalf("a refused proposal left %d request(s) or reached a device", e.requests())
	}
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	for _, p := range pl.Items {
		if pr := p.Steps[0].Proposal; pr != nil && pr.State == "ready" {
			t.Errorf("proposal %s is shown as ready", pr.ID)
		}
	}
}

// INV-10: the never-touch list applies to a plan proposal: the device the plan is about must stay reachable.
func TestContract_INV10_PlanProposalNeverTouch(t *testing.T) {
	e := planEnv(t)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_vip_disable","params":{"name":"NAS-PHOTO-443"},"asset_id":"a-nas","asset_name":"NAS"}`)
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "192.168.10.21", Label: "NAS"}})
	e.must(err)
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "never_touch")
}

// INV-9, INV-12: a proposal is requested only when the breaker is closed and no maintenance window is active, and a request that
// was already approved (not run yet) counts as requested.
func TestContract_INV12_PlanProposalGates(t *testing.T) {
	e := planEnv(t)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_vip_disable","params":{"name":"NAS-PHOTO-443"},"asset_id":"a-nas","asset_name":"NAS"}`)
	e.saveSettings(func(in *response.SettingsInput) {
		in.Maintenance = []response.Window{{ID: "w1", Name: "Patch night", Start: e.at(-time.Hour), End: e.at(time.Hour)}}
	})
	_, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "maintenance")
	e.saveSettings(func(in *response.SettingsInput) { in.Maintenance = nil })
	_, err = e.svc.EmergencyStop(e.ctx(), oper) // opens the breaker and turns execution off
	e.must(err)
	e.turnOn()
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "circuit_open")
	_, err = e.svc.ResetBreaker(e.ctx(), admin)
	e.must(err)
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	e.must(err)
	e.exec1(`UPDATE resp_actions SET status = 'approved' WHERE id = ?`, a.ID)
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "already_requested")
	if e.requests() != 1 {
		t.Fatalf("%d requests", e.requests())
	}
}

// ---- H2: a step is never unrecorded ----

// cancelExec cancels the approver's request context while the first device step runs, as a browser that disconnects (or a
// reverse proxy timeout) does, and then answers with whatever error its own context shows.
type cancelExec struct {
	cancel func()
	steps  []response.DeviceStep
}

func (c *cancelExec) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	c.steps = append(c.steps, s)
	c.cancel()
	return response.DeviceResult{Status: response.StepOK, Detail: "done"}, ctx.Err()
}

// INV-19: the approval is committed, so every item runs to the end and is recorded, whether or not the approver is still
// connected. Nothing is left pending inside an approved request, and no step goes unrecorded.
func TestContract_INV19_ApproverDisconnectDoesNotStrandTheBundle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ce := &cancelExec{cancel: cancel}
	e := newEnv(t, func(c *response.Config) { c.Executor = ce })
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban both", "ioc_connection", banAndBlock(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	_, _ = e.svc.Approve(ctx, oper, a.ID, nil, "")
	got := e.only()
	for _, it := range got.Items {
		if it.Status != response.ItemExecuted {
			t.Errorf("item %q is %s, want executed", it.Title, it.Status)
		}
	}
	if got.Status != response.StatusExecuted || len(ce.steps) == 0 || ce.steps[0].Phase != "run" {
		t.Fatalf("request %s, steps %+v", got.Status, ce.steps)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'executed'`); n != 2 {
		t.Fatalf("%d executed lines in the log, want 2", n)
	}
}

// INV-19: before a step is sent, the item is marked running and a log line says so, in a committed transaction; the mark is
// gone when the result is recorded.
func TestContract_INV19_StepIsRecordedBeforeItIsSent(t *testing.T) {
	var e *env
	var steps []response.DeviceStep
	e = newEnv(t, func(c *response.Config) {
		c.Executor = hookExec{steps: &steps, fn: func(context.Context, response.DeviceStep) error {
			if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'approved' AND detail LIKE 'Running:%'`); n != 1 { //nolint:contextcheck // reads the box while the step is in flight
				t.Errorf("%d running lines in the log while the step is on its way", n)
			}
			if n := e.count(`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%"running_at":"2026%'`); n != 1 { //nolint:contextcheck // reads the box while the step is in flight
				t.Errorf("the item is not marked running while the step is on its way")
			}
			return nil
		}}
	})
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if len(steps) == 0 || got.Items[0].Status != response.ItemExecuted || e.count(`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%running_at%'`) != 0 {
		t.Fatalf("steps %d, item %+v", len(steps), got.Items[0])
	}
}

// INV-19, INV-13: a step that runs out of its own time limit is failed with "state unknown, check the device": it may have been
// applied, so the box does not claim that nothing changed.
func TestContract_INV19_StepThatRunsOutOfTimeIsStateUnknown(t *testing.T) {
	var steps []response.DeviceStep
	e := newEnv(t, func(c *response.Config) {
		c.Executor = hookExec{steps: &steps, fn: func(ctx context.Context, _ response.DeviceStep) error { <-ctx.Done(); return ctx.Err() }}
	})
	e.svc.SetStepLimitForTest(50 * time.Millisecond)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	it := got.Items[0]
	if it.Status != response.ItemFailed || it.Result == nil || !strings.Contains(*it.Result, "State unknown") || !e.logHas("failed", "State unknown") || got.Status != response.StatusFailed {
		t.Fatalf("item %+v, request %s", it, got.Status)
	}
}

// INV-19: after a restart an item can be left "running" (a step may have been applied) or never started. The sweep fails them,
// says so in the log, never re-sends a step, and leaves an item that started a moment ago alone.
func TestContract_INV19_SweepFailsStuckItems(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(600)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	id := e.only().ID
	_, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	steps := e.exec.count()

	e.tamperItems(id, "approved", e.at(-time.Minute), e.at(-10*time.Second)) // started 10 seconds ago
	e.must(e.svc.Sweep(e.ctx()))
	if got := e.only(); got.Items[0].Status != response.ItemPending || got.Status != response.StatusApproved {
		t.Fatalf("an item that started 10 seconds ago was failed: %+v", got.Items[0])
	}

	e.tamperItems(id, "approved", e.at(-10*time.Minute), e.at(-5*time.Minute)) // running for 5 minutes: the box restarted
	e.must(e.svc.Sweep(e.ctx()))
	got := e.only()
	if got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "State unknown") || got.Status != response.StatusFailed || !e.logHas("failed", "State unknown") {
		t.Fatalf("a stuck running item: %+v, request %s", got.Items[0], got.Status)
	}

	e.tamperItems(id, "approved", e.at(-11*time.Minute), "") // approved, never started
	e.must(e.svc.Sweep(e.ctx()))
	got = e.only()
	if got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "did not start") || !e.logHas("failed", "did not start") {
		t.Fatalf("an item that never started: %+v", got.Items[0])
	}
	for _, st := range e.exec.steps[steps:] { // the sweep may read a device back to settle an unclear outcome; it never writes
		if st.Phase == "run" || st.Phase == "rollback" {
			t.Fatalf("the sweep sent a %s step to a device", st.Phase)
		}
	}
}

// ---- M1: auto-approval is not one of two approvers ----

// INV-2, INV-5: a pre-approved rule never stands in for one of two people. When the limit is lowered after the rule was saved,
// the request needs two humans, becomes a normal pending request, and runs only after two different people approved it. A rule
// whose request would already need two people cannot be saved as pre-approved.
func TestContract_INV2_PreApprovalNeverCountsAsOneOfTwoApprovers(t *testing.T) {
	e := newEnv(t)
	e.rule("Block both ends", "ioc_connection", twoBlocks(), func(in *response.RuleInput) { in.PreApproved = true })
	e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	if sum.Executed != 0 || a.Status != response.StatusPending || a.PreApproved || len(a.Approvals) != 0 || a.RequiresApprovals != 2 {
		t.Fatalf("summary %+v, request %+v", sum, a)
	}
	if !e.logHas("request", "pre-approval not used") {
		t.Fatal("the log does not say why the pre-approval was not used")
	}
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Status != response.StatusPending || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("one person completed a two-person request: %+v", got)
	}
	got, err = e.svc.Approve(e.ctx(), oper2, a.ID, nil, "")
	e.must(err)
	if got.Status != response.StatusExecuted || len(got.Approvals) != 2 || got.Approvals[0].Via == response.ViaAuto || got.Approvals[1].Via == response.ViaAuto {
		t.Fatalf("after two people: %+v", got)
	}
	// Saving: refused while the request would need two people.
	_, err = e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Pre two", Enabled: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{}, Actions: twoBlocks(), PreApproved: true, MaxPerHour: 5})
	wantCode(t, err, 400, "invalid")
}

// INV-2: the second approver cannot pass off a repeated id for a different selection.
func TestContract_INV2_SecondApproverDuplicateIDsDoNotPassTheSelectionCheck(t *testing.T) {
	e := newEnv(t)
	e.saveSettings(func(in *response.SettingsInput) { in.MultiTargetMax = 1 })
	e.rule("Block both", "ioc_connection", twoBlocks(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	first := a.Items[0].ID
	_, err = e.svc.Approve(e.ctx(), oper2, a.ID, []string{first, first}, "")
	wantCode(t, err, 409, "selection_differs")
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatal("a different set ran")
	}
}

// ---- M2: events ----

// Events no rule has seen yet are never trimmed to make room: a burst of events (spoofed MAC addresses, for example) does not
// hide the real one from the rules.
func TestEventFloodDoesNotEvictUnprocessedEvents(t *testing.T) {
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("e-real", "198.51.100.7")))
	for i := range 520 {
		e.must(e.svc.StoreEvent(e.ctx(), response.Det{ID: "device:noise-" + strconv.Itoa(i), Trigger: "unknown_device", TS: "2026-11-09T10:00:00.000Z", Summary: "noise",
			Fields: map[string]string{"ip": "192.168.10.200", "mac": "02:00:00:00:00:01", "vendor": "x", "kind": "unknown"}}))
	}
	for range 5 {
		_, err := e.svc.Evaluate(e.ctx())
		e.must(err)
	}
	if len(e.actions()) != 1 {
		t.Fatalf("the rule never saw the real event (requests: %d)", len(e.actions()))
	}
	if e.svc.DroppedEvents() != 0 {
		t.Fatal("events were dropped below the backlog bound")
	}
}

// When the unprocessed events pass the backlog bound the oldest are dropped, and the loss is counted, warned about and written
// to the response log: never silent.
func TestEventBacklogOverflowIsCountedAndLogged(t *testing.T) {
	e := newEnv(t)
	e.svc.SetBacklogForTest(5)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	for i := range 8 {
		e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("e"+strconv.Itoa(i+1), "198.51.100."+strconv.Itoa(10+i))))
	}
	// the metric counts every drop; the log gets one coalesced line per minute (the first drop writes it)
	if e.svc.DroppedEvents() != 3 || !e.logHas("refused", "event_backlog: 1 unprocessed") || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'event_backlog:%'`) != 1 {
		t.Fatalf("dropped %d", e.svc.DroppedEvents())
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE processed = 0`); n != 5 {
		t.Fatalf("%d events waiting, want 5", n)
	}
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	if sum.Requests != 5 {
		t.Fatalf("%d requests, want 5 (the three oldest events were dropped)", sum.Requests)
	}
}

// ---- M3: the emergency stop stops everything ----

// INV-8, INV-12: the stop also opens the global breaker, so a pre-approved rule with a box action stops too, until an admin
// resets the breaker.
func TestContract_INV8_EmergencyStopOpensTheBreaker(t *testing.T) {
	e := newEnv(t)
	e.rule("Pre", "ioc_connection", blockAction(60), func(in *response.RuleInput) { in.PreApproved = true })
	_, err := e.svc.EmergencyStop(e.ctx(), oper)
	e.must(err)
	if e.settings().BreakerTrippedAt == nil || e.settings().Execution {
		t.Fatalf("settings after the stop: %+v", e.settings())
	}
	sum := e.fire(e.iocEvent("e1", "198.51.100.7"))
	if n := e.count(`SELECT COUNT(*) FROM resp_block_entries`); n != 0 || sum.Refused != 1 || !e.logHas("refused", "circuit_open") {
		t.Fatalf("after the stop a pre-approved rule published %d entries (summary %+v)", n, sum)
	}
	_, err = e.svc.ResetBreaker(e.ctx(), admin)
	e.must(err)
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	if n := e.count(`SELECT COUNT(*) FROM resp_block_entries`); n != 1 {
		t.Fatalf("after an admin reset the rule is still stopped (%d entries)", n)
	}
}

// INV-8: a bundle that is running when the stop comes: the step in flight finishes, every later item (here a box action) is
// refused with circuit_open instead of running.
func TestContract_INV8_EmergencyStopStopsItemsStillToRun(t *testing.T) {
	var e *env
	var steps []response.DeviceStep
	e = newEnv(t, func(c *response.Config) {
		c.Executor = hookExec{steps: &steps, fn: func(ctx context.Context, _ response.DeviceStep) error {
			_, err := e.svc.EmergencyStop(ctx, oper)
			return err
		}}
	})
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban and block", "ioc_connection", banAndBlock(), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemExecuted || got.Items[1].Status != response.ItemFailed || !e.logHas("refused", "circuit_open") {
		t.Fatalf("items: %+v / %+v", got.Items[0], got.Items[1])
	}
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatal("a box action ran after the stop")
	}
}

// ---- M4: never-touch for switch ports, MAC addresses, interfaces ----

// INV-10: the subject of the event counts for every trigger, so a port action for an event about the gateway is refused even
// though the action names only a port.
func TestContract_INV10_NeverTouchCoversTheEventSubjectOfPortActions(t *testing.T) {
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "192.168.10.1", Label: "Gateway"}})
	e.must(err)
	e.rule("Shut the port", "ioc_connection", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(240)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["src_ip"], ev.Fields["device"], ev.Fields["switch_port"] = "192.168.10.1", "gateway", "Gi1/0/48"
	sum := e.fire(ev)
	if l := e.actions(); len(l) != 0 || sum.Refused != 1 || !e.logHas("refused", "never_touch") {
		t.Fatalf("a port shutdown for the never-touch gateway was requested: %+v", l)
	}
	ev2 := e.iocEvent("e2", "198.51.100.7") // another device on another port: allowed
	ev2.Fields["switch_port"] = "Gi1/0/5"
	e.fire(ev2)
	if len(e.actions()) != 1 {
		t.Fatal("an unrelated port was refused")
	}
}

// INV-10: an action that names an address acts on that address only. Blocking the bad destination of a connection is not
// refused because the device that made it is a never-touch router; the router itself still cannot be blocked.
func TestContract_INV10_AddressActionsAreNotRefusedForTheirSubject(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "192.168.10.1", Label: "Gateway"}})
	e.must(err)
	e.rule("Block the destination", "ioc_connection", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["src_ip"], ev.Fields["device"] = "192.168.10.1", "gateway"
	e.fire(ev)
	if l := e.actions(); len(l) != 1 {
		t.Fatalf("blocking the destination was refused because the source is the gateway: %+v", l)
	}
	e.rule("Block the source", "ioc_connection", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}, TTLMin: intp(60)}}, nil)
	ev2 := e.iocEvent("e2", "198.51.100.8")
	ev2.Fields["src_ip"], ev2.Fields["device"] = "192.168.10.1", "gateway"
	e.fire(ev2)
	if !e.logHas("refused", "never_touch") {
		t.Fatal("blocking the never-touch gateway itself was not refused")
	}
}

// INV-10: the list takes MAC addresses and interface names. A listed port is protected whatever device the event is about; a
// listed MAC is protected as the subject of an event. A typo that is not an address, a MAC or a port name is refused when saved.
func TestContract_INV10_NeverTouchMACAndInterfaceEntries(t *testing.T) {
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	for _, bad := range []string{"192.168.1.300", "10.0.0.0/33", "../x", "Gi1/0/48 ", "a/../b", "1/../2", "x//y"} {
		_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: bad, Label: "x"}})
		if bad == "Gi1/0/48 " { // surrounding blanks are trimmed
			e.must(err)
			continue
		}
		wantCode(t, err, 400, "invalid")
	}
	l, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "AA-BB-CC-DD-EE-FF", Label: "Core switch"}, {Value: "Gi1/0/48", Label: "Uplink"}, {Value: "1/1/52", Label: "Stack uplink"}})
	e.must(err)
	if !hasEntry(l, "aa:bb:cc:dd:ee:ff") || !hasEntry(l, "gi1/0/48") || !hasEntry(l, "1/1/52") {
		t.Fatalf("list: %+v", l)
	}
	e.rule("Shut the port", "ioc_connection", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(240)}}, nil)
	up := e.iocEvent("e1", "198.51.100.7")
	up.Fields["switch_port"] = "Gi1/0/48"
	e.fire(up)
	mac := e.iocEvent("e2", "198.51.100.7")
	mac.Fields["switch_port"], mac.Fields["mac"] = "Gi1/0/7", "AA:BB:CC:DD:EE:FF"
	e.fire(mac)
	if len(e.actions()) != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'never_touch%'`) != 2 {
		t.Fatalf("a listed port or MAC was not protected: %d requests", len(e.actions()))
	}
	ok := e.iocEvent("e3", "198.51.100.7")
	ok.Fields["switch_port"] = "Gi1/0/7"
	e.fire(ok)
	if len(e.actions()) != 1 {
		t.Fatal("an unlisted port on an unlisted device was refused")
	}
}

// ---- M5: gateways from the inventory, fail closed ----

// INV-10: every inventory router and firewall counts as never-touch without being listed, read at planning and again at run.
func TestContract_INV10_InventoryGatewaysAreNeverTouch(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-gw"] = response.DeviceInfo{ID: "a-gw", Name: "Edge router", IP: "203.0.113.1", Kind: "router"}
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC", IP: "203.0.113.50", Kind: "pc"}
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	l, err := e.svc.Allowlist(e.ctx())
	e.must(err)
	if !hasEntry(l, "203.0.113.1") || hasEntry(l, "203.0.113.50") {
		t.Fatalf("the never-touch list: %+v", l)
	}
	if sum := e.fire(e.iocEvent("e1", "203.0.113.1")); sum.Refused != 1 || len(e.actions()) != 0 || !e.logHas("refused", "never_touch") {
		t.Fatalf("a router was planned for blocking: %+v", sum)
	}
	e.fire(e.iocEvent("e2", "203.0.113.50"))
	a := e.only()
	// the router appears after the request was made: refused right before it runs
	e.dir.devices["a-new"] = response.DeviceInfo{ID: "a-new", Name: "New firewall", IP: "203.0.113.50", Kind: "firewall"}
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("a firewall added since the request was blocked anyway: %+v", got.Items[0])
	}
}

// INV-10: when the box's own addresses (or the inventory) cannot be read the never-touch list cannot be built: the action is
// refused with a plain reason, at planning and right before it runs, and the block list answers 503 instead of publishing with fewer entries.
func TestContract_INV10_UnreadableNeverTouchListFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)

	e.svc.SetInterfacesForTest(func() ([]netipAddr, error) { return nil, context.DeadlineExceeded })
	sum := e.fire(e.iocEvent("e2", "198.51.100.8"))
	if sum.Refused != 1 || len(e.actions()) != 1 || !e.logHas("refused", "could not be read in full") {
		t.Fatalf("planned with a list that could not be built: %+v", sum)
	}
	if _, err := e.svc.Allowlist(e.ctx()); err == nil {
		t.Fatal("the never-touch list was shown without the box addresses")
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), tokenOf(v.URL), "192.168.10.50"); err == nil {
		t.Fatal("the block list was published without the never-touch list")
	} else {
		wantCode(t, err, 503, "server_busy")
	}
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || !contains(*got.Items[0].Result, "could not be read in full") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatalf("ran with a list that could not be built: %+v", got.Items[0])
	}

	e.svc.SetInterfacesForTest(nil)
	e.dir.listErr = context.DeadlineExceeded // the inventory cannot be read
	sum = e.fire(e.iocEvent("e3", "198.51.100.9"))
	if sum.Refused != 1 {
		t.Fatalf("planned without the inventory gateways: %+v", sum)
	}
	e.dir.listErr = nil
	e.fire(e.iocEvent("e4", "198.51.100.10"))
	if len(e.actions()) != 2 {
		t.Fatal("planning did not recover once the lists were readable")
	}
}

// ---- the block list ----

// INV-17: only public addresses are published: RFC 1918 and unique-local, carrier-grade NAT, 0.0.0.0/8, loopback, link-local,
// multicast and reserved ranges never are, so a poisoned feed cannot lock the customer's own network out. The never-touch list
// still holds back what it lists.
func TestContract_INV17_BlocklistPublishesPublicAddressesOnly(t *testing.T) {
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "192.168.10.1"))
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	for i, v := range []string{"10.1.1.1", "172.16.0.1", "100.64.0.1", "100.127.255.254", "0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "fc00::1", "fe80::1", "::1", "198.51.100.9", "2606:4700::7", "100.128.0.1"} {
		e.exec1(`INSERT INTO resp_block_entries (value, request_id, item_id, source, reason, added_at) VALUES (?, 'x', ?, 's', 'r', '2026-11-09T10:00:00.000Z')`, v, "i"+strconv.Itoa(i))
	}
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	b, err := e.svc.FetchBlocklist(e.ctx(), tokenOf(v.URL), "192.168.10.50")
	e.must(err)
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasPrefix(l, "#") {
			got = append(got, l)
		}
	}
	want := []string{"100.128.0.1", "2606:4700::7", "198.51.100.9"}
	if len(got) != len(want) {
		t.Fatalf("published %v, want %v", got, want)
	}
	for _, w := range want {
		if !strings.Contains("\n"+strings.Join(got, "\n")+"\n", "\n"+w+"\n") {
			t.Errorf("%s is not published: %v", w, got)
		}
	}
	for _, en := range v.Entries {
		if en.Value == "10.1.1.1" {
			t.Error("the admin view lists an address that is never published")
		}
	}
}

// INV-17: the public file's comments hold only the name of the list, the time and the count: no device name, event summary or rule.
func TestContract_INV17_BlocklistNamesNothingInternal(t *testing.T) {
	e := newEnv(t)
	e.rule("Block the sales PCs", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	b, err := e.svc.FetchBlocklist(e.ctx(), tokenOf(v.URL), "192.168.10.50")
	e.must(err)
	want := "# vedette blocklist\n# generated 2026-11-09T10:00:00.000Z\n# entries 1\n198.51.100.7\n"
	if string(b) != want {
		t.Fatalf("the public list:\n%s\nwant:\n%s", b, want)
	}
	if len(v.Entries) != 1 || !strings.Contains(v.Entries[0].Source, "Block the sales PCs") {
		t.Fatalf("the admin view lost the source: %+v", v.Entries)
	}
}

// INV-17: when the store cannot be read the answer is 503 with Retry-After, never an empty list (a firewall keeps its old list on
// an error and drops every entry on an empty one).
func TestContract_INV17_BlocklistUnreadableStoreIs503(t *testing.T) {
	e := newEnv(t)
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	e.exec1(`DROP TABLE resp_block_entries`)
	_, err = e.svc.FetchBlocklist(e.ctx(), tokenOf(v.URL), "192.168.10.50")
	wantCode(t, err, 503, "server_busy")
	if ae, _ := apierr.As(err); ae.Extra["retry_after"] != 60 {
		t.Fatalf("no Retry-After: %+v", ae.Extra)
	}
}

// INV-17: the list holds at most 10 000 entries; at the limit a new entry is refused with a reason, never cut silently.
func TestContract_INV17_BlocklistEntryLimit(t *testing.T) {
	e := newEnv(t)
	e.exec1(`WITH RECURSIVE c(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM c WHERE n < 9999)
INSERT INTO resp_block_entries (value, request_id, item_id, source, reason, added_at) SELECT '45.0.' || (n / 256) || '.' || (n % 256), 'x', 'y' || n, 's', 'r', '2026-11-09T10:00:00.000Z' FROM c`)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemFailed || !contains(*got.Items[0].Result, "10000") || !e.logHas("refused", "limit") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 10000 {
		t.Fatalf("item %+v", got.Items[0])
	}
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	b, err := e.svc.FetchBlocklist(e.ctx(), tokenOf(v.URL), "192.168.10.50")
	e.must(err)
	if n := strings.Count(string(b), "\n45."); n != 10000 {
		t.Fatalf("published %d entries", n)
	}
}

// INV-17: the rate limit is per source address and, for IPv6, per /64: one host rotating addresses inside its /64 is limited, a
// host in another /64 and an IPv4 host are not affected.
func TestBlocklistRateLimitIsPerIPv6Prefix(t *testing.T) {
	e := newEnv(t)
	limited := 0
	for i := range 40 {
		_, err := e.svc.FetchBlocklist(e.ctx(), strings.Repeat("0", 32), "2001:db8:1:2::"+strconv.FormatInt(int64(i+1), 16))
		if s, _ := apiCode(err); s == 429 {
			limited++
		}
	}
	if limited != 20 {
		t.Fatalf("%d of 40 wrong tokens from one /64 were limited, want 20", limited)
	}
	for _, from := range []string{"2001:db8:1:3::1", "192.168.10.5"} {
		_, err := e.svc.FetchBlocklist(e.ctx(), strings.Repeat("0", 32), from)
		wantCode(t, err, 404, "not_found")
	}
	if n := e.svc.FetchKeysForTest(); n > 4 {
		t.Fatalf("the rate limit table holds %d keys for 3 sources", n)
	}
}

// ---- M6, M7: what the request was made against ----

func mcpEnv(t *testing.T) (*env, response.CatalogAction) {
	t.Helper()
	e := newEnv(t)
	e.conns.list = []response.ConnectionInfo{{Connection: response.Connection{ID: "cn-mcp", Name: "MCP firewall", Enabled: true, Kind: "mcp-http", WriteTools: []string{"block_ip", "unblock_ip", "delete_all_rules"}}, Target: "https://mcp.lan"}}
	act, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Block an IP (MCP)", ConnectionID: "cn-mcp", Tool: strp("block_ip"), RollbackTool: strp("unblock_ip"),
		Run: response.Tpl{Body: `{"ip":"{ip}"}`}, Rollback: response.Tpl{Body: `{"ip":"{ip}"}`}, Risk: response.RiskMedium, Enabled: true})
	e.must(err)
	e.rule("Block via MCP", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	return e, act
}

// INV-9: an admin who edits a custom MCP action while a request waits cannot make the approval run another write tool: the item
// carries the tool it was made for, and the catalog must still say the same at approval.
func TestContract_INV9_ToolChangedAfterTheRequestIsRefused(t *testing.T) {
	e, act := mcpEnv(t)
	a := e.only()
	// Behind the API (a restore, another writer): ChangeAction would cancel the request (D-88 29), the gate must hold without it.
	e.exec1(`UPDATE resp_catalog SET tool = 'delete_all_rules' WHERE id = ?`, act.ID)
	e.turnOn()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	wantCode(t, err, 409, "tool_unavailable")
	if e.exec.count() != 0 {
		t.Fatal("a step reached the device")
	}
	// the same request with the tool put back runs the tool it was made for
	e.exec1(`UPDATE resp_catalog SET tool = 'block_ip' WHERE id = ?`, act.ID)
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if len(e.exec.steps) == 0 || e.exec.steps[0].Tool != "block_ip" {
		t.Fatalf("steps: %+v", e.exec.steps)
	}
}

// INV-9, INV-13: the undo tool is checked too: an edit of the rollback tool after the change was made refuses the undo (the
// change stays, the person is told), and the step that was sent used the tools stored in the item.
func TestContract_INV13_RollbackToolChangedAfterTheRequestIsRefused(t *testing.T) {
	e, act := mcpEnv(t)
	a := e.only()
	e.turnOn()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	_, err = e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{RollbackTool: strp("delete_all_rules"), Present: map[string]bool{"rollback_tool": true}})
	e.must(err)
	_, err = e.svc.Rollback(e.ctx(), oper, a.ID)
	wantCode(t, err, 409, "tool_unavailable")
	for _, s := range e.exec.steps {
		if s.Phase == "rollback" {
			t.Fatalf("the undo ran with another tool: %+v", s)
		}
	}
	_, err = e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{RollbackTool: strp("unblock_ip"), Present: map[string]bool{"rollback_tool": true}})
	e.must(err)
	if _, err = e.svc.Rollback(e.ctx(), oper, a.ID); err != nil {
		t.Fatal(err)
	}
	if last := e.exec.steps[len(e.exec.steps)-1]; last.Phase != "rollback" || last.Tool != "unblock_ip" {
		t.Fatalf("steps: %+v", e.exec.steps)
	}
}

// INV-9: the stored call holds the address of the connection the request was made against. When the connection changed
// (another address, another version) the approval is refused with connection_changed and nothing is sent; so is an undo.
func TestContract_INV9_ConnectionChangedAfterTheRequestIsRefused(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	l := e.actions()
	e.conns.list[0].Target = "https://new-fw.lan"
	_, err := e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 409, "connection_changed")
	e.conns.list[0].Target = "https://fw.lan"
	e.conns.list[0].UpdatedAt = "2026-11-09T09:59:00.000Z" // edited (credentials, tools): another version
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 409, "connection_changed")
	if e.exec.count() != 0 {
		t.Fatal("a step was sent to a connection that changed")
	}
	e.conns.list[0].UpdatedAt = ""
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	e.must(err)
	e.conns.list[0].Target = "https://new-fw.lan"
	_, err = e.svc.Rollback(e.ctx(), oper, l[0].ID)
	wantCode(t, err, 409, "connection_changed")
	if got := e.exec.phases(); strings.Join(got, ",") != "run,verify" {
		t.Fatalf("steps = %v", got)
	}
}

// ---- L2, L10: rolling back ----

// INV-13: after an admin disables an action, a person can still undo what it did: removing a change is the safe direction.
// The execution switch still applies to a device undo (INV-7).
func TestContract_INV13_RollbackAllowedAfterTheActionWasDisabled(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(600)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	a := e.only()
	_, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	off := false
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{Enabled: &off, Present: map[string]bool{"enabled": true}})
	e.must(err)
	got, err := e.svc.Rollback(e.ctx(), oper, a.ID)
	if err != nil {
		t.Fatalf("rollback of an executed change refused after the action was disabled: %v", err)
	}
	if got.Status != response.StatusRolledBack || strings.Join(e.exec.phases(), ",") != "run,verify,rollback,verify" {
		t.Fatalf("status %s, steps %v", got.Status, e.exec.phases())
	}
}

// INV-13: a read (GET /response/actions) never sends a step to a device: the undo of an expired change belongs to the sweep job.
func TestContract_INV13_ReadsNeverUndoOnlyTheSweepDoes(t *testing.T) {
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	e.clock.Advance(2 * time.Hour)
	if got := e.only(); got.Items[0].Status != response.ItemExecuted || e.exec.count() != 2 {
		t.Fatalf("a read undid a change: %+v, steps %v", got.Items[0], e.exec.phases())
	}
	if _, err := e.svc.Metrics(e.ctx()); err != nil || e.exec.count() != 2 {
		t.Fatalf("metrics: %v, steps %v", err, e.exec.phases())
	}
	e.must(e.svc.Sweep(e.ctx()))
	if got := e.only(); got.Status != response.StatusRolledBack || strings.Join(e.exec.phases(), ",") != "run,verify,rollback,verify" {
		t.Fatalf("the sweep did not undo: %+v, steps %v", got.Status, e.exec.phases())
	}
}

// ---- L13, note 1, note 3 ----

// httpAction adds an API connection and a custom, low-risk, reversible action on it.
func (e *env) httpAction(headers string) response.CatalogAction {
	e.t.Helper()
	e.conns.list = append(e.conns.list, response.ConnectionInfo{Connection: response.Connection{ID: "cn-api", Name: "Quarantine API", Enabled: true, Kind: "http", WriteTools: []string{"write"}}, Target: "https://api.lan"})
	act, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Quarantine an IP (API)", ConnectionID: "cn-api",
		Run: response.Tpl{Method: "POST", Path: "/q/{ip}", Headers: headers}, Rollback: response.Tpl{Method: "DELETE", Path: "/q/{ip}"}, Risk: response.RiskLow, Enabled: true})
	e.must(err)
	return act
}

// INV-5: editing the templates or the risk of a custom action switches pre-approval off on every rule that uses it, with a
// log line; an admin confirms the rule again. An edit that changes neither (the description) leaves it on.
func TestContract_INV5_EditingAnActionSwitchesPreApprovalOff(t *testing.T) {
	e := newEnv(t)
	act := e.httpAction("")
	r := e.rule("Quarantine", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, func(in *response.RuleInput) { in.PreApproved = true })
	if !mustRules(e)[0].PreApproved {
		t.Fatal("the rule is not pre-approved")
	}
	desc := "Isolates the address."
	_, err := e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{Description: &desc})
	e.must(err)
	if !mustRules(e)[0].PreApproved {
		t.Fatal("a description edit switched pre-approval off")
	}
	run := response.Tpl{Method: "POST", Path: "/quarantine/{ip}"}
	_, err = e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{Run: &run})
	e.must(err)
	if mustRules(e)[0].PreApproved || !e.logHas("settings", "Pre-approval switched off for rule") {
		t.Fatal("editing the templates left the rule pre-approved")
	}
	in := r.RuleInput
	in.PreApproved, in.Live = true, true
	if _, err = e.svc.ChangeRule(e.ctx(), admin, r.ID, in); err != nil || !mustRules(e)[0].PreApproved {
		t.Fatalf("an admin cannot confirm the rule again: %v", err)
	}
	high := response.RiskHigh
	_, err = e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{Risk: &high})
	e.must(err)
	if mustRules(e)[0].PreApproved {
		t.Fatal("raising the risk left the rule pre-approved")
	}
}

// The evaluator reads the rule, then runs it in a transaction: the stored rule is tested again there, so a rule whose condition
// was changed in between does not run for an event it no longer matches, and the event is not marked handled for it.
func TestEvaluatorTestsTheStoredRuleAgain(t *testing.T) {
	e := newEnv(t)
	r := e.rule("Block IPsum hits", "ioc_connection", blockAction(60), func(in *response.RuleInput) {
		in.Conditions = []response.Condition{{Field: "feeds", Op: "eq", Value: "IPsum"}}
	})
	ev := e.iocEvent("e1", "198.51.100.7")
	e.must(e.svc.StoreEvent(e.ctx(), ev))
	in := r.RuleInput
	in.Conditions = []response.Condition{{Field: "feeds", Op: "eq", Value: "Feodo Tracker"}}
	_, err := e.svc.ChangeRule(e.ctx(), admin, r.ID, in)
	e.must(err)
	handled, err := e.svc.HandleStaleForTest(e.ctx(), r.ID, ev, []response.Det{ev})
	e.must(err)
	if handled || len(e.actions()) != 0 || e.count(`SELECT COUNT(*) FROM resp_done`) != 0 {
		t.Fatalf("the rule ran for an event it no longer matches (handled %v, %d requests)", handled, len(e.actions()))
	}
	in.Conditions = []response.Condition{{Field: "feeds", Op: "eq", Value: "IPsum"}}
	_, err = e.svc.ChangeRule(e.ctx(), admin, r.ID, in)
	e.must(err)
	if handled, err = e.svc.HandleStaleForTest(e.ctx(), r.ID, ev, []response.Det{ev}); err != nil || !handled || len(e.actions()) != 1 {
		t.Fatalf("handled %v, %v, %d requests", handled, err, len(e.actions()))
	}
}

// GET /response/catalog is open to viewers: the header lines of a template (they can carry an authorisation value) show their
// names only, except to an admin.
func TestCatalogHidesHeaderValuesFromNonAdmins(t *testing.T) {
	e := newEnv(t)
	act := e.httpAction("X-Api-Key: abc123secret\nAccept: application/json")
	find := func(c response.Catalog) response.CatalogAction {
		for _, a := range c.Items {
			if a.ID == act.ID {
				return a
			}
		}
		t.Fatal("the action is not in the catalog")
		return response.CatalogAction{}
	}
	full, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	if h := find(full).Run.Headers; h != "X-Api-Key: abc123secret\nAccept: application/json" {
		t.Fatalf("an admin sees %q", h)
	}
	masked, err := e.svc.Catalog(e.ctx(), false)
	e.must(err)
	if h := find(masked).Run.Headers; h != "X-Api-Key: (hidden)\nAccept: (hidden)" || strings.Contains(h, "abc123") {
		t.Fatalf("a viewer sees %q", h)
	}
}
