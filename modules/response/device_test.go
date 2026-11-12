package response_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-6: an approved item reaches its device through the executor: the check before (read only, may refuse), the run, the
// read-back; an undo is the rollback and a read-back that must no longer hold the text. The executor here is a fake; the real
// writer and real servers are in cmd/vedette/response_device_test.go.

// switchRule binds cisco_port_shut to the SSH switch and makes one open request for the port Gi1/0/12.
func switchRequest(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	e.turnOn()
	e.rule("Shut the port", "honeypot", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.trap("h1", "192.168.10.157"))
	return e
}

const staticAccess = "Name: Gi1/0/12\nAdministrative Mode: static access\nSwitchport: Enabled"

// INV-22, D-95 (1): a check before that prints a refusal text fails the item, and nothing is written (no run step is sent).
func TestDevice_PrecheckRefusalSendsNothingToWrite(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	e.exec.pre = "Name: Gi1/0/12\nAdministrative Mode: trunk\nSwitchport: Enabled"
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if strings.Join(e.exec.phases(), ",") != "precheck" {
		t.Fatalf("steps = %v: only the check before may be sent", e.exec.phases())
	}
	it := got.Items[0]
	if it.Status != response.ItemFailed || it.Result == nil || !strings.Contains(*it.Result, "Refused by the check before: Mode: trunk") || !strings.Contains(*it.Result, "Nothing was changed") {
		t.Fatalf("item: %+v", it)
	}
	if !e.logHas("refused", "precheck_refused") || e.logHas("executed", "") {
		t.Fatal("the refusal is not in the log, or something was recorded as executed")
	}
	if in, err := e.svc.ChangesInForce(e.ctx(), "cn-sw"); err != nil || in {
		t.Fatalf("a refused item counts as in force: %v %v", in, err)
	}
}

// D-95 (1a): the check before must contain precheck_expect; an output that does not is refused (a text nobody foresaw is not an all-clear).
func TestDevice_PrecheckExpectMissingIsRefused(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	e.exec.pre = "Name: Gi1/0/12\nSomething nobody foresaw"
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if strings.Join(e.exec.phases(), ",") != "precheck" || got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "does not contain: Administrative Mode: static access") {
		t.Fatalf("steps %v, item %+v", e.exec.phases(), got.Items[0])
	}
}

// D-95 (1b): a check that prints nothing (after the output is normalised) is refused, whatever the device meant by it.
func TestDevice_EmptyPrecheckOutputFailsClosed(t *testing.T) {
	t.Parallel()
	for _, out := range []string{" ", "\r\n", "\x1b[0m \t"} {
		e := switchRequest(t)
		e.exec.pre = out
		got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
		e.must(err)
		if strings.Join(e.exec.phases(), ",") != "precheck" || got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "printed nothing") {
			t.Fatalf("output %q: steps %v, item %+v", out, e.exec.phases(), got.Items[0])
		}
	}
}

// The order, the exact rendering of every step and the read-back: precheck, run, verify; the lines are the template filled, one line each;
// the undo is the rollback and then a read-back that must not hold the text.
func TestDevice_StepsAreTheRenderedTemplatesInOrder(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	e.exec.pre = staticAccess
	e.exec.present = "Gi1/0/12 disabled"
	req := e.only()
	got, err := e.svc.Approve(e.ctx(), oper, req.ID, nil, "")
	e.must(err)
	if strings.Join(e.exec.phases(), ",") != "precheck,verify,run,verify" { // the read before the run (D-356): not the same read as the check
		t.Fatalf("steps = %v", e.exec.phases())
	}
	want := map[string]string{
		"precheck": "terminal length 0|show interfaces Gi1/0/12 switchport|show interfaces Gi1/0/12",
		"run":      "terminal length 0|configure terminal|interface Gi1/0/12|shutdown|end",
		"verify":   "terminal length 0|show interfaces Gi1/0/12 status",
	}
	for _, s := range e.exec.steps {
		if g := strings.Join(s.Lines, "|"); g != want[s.Phase] || s.ConnectionID != "cn-sw" || s.ConnFP == "" || s.Method != "" || s.URL != "" || s.Tool != "" {
			t.Errorf("%s step = %+v", s.Phase, s)
		}
	}
	if v := got.Items[0].Verified; v == nil || !v.OK || got.Items[0].Status != response.ItemExecuted {
		t.Fatalf("item: %+v", got.Items[0])
	}
	// The undo: the rollback, then a read-back that must not hold "disabled" any more.
	if _, err := e.svc.Rollback(e.ctx(), oper, req.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Join(e.exec.phases(), ",") != "precheck,verify,run,verify,rollback,verify" {
		t.Fatalf("steps = %v", e.exec.phases())
	}
	if g := strings.Join(e.exec.steps[4].Lines, "|"); g != "terminal length 0|configure terminal|interface Gi1/0/12|no shutdown|end" {
		t.Errorf("rollback lines = %s", g)
	}
	if it := e.only().Items[0]; it.Status != response.ItemRolledBack || it.Result == nil || !strings.Contains(*it.Result, "the change is gone") {
		t.Fatalf("after the undo: %+v", it)
	}
}

// D-95 (2): after the undo the read-back must NOT hold the text. A device that still shows the change leaves the item executed with the
// reason (the sweep tries again), and the failure is logged once.
func TestDevice_RollbackReadBackMustNotContainExpect(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	e.exec.pre, e.exec.present = staticAccess, "Gi1/0/12 disabled"
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	e.exec.after = "Gi1/0/12 disabled" // after the run (not before it: that would be a change already there, D-356)
	e.clock.Advance(31 * time.Minute)
	e.must(e.svc.Sweep(e.ctx()))
	e.must(e.svc.Sweep(e.ctx()))
	it := e.only().Items[0]
	if it.Status != response.ItemExecuted || it.Result == nil || !strings.Contains(*it.Result, "read-back still shows the change") {
		t.Fatalf("item: %+v", it)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'failed' AND detail LIKE '%still shows the change%'`); n != 1 {
		t.Fatalf("the failure was logged %d times", n)
	}
	// The device is now clean: the next sweep finishes the undo.
	e.exec.after = ""
	e.must(e.svc.Sweep(e.ctx()))
	if got := e.only(); got.Status != response.StatusRolledBack {
		t.Fatalf("request: %s", got.Status)
	}
}

// D-95 (2): a read-back needs a text to look for. Without one the item is not "checked" and the read-back is not even sent (a 2xx or a
// silent command is never "verified").
func TestDevice_VerifyNeedsExpect(t *testing.T) {
	t.Parallel()
	e := precheckEnv(t)
	in := apiAction()
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}"} // a read-back without a text
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if strings.Join(e.exec.phases(), ",") != "run" || got.Items[0].Status != response.ItemExecuted || got.Items[0].Verified != nil {
		t.Fatalf("steps %v, item %+v", e.exec.phases(), got.Items[0])
	}
	// With a text the read-back is sent and judged: a device that does not show it is "not confirmed", never "ok".
	e2 := precheckEnv(t)
	in2 := apiAction()
	in2.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Expect: "{domain}"}
	act2, err := e2.svc.AddAction(e2.ctx(), admin, in2)
	e2.must(err)
	e2.turnOn()
	e2.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act2.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	e2.fire(ev)
	got2, err := e2.svc.Approve(e2.ctx(), oper, e2.only().ID, nil, "")
	e2.must(err)
	if strings.Join(e2.exec.phases(), ",") != "verify,run,verify" || got2.Items[0].Verified == nil || got2.Items[0].Verified.OK {
		t.Fatalf("steps %v, item %+v", e2.exec.phases(), got2.Items[0])
	}
	if got2.Items[0].Status != response.ItemExecuted {
		t.Fatalf("a read-back that does not confirm is a note on the item, not a failure: %+v", got2.Items[0])
	}
}

// D-94 (4): {expiry_s} is the undo time in seconds, filled when the request is made; an item without an undo time cannot use it.
func TestDevice_ExpirySecondsAreTheUndoTime(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	if _, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	run := e.exec.runStep()
	if run.Phase != "run" || run.Method != "POST" || run.URL != "https://fw.lan/api/v2/monitor/user/banned/add_users" || run.Body != `{"ip_addresses":["198.51.100.7"],"expiry":1800}` {
		t.Fatalf("run step: %+v", run)
	}
	// No undo time: the action is not available for this item and nothing is requested.
	e2 := newEnv(t)
	e2.firewall("fgt_ban_ip")
	e2.turnOn()
	e2.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}}}, nil)
	sum := e2.fire(e2.iocEvent("e1", "198.51.100.7"))
	if len(e2.actions()) != 0 || sum.Refused != 1 || !e2.logHas("refused", "needs an undo time") {
		t.Fatalf("a ban without an undo time was requested: %+v %+v", e2.actions(), sum)
	}
}

// The exact text of the step is what the approver saw: the API call of the change is the call of the run step.
func TestDevice_RunStepIsWhatTheApproverSaw(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_vip_disable")
	e.turnOn()
	e.rule("VIP", "ioc_connection", []response.RuleAction{{ActionID: "fgt_vip_disable", Params: map[string]string{"name": "web-vip"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	req := e.only()
	if _, err := e.svc.Approve(e.ctx(), oper, req.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	shown := req.Items[0].Change.Rest
	run := e.exec.runStep()
	if shown == nil || shown.Method != run.Method || shown.URL != run.URL || shown.Body == nil || *shown.Body != run.Body {
		t.Fatalf("shown %+v, sent %+v", shown, run)
	}
}

// D-94 (4): an action that needs a value read from the device while it runs is not available until 13c.
func TestDevice_RuntimeValueIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.sshSwitch("cisco_acl_deny")
	cat, err := e.svc.Catalog(e.ctx(), false)
	e.must(err)
	for _, a := range cat.Items {
		if a.ID == "cisco_acl_deny" && (a.Available || a.UnavailableReason == nil || !strings.Contains(*a.UnavailableReason, "Not available yet")) {
			t.Fatalf("cisco_acl_deny: %+v", a)
		}
	}
	e.turnOn()
	e.rule("ACL", "ioc_connection", []response.RuleAction{{ActionID: "cisco_acl_deny", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	if len(e.actions()) != 0 || e.exec.count() != 0 {
		t.Fatal("an action with a runtime value was requested")
	}
}

// D-95 (3): an action that names a port needs a check before it with a refusal text. A row whose check was emptied behind the API is
// not available, so it cannot be requested or run.
func TestDevice_PortActionNeedsAPrecheck(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.sshSwitch("cisco_port_shut")
	e.exec1(`UPDATE resp_catalog SET precheck = '{}', precheck_refuse = '[]' WHERE id = 'cisco_port_shut'`)
	cat, err := e.svc.Catalog(e.ctx(), false)
	e.must(err)
	found := false
	for _, a := range cat.Items {
		if a.ID == "cisco_port_shut" {
			found = true
			if a.Available || a.UnavailableReason == nil || !strings.Contains(*a.UnavailableReason, "check before it") {
				t.Fatalf("cisco_port_shut: %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("no cisco_port_shut in the catalog")
	}
}

// 13b-6: a connection that is not ready (never tested, last test failed) and a write tool on a connection that is not an MCP server make
// an action unavailable, with the reason in plain words.
func TestDevice_NotReadyAndToolOnANonMCPConnection(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	reason := func() string {
		cat, err := e.svc.Catalog(e.ctx(), false)
		e.must(err)
		for _, a := range cat.Items {
			if a.ID == "fgt_ban_ip" {
				if a.Available {
					return ""
				}
				return *a.UnavailableReason
			}
		}
		return "missing"
	}
	if got := reason(); got != "" {
		t.Fatalf("a ready connection: %s", got)
	}
	e.conns.list[0].NotReady = "The connection was never tested. Test it first."
	if got := reason(); !strings.Contains(got, "never tested") {
		t.Fatalf("not ready: %q", got)
	}
	e.conns.list[0].NotReady = ""
	e.exec1(`UPDATE resp_catalog SET tool = 'send_request' WHERE id = 'fgt_ban_ip'`)
	if got := reason(); !strings.Contains(got, "only an MCP server") {
		t.Fatalf("a tool on an HTTP connection: %q", got)
	}
}

// INV-22: a device item made by an older version has no stored steps: it fails with that reason and nothing is sent; so does its undo.
func TestDevice_ItemWithoutExecFails(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	l := e.actions()
	e.exec1(`UPDATE resp_actions SET items = json_remove(items, '$[0].exec') WHERE id = ?`, l[1].ID)
	got, err := e.svc.Approve(e.ctx(), oper, l[1].ID, nil, "")
	e.must(err)
	if it := got.Items[0]; it.Status != response.ItemFailed || it.Result == nil || !strings.Contains(*it.Result, "older version") || e.exec.count() != 0 {
		t.Fatalf("item %+v, %d steps", it, e.exec.count())
	}
	// An item that ran and lost its steps (a restore of an old copy) cannot be undone from here: it stays executed, once logged.
	e.must(func() error { _, err := e.svc.Approve(e.ctx(), oper, l[0].ID, nil, ""); return err }())
	e.exec1(`UPDATE resp_actions SET items = json_remove(items, '$[0].exec') WHERE id = ?`, l[0].ID)
	e.clock.Advance(31 * time.Minute)
	steps := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	e.must(e.svc.Sweep(e.ctx()))
	if it := e.actions()[0].Items[0]; it.Status != response.ItemExecuted || it.Result == nil || !strings.Contains(*it.Result, "older version") || e.exec.count() != steps {
		t.Fatalf("undo of an item without steps: %+v (%d new steps)", it, e.exec.count()-steps)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'failed' AND detail LIKE '%older version%'`); n != 2 {
		t.Fatalf("%d lines about the older version, want 2 (one per item)", n)
	}
}

// D-94 (5), INV-22: what a device printed is compared and dropped. It is in no table, no log line and no result.
func TestDevice_OutputIsNeverStoredOrLogged(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	const marker = "CANARY-DEVICE-OUTPUT-4711"
	e.exec.pre = marker + "\nAdministrative Mode: trunk"
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	e2 := switchRequest(t)
	e2.exec.pre = marker + "\n" + staticAccess
	e2.exec.present = marker + " disabled"
	_, err = e2.svc.Approve(e2.ctx(), oper, e2.only().ID, nil, "")
	e2.must(err)
	for _, x := range []*env{e, e2} {
		for _, q := range []string{`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%` + marker + `%' OR title LIKE '%` + marker + `%'`, `SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%` + marker + `%'`, `SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%` + marker + `%'`} {
			if n := x.count(q); n != 0 {
				t.Fatalf("%s: the device output was kept (%d rows)", q, n)
			}
		}
	}
}

// What the executor says decides what is recorded: nothing sent (nothing changed), refused by the device (nothing changed), unknown (state
// unknown: counts as in force, so the connection cannot be deleted), a connection that changed (a refusal, nothing sent).
func TestDevice_StepStatusesAreRecordedForWhatTheyMean(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status   response.StepStatus
		code     string // log kind
		contains string
		inForce  bool
	}{
		{response.StepNotSent, "failed", "Nothing was changed", false},
		{response.StepFailed, "failed", "was refused by", false},
		{response.StepUnknown, "failed", "State unknown", true},
		{response.StepStatus("surprise"), "failed", "State unknown", true}, // an answer that is not understood may have been applied
		{response.StepConnectionChange, "refused", "connection_changed", false},
	}
	for _, c := range cases {
		e := newEnv(t)
		e.firewall("fgt_ban_ip")
		e.turnOn()
		e.exec.status = map[string]response.StepStatus{"run": c.status}
		e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
		e.fire(e.iocEvent("e1", "198.51.100.7"))
		got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
		e.must(err)
		it := got.Items[0]
		if it.Status != response.ItemFailed || !e.logHas(c.code, c.contains) {
			t.Errorf("%s: item %+v", c.status, it)
		}
		if in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw"); err != nil || in != c.inForce {
			t.Errorf("%s: in force = %v %v, want %v", c.status, in, err, c.inForce)
		}
		// An outcome that is not clear is read back once at once (fgt_ban_ip has a read-back text); the read-back prints nothing here, which
		// settles nothing, so the item stays unknown.
		want := "verify,run" // the read before the run (D-356), then the run
		if c.inForce {
			want = "verify,run,verify"
		}
		if strings.Join(e.exec.phases(), ",") != want {
			t.Errorf("%s: steps %v, want %s", c.status, e.exec.phases(), want)
		}
	}
}

// A check before that cannot be read changed nothing, even when it never answered in time (it only reads): "nothing was changed", never "state unknown".
func TestDevice_PrecheckThatDoesNotAnswerChangedNothing(t *testing.T) {
	t.Parallel()
	e := switchRequest(t)
	e.exec.status = map[string]response.StepStatus{"precheck": response.StepUnknown}
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	it := got.Items[0]
	if it.Status != response.ItemFailed || strings.Contains(*it.Result, "State unknown") || !strings.Contains(*it.Result, "Nothing was changed") {
		t.Fatalf("item: %+v", it)
	}
	if in, _ := e.svc.ChangesInForce(e.ctx(), "cn-sw"); in {
		t.Fatal("a check that did not answer counts as a change in force")
	}
}

// An emergency stop that commits after the approval and before the step goes out means no step at all: the claim reads the switch inside
// its own transaction (INV-9).
func TestDevice_EmergencyStopBeforeTheClaimSendsNothing(t *testing.T) {
	t.Parallel()
	late := &stopOnList{}
	e := newEnv(t, func(c *response.Config) { late.inner = c.Connections; c.Connections = late })
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	late.after = func() { _, err := e.svc.EmergencyStop(e.ctx(), admin); e.must(err) }
	late.armed = true
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if e.exec.count() != 0 || got.Items[0].Status != response.ItemFailed || e.logHas("approved", "Running: ") {
		t.Fatalf("steps %v, item %+v", e.exec.phases(), got.Items[0])
	}
}

// The claim reads the connections again: one that is gone by then (the second read after the approval) stops the step.
func TestDevice_ClaimRefusesAConnectionThatIsGone(t *testing.T) {
	t.Parallel()
	late := &stopOnList{}
	e := newEnv(t, func(c *response.Config) { late.inner = c.Connections; c.Connections = late })
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	late.empty = 3 // approve reads once, runItem once, the claim once: the claim finds none
	late.armed = true
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if e.exec.count() != 0 || got.Items[0].Status != response.ItemFailed || !strings.Contains(*got.Items[0].Result, "no longer exists") || e.logHas("approved", "Running: ") {
		t.Fatalf("steps %v, item %+v", e.exec.phases(), got.Items[0])
	}
}

// 13b-6: an item that ran and whose connection has gone since cannot be undone from here. The sweep does not try again and the item leaves the
// sweep, one line says so in the log, and nothing crashes.
func TestDevice_UndoForAGoneConnectionIsNotRetried(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	_, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	steps := e.exec.count()
	e.conns.list = nil // the connection is gone (deleted, or restored away)
	e.clock.Advance(31 * time.Minute)
	for range 3 {
		e.must(e.svc.Sweep(e.ctx()))
	}
	it := e.only().Items[0]
	if it.Status != response.ItemExecuted || it.Result == nil || !strings.Contains(*it.Result, "no longer exists") || e.exec.count() != steps {
		t.Fatalf("item %+v, %d new steps", it, e.exec.count()-steps)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%no longer exists%'`); n != 1 {
		t.Fatalf("%d log lines about the gone connection, want 1", n)
	}
	if e.count(`SELECT COUNT(*) FROM resp_actions WHERE json_extract(items, '$[0].remove_at') IS NOT NULL`) != 0 {
		t.Fatal("the item is still due for an automatic undo")
	}
}

// A late result for a connection that vanished while the step ran: the result is recorded, the item leaves the sweep, one clear line.
func TestDevice_LateResultForAGoneConnection(t *testing.T) {
	t.Parallel()
	var e *env
	e = newEnv(t, func(c *response.Config) {
		c.Executor = &afterExec{inner: c.Executor, after: func(s response.DeviceStep) {
			if s.Phase == "run" {
				e.conns.list = nil // the connection disappears while the step is in flight
			}
		}}
	})
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemExecuted || got.Items[0].RemoveAt != nil {
		t.Fatalf("item: %+v", got.Items[0])
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'failed' AND detail LIKE '%no longer exists%'`); n != 1 {
		t.Fatalf("%d lines about the gone connection, want 1", n)
	}
	e.clock.Advance(2 * time.Hour)
	for range 2 {
		e.must(e.svc.Sweep(e.ctx()))
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%no longer exists%'`); n != 1 {
		t.Fatalf("the sweep added lines: %d", n)
	}
}

// stopOnList wraps the connection port: after the second read once armed (runItem's, which comes after the approval is committed)
// it runs after, and from the empty-th read on it answers no connection at all.
type stopOnList struct {
	inner response.Connections
	mu    sync.Mutex
	armed bool
	n     int
	after func()
	empty int
}

func (s *stopOnList) List(ctx context.Context) ([]response.ConnectionInfo, error) {
	s.mu.Lock()
	armed := s.armed
	if armed {
		s.n++
	}
	n, after, empty := s.n, s.after, s.empty
	s.mu.Unlock()
	l, err := s.inner.List(ctx)
	if armed && n == 2 && after != nil {
		after()
	}
	if armed && empty > 0 && n >= empty {
		return nil, nil
	}
	return l, err
}

// afterExec runs a function after the executor answered a step: what happens while the step was in flight.
type afterExec struct {
	inner response.Executor
	after func(response.DeviceStep)
}

func (a *afterExec) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	r, err := a.inner.Execute(ctx, s)
	a.after(s)
	return r, err
}
