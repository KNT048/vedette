package response_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// D-356 (INV-22 (k)): the read-back text is read before the run, and only whether it was there is kept. A read-back that settles an unclear
// run counts the change as this step's only when the text was not there before; otherwise the item is not counted and nothing undoes it.

const banned = "CANARY banned: 198.51.100.7" // holds the read-back text of fgt_ban_ip ("198.51.100.7"); the CANARY must never be stored

func (e *env) presentBefore() string {
	e.t.Helper()
	var v any
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT json_extract(items, '$[0].present_before') FROM resp_actions`).Scan(&v))
	switch v {
	case nil:
		return "unset"
	case int64(1):
		return "true"
	case int64(0):
		return "false"
	}
	return "?"
}

func (e *env) noDeviceOutputKept() {
	e.t.Helper()
	for _, q := range []string{`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%CANARY%'`, `SELECT COUNT(*) FROM resp_log WHERE detail LIKE '%CANARY%'`} {
		if e.count(q) != 0 {
			e.t.Fatalf("what the device printed was kept: %s", q)
		}
	}
}

func TestD356_AlreadyThereAndUnclearRunIsNotThisStepsChange(t *testing.T) {
	e := banRequest(t)
	e.exec.after, e.exec.present = banned, banned // the ban is on the device before the run (another admin, another tool)
	e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
	got := e.approveOnly()
	it := got.Items[0]
	if e.phaseList() != "verify,run,verify" {
		t.Fatalf("steps %s, want the read before, the run, the read-back", e.phaseList())
	}
	if it.Status != response.ItemFailed || it.StateUnknown || it.RemoveAt != nil || !strings.Contains(resultOf(it), "already there before this step") ||
		!strings.Contains(resultOf(it), "State unknown") || strings.Contains(resultOf(it), "Nothing was changed") {
		t.Fatalf("item %s %q (state_unknown %v, remove_at %v)", it.Status, resultOf(it), it.StateUnknown, it.RemoveAt)
	}
	if in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw"); err != nil || in {
		t.Fatalf("a change that was there before counts as this step's: %v %v", in, err)
	}
	if e.presentBefore() != "true" || !e.logHas("failed", "already there before this step") {
		t.Fatalf("present_before %s, or the log does not say why", e.presentBefore())
	}
	e.noDeviceOutputKept()
	// Nothing sends an undo of it: the change may be another's.
	e.clock.Advance(2 * time.Hour)
	n := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	if e.exec.count() != n {
		t.Fatalf("the sweep sent %v after the item was settled", e.exec.phases()[n:])
	}
}

func TestD356_NeverThereAndUnclearRunIsApplied(t *testing.T) {
	e := banRequest(t)
	e.exec.present = banned // the read before prints the list without the address; after the run it holds it
	e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
	got := e.approveOnly()
	it := got.Items[0]
	if e.phaseList() != "verify,run,verify" || it.Status != response.ItemExecuted || it.Verified == nil || !it.Verified.OK || it.RemoveAt == nil {
		t.Fatalf("steps %s, item %s %q", e.phaseList(), it.Status, resultOf(it))
	}
	if e.presentBefore() != "false" {
		t.Fatalf("present_before %s", e.presentBefore())
	}
	e.noDeviceOutputKept()
}

// The sweep (resolveUnknown) settles an item the immediate read-back could not, by the same rule. An item with no record of the read before
// (its run predates D-356) is never disowned: it is in force, undoable here, and not undone unattended.
func TestD356_SweepSettlesByTheReadBefore(t *testing.T) {
	for name, tc := range map[string]struct {
		before   string // output of the read before the run; "" = the address is not listed
		drop     bool   // remove present_before, as on an item from an older version
		want     response.ItemStatus
		contains string
		inForce  bool
		ttl      bool // an undo time is set
	}{
		"there before":    {banned, false, response.ItemFailed, "already there before this step", false, false},
		"not there":       {"", false, response.ItemExecuted, "Confirmed by a read-back", true, true},
		"no read before":  {"", true, response.ItemExecuted, "no record of a read before its run", true, false},
		"there, no check": {banned, true, response.ItemExecuted, "no record of a read before its run", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := banRequest(t)
			e.exec.after, e.exec.present = tc.before, banned
			e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown, "readback": response.StepUnknown}
			if it := e.approveOnly().Items[0]; it.Status != response.ItemFailed || !it.StateUnknown {
				t.Fatalf("before the sweep: %s %q", it.Status, resultOf(it))
			}
			if tc.drop {
				e.exec1(`UPDATE resp_actions SET items = json_remove(items, '$[0].present_before')`)
			}
			e.exec.status = nil
			e.must(e.svc.Sweep(e.ctx()))
			it := e.only().Items[0]
			if it.Status != tc.want || it.StateUnknown || !strings.Contains(resultOf(it), tc.contains) {
				t.Fatalf("after the sweep: %s %q (state_unknown %v)", it.Status, resultOf(it), it.StateUnknown)
			}
			if in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw"); err != nil || in != tc.inForce {
				t.Fatalf("in force %v %v, want %v", in, err, tc.inForce)
			}
			if tc.ttl != (it.RemoveAt != nil) {
				t.Fatalf("undo time %v for a %s item", it.RemoveAt, it.Status)
			}
			e.noDeviceOutputKept()
			if tc.inForce { // the undo stays open by hand
				e.exec.after = ""
				got, err := e.svc.Rollback(e.ctx(), oper, e.only().ID)
				e.must(err)
				if got.Items[0].Status != response.ItemRolledBack {
					t.Fatalf("the undo by hand: %s %q", got.Items[0].Status, resultOf(got.Items[0]))
				}
			}
		})
	}
}

// HIGH (review of D-356): present_before is stored before the write goes out, so a restart between the run and its result (the box dies, the
// sweep finds the item still running) settles it as this step's change: in force, with its undo time.
func TestD356_RestartBetweenTheRunAndItsResultKeepsTheUndo(t *testing.T) {
	for name, tc := range map[string]struct {
		before  string
		inForce bool
	}{
		"not there before": {"", true},
		"there before":     {banned, false},
	} {
		t.Run(name, func(t *testing.T) {
			var e *env
			var snapshot string
			e = newEnv(t, func(c *response.Config) {
				c.Executor = &afterExec{inner: c.Executor, after: func(s response.DeviceStep) {
					if s.Phase == "run" { // what the database holds while the write is on its way: what a crash leaves
						e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT items FROM resp_actions`).Scan(&snapshot))
					}
				}}
			})
			e.firewall("fgt_ban_ip")
			e.turnOn()
			e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(30)}}, nil)
			e.fire(e.iocEvent("e1", "198.51.100.7"))
			e.exec.after, e.exec.present = tc.before, banned
			id := e.approveOnly().ID
			if !strings.Contains(snapshot, `"present_before":`) || !strings.Contains(snapshot, `"running_at":`) {
				t.Fatalf("present_before is not stored before the run: %s", snapshot)
			}
			e.exec1(`UPDATE resp_actions SET status = 'approved', decided_at = ?, items = ? WHERE id = ?`, e.at(-10*time.Minute), snapshot, id) // the restart
			e.exec1(`UPDATE resp_actions SET items = json_set(items, '$[0].running_at', ?) WHERE id = ?`, e.at(-5*time.Minute), id)
			e.must(e.svc.Sweep(e.ctx()))
			it := e.only().Items[0]
			in, err := e.svc.ChangesInForce(e.ctx(), "cn-fw")
			e.must(err)
			if in != tc.inForce || it.StateUnknown || (it.Status == response.ItemExecuted) != tc.inForce || (it.RemoveAt != nil) != tc.inForce {
				t.Fatalf("after the restart and the sweep: %s %q (in force %v, remove_at %v)", it.Status, resultOf(it), in, it.RemoveAt)
			}
		})
	}
}

// MEDIUM (review of D-356): a run that answers clearly over a change that was already there is recorded, but not undone at the end of its
// undo time (it may be another's); the result says so, and the undo by hand stays open.
func TestD356_ClearRunOverAChangeAlreadyThereGetsNoUndoTime(t *testing.T) {
	e := banRequest(t)
	e.exec.after, e.exec.present = banned, banned
	it := e.approveOnly().Items[0]
	if it.Status != response.ItemExecuted || it.RemoveAt != nil || !strings.Contains(resultOf(it), "already there before this step, so it is not undone automatically") {
		t.Fatalf("item %s %q, remove_at %v", it.Status, resultOf(it), it.RemoveAt)
	}
	e.clock.Advance(2 * time.Hour)
	n := e.exec.count()
	e.must(e.svc.Sweep(e.ctx()))
	if e.exec.count() != n || e.only().Items[0].Status != response.ItemExecuted {
		t.Fatalf("the sweep undid a change that was there before: %v", e.exec.phases()[n:])
	}
	e.exec.after = ""
	got, err := e.svc.Rollback(e.ctx(), oper, e.only().ID)
	e.must(err)
	if got.Items[0].Status != response.ItemRolledBack {
		t.Fatalf("the undo by hand: %s %q", got.Items[0].Status, resultOf(got.Items[0]))
	}
}

// When the check before is the read-back's own read, its output is used: no second read goes out.
func TestD356_TheCheckBeforeIsTheReadWhenItIsTheSameStep(t *testing.T) {
	e := precheckEnv(t)
	in := apiAction()
	in.Precheck = response.Tpl{Method: "GET", Path: "/d/{domain}"}
	in.PrecheckRefuse = []string{"locked"}
	in.Verify = response.Tpl{Method: "GET", Path: "/d/{domain}", Expect: "{domain}"}
	act, err := e.svc.AddAction(e.ctx(), admin, in)
	e.must(err)
	e.turnOn()
	e.rule("Block", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"domain": "{{trigger.dest_domain}}"}, TTLMin: intp(60)}}, nil)
	ev := e.iocEvent("e1", "198.51.100.7")
	ev.Fields["dest_domain"] = "bad.example.com"
	e.fire(ev)
	e.exec.pre, e.exec.present = "CANARY bad.example.com", "CANARY bad.example.com"
	e.exec.status = map[string]response.StepStatus{"run": response.StepUnknown}
	got := e.approveOnly()
	it := got.Items[0]
	if e.phaseList() != "precheck,run,verify" || it.Status != response.ItemFailed || !strings.Contains(resultOf(it), "already there before this step") || e.presentBefore() != "true" {
		t.Fatalf("steps %s, item %s %q, present_before %s", e.phaseList(), it.Status, resultOf(it), e.presentBefore())
	}
	e.noDeviceOutputKept()
}

// A device that does not answer the read before the run gets no write, like a check before that does not answer.
func TestD356_ReadBeforeThatDoesNotAnswerSendsNothingToWrite(t *testing.T) {
	e := banRequest(t)
	e.exec.status = map[string]response.StepStatus{"verify": response.StepUnknown}
	got := e.approveOnly()
	it := got.Items[0]
	if e.phaseList() != "verify" || it.Status != response.ItemFailed || it.StateUnknown || !strings.Contains(resultOf(it), "Nothing was changed") {
		t.Fatalf("steps %s, item %s %q", e.phaseList(), it.Status, resultOf(it))
	}
}
