package response_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// editEnv is a custom HTTP action, a rule that uses it and one pending request made with the template "/q/{ip}".
func editEnv(t *testing.T) (*env, response.CatalogAction, string) {
	t.Helper()
	e := newEnv(t)
	act := e.httpAction("")
	e.turnOn()
	e.rule("Quarantine", "ioc_connection", []response.RuleAction{{ActionID: act.ID, Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	return e, act, e.only().ID
}

// INV-9 (L5): an admin who edits the template or the risk of a custom action cancels the requests that are still open for it: they
// were made, and shown to the approvers, with the old rendering and the old risk. Each is logged; nothing is sent.
func TestContract_INV9_EditingACustomActionCancelsItsOpenRequests(t *testing.T) {
	e, act, id := editEnv(t)
	run := response.Tpl{Method: "POST", Path: "/q2/{ip}"}
	high := response.RiskHigh
	_, err := e.svc.ChangeAction(e.ctx(), admin, act.ID, response.CatalogUpdate{Run: &run, Risk: &high})
	e.must(err)
	got := e.only()
	if got.Status != response.StatusRejected || !e.logHas("rejected", "was edited by") {
		t.Fatalf("the open request is %s; edit logged: %v", got.Status, e.logHas("rejected", "was edited by"))
	}
	_, err = e.svc.Approve(e.ctx(), oper, id, nil, "")
	wantCode(t, err, 409, "not_pending")
	if e.exec.count() != 0 {
		t.Fatal("a step reached the device")
	}
	// the same event asked again after the edit is a new request with the new rendering and the new risk
	e.fire(e.iocEvent("e2", "198.51.100.7"))
	var fresh response.ActionRequest
	for _, a := range e.actions() {
		if a.Status == response.StatusPending {
			fresh = a
		}
	}
	if fresh.ID == "" || fresh.Items[0].Risk != response.RiskHigh || fresh.Items[0].Change.Rest == nil || !strings.Contains(fresh.Items[0].Change.Rest.URL, "/q2/") {
		t.Fatalf("the new request does not carry the edit: %+v", fresh)
	}
}

// INV-9 (L5): the item keeps a fingerprint of the template and the risk it was rendered from. If the catalog differs at approval or at
// run (an edit that did not go through ChangeAction: a restore, another writer) the request refuses with tool_unavailable and the old
// rendering is never sent at the old risk.
func TestContract_INV9_ActionFingerprintMismatchRefusesTheRun(t *testing.T) {
	e, act, id := editEnv(t)
	e.exec1(`UPDATE resp_catalog SET risk = 'high' WHERE id = ?`, act.ID)
	_, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	wantCode(t, err, 409, "tool_unavailable")
	e.exec1(`UPDATE resp_catalog SET risk = 'low' WHERE id = ?`, act.ID)
	got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemExecuted {
		t.Fatalf("an unchanged action did not run: %s %q", got.Items[0].Status, resultOf(got.Items[0]))
	}
	if e.exec.count() == 0 || !strings.Contains(e.exec.steps[0].Rest.URL, "/q/") {
		t.Fatalf("steps: %+v", e.exec.steps)
	}
}
