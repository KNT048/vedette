package response_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/modules/response"
)

// A finding that goes to another device with its software line takes what is still to be decided about it there: the events the rules
// have not run on yet name the device the finding is on now (and that device's name). Its plan is retired
// (TestFindingMovedRetiresThePlanAndANewOneIsWritten) and its pending request is withdrawn on the device it was made for
// (TestFindingMovedWithdrawsThePendingRequest). What was already decided or done keeps the
// device it was about: an approved, executed, rejected or expired request and an event the rules already ran on are history. Rows of
// another finding, or of this finding on a third device, do not move.
func TestFindingMovedTakesWhatIsPendingAndKeepsHistory(t *testing.T) {
	e := newEnv(t)
	e.dir.devices["a-new"] = response.DeviceInfo{ID: "a-new", Name: "web-02", IP: "192.0.2.42", Kind: "server"}
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES
		('plan-f1','f1','CVE-2024-0001','a-old','nas-01','2026-11-09T09:00:00.000Z','m','p','path','[]','[]'),
		('plan-f2','f2','CVE-2024-0002','a-old','nas-01','2026-11-09T09:00:00.000Z','m','p','path','[]','[]')`)
	for _, r := range []struct{ id, finding, asset, status string }{
		{"r-pending", "f1", "a-old", "pending"},
		{"r-approved", "f1", "a-old", "approved"},
		{"r-executed", "f1", "a-old", "executed"},
		{"r-rejected", "f1", "a-old", "rejected"},
		{"r-expired", "f1", "a-old", "expired"},
		{"r-other", "f2", "a-old", "pending"},
		{"r-third", "f1", "a-third", "pending"},
	} {
		e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES (?, 'ai', 'p', ?, 'CVE-2024-0001', ?, 'nas-01', 't', 'low', ?, '2026-11-09T09:00:00.000Z', '2026-11-10T09:00:00.000Z', 1, '[]')`,
			r.id, r.finding, r.asset, r.status)
	}
	e.exec1(`INSERT INTO resp_events (id, trigger, ts, summary, fields, asset_id, finding_id, cve, processed) VALUES
		('ev-waiting','finding','2026-11-09T09:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','a-old','f1','CVE-2024-0001',0),
		('ev-done','finding','2026-11-09T08:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','a-old','f1','CVE-2024-0001',1)`)

	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-new"})
	}); err != nil {
		t.Fatal(err)
	}

	device := func(table, id string) string {
		t.Helper()
		var asset, name string
		q := `SELECT asset_id, fields ->> '$.device' || ' ' || (fields ->> '$.ip') FROM ` + table + ` WHERE id = ?`
		if table != "resp_events" {
			q = `SELECT asset_id, asset_name FROM ` + table + ` WHERE id = ?`
		}
		if err := e.db.Reader().QueryRowContext(e.ctx(), q, id).Scan(&asset, &name); err != nil {
			t.Fatal(err)
		}
		if name != "" {
			return asset + "/" + name
		}
		return asset
	}
	for _, c := range []struct{ table, id, want string }{
		{"resp_plans", "plan-f2", "a-old/nas-01"},
		{"resp_actions", "r-pending", "a-old/nas-01"},
		{"resp_actions", "r-approved", "a-old/nas-01"},
		{"resp_actions", "r-executed", "a-old/nas-01"},
		{"resp_actions", "r-rejected", "a-old/nas-01"},
		{"resp_actions", "r-expired", "a-old/nas-01"},
		{"resp_actions", "r-other", "a-old/nas-01"},
		{"resp_actions", "r-third", "a-third/nas-01"},
		{"resp_events", "ev-waiting", "a-new/web-02 192.0.2.42"}, // a rule reads the device's name and address from the event
		{"resp_events", "ev-done", "a-old/nas-01 192.0.2.10"},
	} {
		if got := device(c.table, c.id); got != c.want {
			t.Errorf("%s %s: on %s, want %s", c.table, c.id, got, c.want)
		}
	}
	if n := e.count(`SELECT count(*) FROM resp_events WHERE id = 'ev-waiting' AND device_kind = 'server'`); n != 1 {
		t.Error("the waiting event kept the kind of the device the finding left")
	}
	if n := e.count(`SELECT count(*) FROM resp_plans WHERE id = 'plan-f1'`); n != 0 {
		t.Error("the plan written for the device the finding left was kept")
	}
}

// When the directory does not know the device the finding went to (a split creates it in the same write, which a reader does not see
// yet), the waiting event still follows the finding but keeps no name, kind or address of the device it left: a rule that names the
// address finds none and is refused, never run on the old device's address under the new device's id.
func TestFindingMovedToAnUnknownDeviceKeepsNoAddressOfTheOldOne(t *testing.T) {
	e := newEnv(t)
	e.exec1(`INSERT INTO resp_events (id, trigger, ts, summary, fields, device_kind, asset_id, finding_id, cve, processed) VALUES
		('ev-waiting','finding','2026-11-09T09:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','nas','a-old','f1','CVE-2024-0001',0)`)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-split"})
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM resp_events WHERE id = 'ev-waiting' AND asset_id = 'a-split' AND processed = 0 AND device_kind IS NULL
		AND fields ->> '$.device' = '' AND fields ->> '$.ip' = '' AND fields ->> '$.cve' = 'CVE-2024-0001'`); n != 1 {
		t.Fatal("the waiting event did not follow the finding without the old device's name, kind and address")
	}
}

// A request still waiting for a decision holds the items it was rendered with, the old device's address among them. When its finding
// moves to another device, approving it would act on the old address under the new device's name, so it is withdrawn instead: it
// ends without a decision, keeps the device it was made for, says why, and is logged and audited. Approving it afterwards changes
// nothing on any device; a new request is asked for from the finding's plan, which is checked against the device the finding is on now.
func TestFindingMovedWithdrawsThePendingRequest(t *testing.T) {
	t.Parallel()
	e, _, id := editEnv(t)
	e.dir.devices["a-new"] = response.DeviceInfo{ID: "a-new", Name: "web-02", IP: "192.0.2.42", Kind: "server"}
	e.exec1(`UPDATE resp_actions SET finding_id = 'f1', asset_id = 'a-old' WHERE id = ?`, id)
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-new"})
	}); err != nil {
		t.Fatal(err)
	}
	got := e.only()
	if got.Status != response.StatusExpired || got.Note == nil || !strings.Contains(*got.Note, "moved to web-02") {
		t.Fatalf("the moved finding's pending request is %s (note %v), want it withdrawn with the reason", got.Status, got.Note)
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE id = ? AND asset_id = 'a-old'`, id); n != 1 {
		t.Error("the withdrawn request left the device it was made for")
	}
	for _, it := range got.Items {
		if it.Status != response.ItemSkipped {
			t.Errorf("item %s is %s, want skipped", it.ID, it.Status)
		}
	}
	if !e.logHas("expired", "moved to web-02") {
		t.Error("the withdrawal is not in the response log")
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'response.expire' AND target = ? AND detail LIKE '%moved to web-02%'`, id); n != 1 {
		t.Error("the withdrawal has no audit row")
	}
	_, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	wantCode(t, err, 409, "withdrawn")
	if e.exec.count() != 0 {
		t.Fatal("approving the withdrawn request reached a device")
	}
}

// The rules run on a batch of waiting events read before any of them is handled. When a finding moves to another device while the
// batch is being worked through, the rule must run on the event as it is stored now (moved to the finding's new device, with that
// device's name and address), not on the copy read before the move: a request made from the stale copy would act on the old address
// after the pending requests about the finding were withdrawn.
func TestFindingMovedWhileTheRulesRunUsesTheMovedEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.dir.devices["a-new"] = response.DeviceInfo{ID: "a-new", Name: "web-02", IP: "192.0.2.42", Kind: "server"}
	e.rule("Tell me about IOCs", "ioc_connection", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "ioc {{trigger.dest_ip}}"}}}, nil)
	e.rule("Tell me about findings", "finding", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.device}} {{trigger.ip}}"}}}, nil)
	e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("e1", "198.51.100.7")))
	e.exec1(`INSERT INTO resp_events (id, trigger, ts, summary, fields, asset_id, finding_id, cve, processed) VALUES
		('ev-f1','finding','2026-11-09T09:00:00.000Z','s','{"device":"nas-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','a-old','f1','CVE-2024-0001',0)`)
	// the split lands after the first event's request is made and before the finding's event is handled
	moved := false
	e.bus.Subscribe(response.EventRequestCreated, func(ctx context.Context, _ events.Event) error {
		if moved {
			return nil
		}
		moved = true
		return e.db.Write(ctx, func(tx *sql.Tx) error {
			return e.svc.FindingMoved(ctx, tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-new"})
		})
	})
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	e.svc.WaitSendsForTest()
	if !moved {
		t.Fatal("the finding was not moved during the run")
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE finding_id = 'f1' AND asset_id = 'a-old' AND status = 'pending'`); n != 0 {
		t.Fatal("a request about the finding was made on the device it left, from the event as it was read before the move")
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE finding_id = 'f1' AND asset_id = 'a-new' AND items LIKE '%web-02 192.0.2.42%'`); n != 1 {
		t.Fatal("the rule did not run on the moved event (the finding's new device and its address)")
	}
}

// The plan of a finding holds proposals built for the address of the device it was written for. When the finding moves to another
// device, that plan is retired (logged and audited) in the same write: its proposals can no longer be requested, and the planner writes
// a new plan for the finding on its new device through the normal path, whose proposal is requested against the new device.
func TestFindingMovedRetiresThePlanAndANewOneIsWritten(t *testing.T) {
	t.Parallel()
	e, fp, targets := aiPlanEnv(t)
	e.turnOn()
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	pl, err := e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	if len(pl.Items) != 1 || pl.Items[0].Steps[0].Proposal == nil {
		t.Fatalf("no plan with a proposal for f2: %+v", pl)
	}
	oldPlan, oldProp := pl.Items[0].ID, pl.Items[0].Steps[0].Proposal.ID
	old, err := e.svc.RequestProposal(e.ctx(), oper, oldProp)
	e.must(err)

	e.dir.devices["a2"] = response.DeviceInfo{ID: "a2", Name: "web-02", IP: "192.0.2.42", Approved: true}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f2", From: "a1", Into: "a2"})
	}); err != nil {
		t.Fatal(err)
	}
	e.dir.findings["f2"] = response.FindingInfo{ID: "f2", AssetID: "a2", CVE: "CVE-2024-0002", Severity: "critical", Status: "confirmed"}
	for i := range *targets {
		if (*targets)[i].FindingID == "f2" {
			(*targets)[i].AssetID, (*targets)[i].AssetName, (*targets)[i].AssetIP, (*targets)[i].AssetKind = "a2", "web-02", "192.0.2.42", "server"
		}
	}
	fp.steps = func(t response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{{Kind: "contain", Title: "Block the address", Detail: "Add it to the block list.", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: t.AssetIP}}}}
	}

	if n := e.count(`SELECT count(*) FROM resp_plans WHERE id = ?`, oldPlan); n != 0 {
		t.Fatal("the plan written for the old device was kept")
	}
	if !e.logHas("proposal", "moved to web-02") || e.count(`SELECT count(*) FROM core_audit WHERE action = 'response.plan_retired' AND target = ?`, oldPlan) != 1 {
		t.Error("retiring the plan is not in the response log and the audit")
	}
	var note string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT note FROM resp_actions WHERE id = ? AND status = 'expired'`, old.ID).Scan(&note))
	if !strings.Contains(note, "new plan") {
		t.Errorf("the withdrawal note does not point at the new plan: %q", note)
	}
	_, err = e.svc.RequestProposal(e.ctx(), oper, oldProp)
	wantCode(t, err, 404, "not_found")

	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	pl, err = e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	if len(pl.Items) != 1 || pl.Items[0].AssetID != "a2" || pl.Items[0].Steps[0].Proposal == nil {
		t.Fatalf("no new plan for the finding on its new device: %+v", pl)
	}
	req, err := e.svc.RequestProposal(e.ctx(), oper, pl.Items[0].Steps[0].Proposal.ID)
	e.must(err)
	if req.Status != response.StatusPending || req.AssetID == nil || *req.AssetID != "a2" ||
		e.count(`SELECT count(*) FROM resp_actions WHERE id = ? AND items LIKE '%192.0.2.42%'`, req.ID) != 1 {
		t.Fatalf("the request from the new plan is not about the new device: %+v", req)
	}
}

// A split moves a finding to the device it creates, inside the write that creates it, where response cannot read that device. The
// split names it (lifecycle.FindingMove IntoName, IntoIP), so the finding's waiting event takes the new device's name and address
// there, and nothing of the old device's; its kind, which the split does not carry, is read when the rules come to the event, after
// the split committed. The automatic response then runs on the new device exactly as on an event made for it: a rule that tests the
// device type and names the device and its address makes its request about the device split off.
func TestASplitGivesTheMovedFindingEventItsDeviceAndTheResponseRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.rule("Tell me about camera findings", "finding", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.device}} {{trigger.ip}}"}}},
		func(in *response.RuleInput) {
			in.Conditions = []response.Condition{{Op: "device_type", Value: "camera"}}
		})
	e.exec1(`INSERT INTO resp_events (id, trigger, ts, summary, fields, device_kind, asset_id, finding_id, cve, processed) VALUES
		('ev-f1','finding','2026-11-09T09:00:00.000Z','s','{"device":"nvr-01","ip":"192.0.2.10","cve":"CVE-2024-0001"}','nvr','a-old','f1','CVE-2024-0001',0)`)

	// inside the split's write: the directory does not know a-split yet
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.FindingMoved(e.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-split", IntoName: "camera-02", IntoIP: "192.0.2.42"})
	}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM resp_events WHERE id = 'ev-f1' AND asset_id = 'a-split' AND processed = 0 AND device_kind IS NULL
		AND fields ->> '$.device' = 'camera-02' AND fields ->> '$.ip' = '192.0.2.42'`); n != 1 {
		t.Fatal("the waiting event did not take the name and address of the device split off, or kept the old device's kind")
	}

	// the split committed: the directory knows the new device and its kind
	e.dir.devices["a-split"] = response.DeviceInfo{ID: "a-split", Name: "camera-02", IP: "192.0.2.42", Kind: "camera"}
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	e.svc.WaitSendsForTest()
	if n := e.count(`SELECT count(*) FROM resp_events WHERE id = 'ev-f1' AND device_kind = 'camera' AND processed = 1`); n != 1 {
		t.Error("the event did not take the kind of the device split off before the rules ran")
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE finding_id = 'f1' AND asset_id = 'a-split' AND items LIKE '%camera-02 192.0.2.42%'`); n != 1 {
		t.Fatal("the automatic response did not run on the device split off")
	}
	if n := e.count(`SELECT count(*) FROM resp_actions WHERE items LIKE '%192.0.2.10%' OR items LIKE '%nvr-01%'`); n != 0 {
		t.Fatal("a request names the device the finding left")
	}
}

// Every way a request can end answers its Approve and Reject the same plain way, whichever way the decision comes (the app, a Slack
// or Telegram button, a Zalo reply code, an email link), and changes nothing: a request a device split withdrew says so and points
// to the request made for the finding on the device split off; an expired one says it expired; a decided one says how it was decided.
func TestEveryEndedRequestAnswersItsButtonsTheSameWay(t *testing.T) {
	t.Parallel()
	type answer struct{ code, msg string }
	ask := func(t *testing.T, c *chatEnv, id string) map[string]answer {
		t.Helper()
		c.mintCodeRaw(id, "A-7KQ2MX", true) // alive now, as a code sent before the request ended would be
		link := c.mintRaw(id, "u-op", "it@acme.example")
		got := map[string]answer{}
		for way, call := range map[string]func() error{
			"app":      func() error { _, err := c.svc.Approve(c.ctx(), oper, id, nil, ""); return err },
			"slack":    func() error { _, err := c.button("slack", slackOp, id, true); return err },
			"telegram": func() error { _, err := c.button("telegram", tgOp, id, false); return err },
			"zalo":     func() error { _, err := c.typed(zlOp, "A-7KQ2MX", true); return err },
			"link":     func() error { _, err := c.decide(link, "approve"); return err },
		} {
			ae, ok := apierr.As(call())
			if !ok || ae.Status != 409 {
				t.Fatalf("%s: answered %v, want a 409", way, ae)
			}
			got[way] = answer{ae.Code, ae.Message}
		}
		if c.exec.count() != 0 || c.tokenUsed() != 0 {
			t.Fatal("a decision on an ended request reached a device or burned a token")
		}
		return got
	}
	same := func(t *testing.T, got map[string]answer, app, outside string) string {
		t.Helper()
		msg := got["app"].msg
		for way, a := range got {
			want := outside
			if way == "app" {
				want = app
			}
			if a.code != want || a.msg != msg {
				t.Errorf("%s answered %s %q, want %s %q", way, a.code, a.msg, want, msg)
			}
		}
		return msg
	}

	t.Run("withdrawn by a split", func(t *testing.T) {
		t.Parallel()
		c := newChatEnv(t)
		a := c.pending()
		c.exec1(`UPDATE resp_actions SET finding_id = 'f1', asset_id = 'a-old' WHERE id = ?`, a.ID)
		c.must(c.db.Write(c.ctx(), func(tx *sql.Tx) error {
			return c.svc.FindingMoved(c.ctx(), tx, lifecycle.FindingMove{Finding: "f1", From: "a-old", Into: "a-split", IntoName: "camera-02", IntoIP: "192.0.2.42"})
		}))
		if n := c.count(`SELECT count(*) FROM resp_actions WHERE id = ? AND end_reason = 'split'`, a.ID); n != 1 {
			t.Fatal("the withdrawn request does not store why it ended")
		}
		// the split committed: the finding is on the device split off
		c.dir.devices["a-split"] = response.DeviceInfo{ID: "a-split", Name: "camera-02", IP: "192.0.2.42", Kind: "camera"}
		c.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a-split", CVE: "CVE-2024-0001", Severity: "high", Status: "confirmed"}
		msg := same(t, ask(t, c, a.ID), "withdrawn", "withdrawn")
		for _, want := range []string{"withdrawn without a decision", "moved to camera-02 after a device split", "Nothing was changed", "ask again from that plan"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the answer %q does not say %q", msg, want)
			}
		}
		// the request made since for the finding on the device split off is named
		c.exec1(`INSERT INTO resp_actions (id, source, proposal_id, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES ('r-new', 'rule', 'p', 'f1', 'CVE-2024-0001', 'a-split', 'camera-02', 'Block the camera-02 web port', 'low', 'pending', ?, '2099-01-01T00:00:00.000Z', 1, '[]')`,
			c.clock.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z"))
		_, err := c.button("slack", slackOp, a.ID, true)
		ae, _ := apierr.As(err)
		if ae == nil || ae.Code != "withdrawn" || !strings.Contains(ae.Message, "A new request for it is waiting for a decision: Block the camera-02 web port.") || ae.Extra["new_request_id"] != "r-new" {
			t.Fatalf("the answer %v does not point to the new request", ae)
		}
		if n := c.count(`SELECT count(*) FROM resp_actions WHERE id = ? AND status = 'expired' AND approvals = '[]'`, a.ID); n != 1 {
			t.Fatal("the withdrawn request was decided")
		}
		v := c.view(c.mintRaw(a.ID, "u-op", "it@acme.example"))
		if v.State != "withdrawn" || len(v.Items) != 0 {
			t.Errorf("the link page shows %s with %d items, want withdrawn and nothing of the request", v.State, len(v.Items))
		}
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		c := newChatEnv(t)
		a := c.pending()
		c.clock.Advance(16 * time.Minute)
		c.must(c.svc.Sweep(c.ctx()))
		if msg := same(t, ask(t, c, a.ID), "expired", "expired"); !strings.Contains(msg, "expired") || !strings.Contains(msg, "Nothing was changed") {
			t.Errorf("the answer %q does not say the request expired and nothing changed", msg)
		}
	})
	t.Run("decided", func(t *testing.T) {
		t.Parallel()
		c := newChatEnv(t)
		a := c.pending()
		_, err := c.svc.Reject(c.ctx(), oper2, a.ID, "", response.RememberNone)
		c.must(err)
		if msg := same(t, ask(t, c, a.ID), "not_pending", "decided"); !strings.Contains(msg, "already rejected") || !strings.Contains(msg, "changed nothing") {
			t.Errorf("the answer %q does not say the request was rejected and this changed nothing", msg)
		}
	})
}
