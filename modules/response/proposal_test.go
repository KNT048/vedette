package response_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// INV-15 (H1): a stored proposal cannot smuggle text. A {text} value with shell characters is refused by its type; a stray "text" or
// "cli" key on a device action is ignored (only the catalog template's placeholders are read); no device action can take {text}.
func TestContract_INV15_ProposalTextCannotReachACommand(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "msg_send", response.CatalogUpdate{Enabled: &on, AIMayPropose: &on})
	e.must(err)
	e.plan("plan-1", `{"id":"pr-msg","action_id":"msg_send","params":{"text":"hi; reboot $(id)"},"asset_id":"a-nas"}`)
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-msg")
	wantCode(t, err, 400, "invalid_target")
	e.plan("plan-2", `{"id":"pr-extra","action_id":"fgt_ban_ip","params":{"ip":"192.168.10.21","text":"execute reboot","cli":"execute factoryreset"},"ttl_min":1440,"asset_id":"a-nas"}`)
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-extra")
	e.must(err)
	if c := a.Items[0].Change; contains(c.CLI, "reboot") || contains(c.CLI, "factoryreset") || response.HasShellChar(c.CLI) {
		t.Fatalf("stray keys reached the change: %+v", c)
	}
	cat, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, x := range cat.Items {
		for _, p := range x.Params {
			if p == response.PText && x.Device {
				t.Errorf("device action %s takes {text}", x.ID)
			}
		}
	}
	_, err = e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Text in a command", ConnectionID: "cn-fw",
		Run: response.Tpl{Method: "POST", Path: "/x", Body: `{"a":"{text}"}`}, Rollback: response.Tpl{Method: "POST", Path: "/y", Body: `{"a":"{text}"}`}, Risk: response.RiskLow, Enabled: true})
	wantCode(t, err, 400, "invalid")
}

// INV-15 (2) (L1): the AI proposes only the actions the admin allowed it to (ai_may_propose). A stored proposal for an action without
// the flag is refused 403 tool_not_allowed: it does not become a request, count towards the breaker or fill the queue.
func TestContract_INV15_ProposalNeedsAIMayPropose(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	off, on := false, true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{AIMayPropose: &off})
	e.must(err)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_ban_ip","params":{"ip":"192.168.10.21"},"ttl_min":1440,"asset_id":"a-nas","asset_name":"NAS"}`)
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 403, "tool_not_allowed")
	if e.requests() != 0 || e.exec.count() != 0 {
		t.Fatalf("a refused proposal left %d request(s)", e.requests())
	}
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	if _, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1"); err != nil {
		t.Fatalf("a proposal for an action the AI may propose was refused: %v", err)
	}
}

// INV-10, INV-15 (L2): the subject of a proposal is the asset of the finding (the directory's word), never the asset_id the AI wrote
// into the proposal: naming another device cannot move the never-touch check off the device the plan is about. A directory that
// cannot answer refuses (fail closed).
func TestContract_INV10_ProposalSubjectIsTheFindingsAsset(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	e.dir.devices["a-other"] = response.DeviceInfo{ID: "a-other", Name: "Printer", IP: "192.168.10.99", Approved: true}
	_, err = e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "192.168.10.21", Label: "NAS"}}) // the finding's asset
	e.must(err)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_ban_ip","params":{"ip":"192.168.10.21"},"ttl_min":1440,"asset_id":"a-other","asset_name":"Printer"}`)
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "never_touch")
	_, err = e.svc.SetAllowlist(e.ctx(), admin, nil)
	e.must(err)
	e.dir.deviceErr = errors.New("inventory unavailable")
	_, err = e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	wantCode(t, err, 409, "never_touch")
	if e.requests() != 0 {
		t.Fatalf("%d request(s) left by refused proposals", e.requests())
	}
	e.dir.deviceErr = nil
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	e.must(err)
	if a.AssetID == nil || *a.AssetID != "a-nas" {
		t.Fatalf("the request is about %v, want the finding's asset a-nas", a.AssetID)
	}
}

// Race detector pass over the lifecycle paths that share mu/execMu and none (EmergencyStop): concurrent approvals of several
// requests, an emergency stop, a breaker reset, the sweep and reads. The chain must still verify and no item may be left
// "running" once everything returned.
func TestConcurrentApproveStopResetSweepKeepsTheChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firewall("fgt_ban_ip")
	e.turnOn()
	e.rule("Ban and block", "ioc_connection", banAndBlock(), nil)
	for i, ip := range []string{"198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10"} {
		ev := e.iocEvent("e"+itoaTest(i), ip)
		ev.Fields["src_ip"] = "203.0.113." + itoaTest(10+i)
		e.fire(ev)
	}
	reqs := e.actions()
	if len(reqs) != 4 {
		t.Fatalf("%d requests", len(reqs))
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Go(func() { _, _ = e.svc.Approve(ctx, oper, r.ID, nil, "") })
	}
	wg.Go(func() { _, _ = e.svc.EmergencyStop(ctx, oper) })
	wg.Go(func() { _, _ = e.svc.ResetBreaker(ctx, admin) })
	wg.Go(func() { _ = e.svc.Sweep(ctx) })
	wg.Go(func() { _, _ = e.svc.Actions(ctx) })
	wg.Wait()
	if r, err := e.svc.VerifyLog(e.ctx()); err != nil || !r.OK {
		t.Fatalf("verify = %+v, %v", r, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%running_at%'`); n != 0 {
		t.Fatalf("%d request(s) left an item running", n)
	}
}
