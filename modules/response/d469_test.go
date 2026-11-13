package response_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// D-469 (INV-17): the block list publishes public addresses only, so a blocklist_add on any other address is refused when it is
// planned, with not_publishable and a refused line, on every path; one planned before the check is refused again before it runs.

const privIP = "192.168.1.5"

func notPublishableLogged(e *env) bool {
	return e.logHas("refused", "not_publishable: ") && e.logHas("refused", privIP+" is not a public address")
}

func TestD469_RuleRunRefusesAPrivateBlock(t *testing.T) {
	t.Parallel()
	// (loopback, link-local, multicast and 0/8, 240/4 are already refused by the type check, invalid_target)
	for _, ip := range []string{privIP, "10.0.0.5", "172.16.4.4", "100.64.0.1", "192.0.0.8", "198.18.0.1", "fd00::5", "2001:db8::1"} {
		t.Run(ip, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.rule("Block", "ioc_connection", blockAction(60), nil)
			sum := e.fire(e.iocEvent("e1", ip))
			if sum.Refused != 1 || len(e.actions()) != 0 {
				t.Fatalf("summary %+v, %d requests: want one refusal and no request", sum, len(e.actions()))
			}
			if !e.logHas("refused", "not_publishable: Block: "+ip+" is not a public address") {
				t.Fatal("no refused line with not_publishable")
			}
		})
	}
	// A public address still plans (the IPv4 documentation blocks count as public, INV-17).
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	if sum := e.fire(e.iocEvent("e1", "198.51.100.7")); sum.Requests != 1 || e.logHas("refused", "not_publishable") {
		t.Fatalf("a public address was refused: %+v", sum)
	}
}

// A block that would do nothing is not a safety refusal: only that action is dropped, the rule's other actions still go ahead.
func TestD469_OnlyTheBlockIsDroppedTheMessageStillGoes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block and tell", "ioc_connection", append(blockAction(60), response.RuleAction{ActionID: "msg_send", Params: map[string]string{"text": "Bad connection from {{trigger.device}}"}}), nil)
	sum := e.fire(e.iocEvent("e1", privIP))
	a := e.only()
	if sum.Requests != 1 || sum.Refused != 1 || len(a.Items) != 1 || a.Items[0].ActionID != "msg_send" || !notPublishableLogged(e) {
		t.Fatalf("summary %+v, request %+v", sum, a.Items)
	}
}

func TestD469_ManualRunSimulationAndSaveRefuseAPrivateBlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-HR-01", IP: privIP, Kind: "pc", Approved: true}
	r := e.rule("Block this PC", "manual", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.ip}}"}, TTLMin: intp(60)}}, nil)
	sum, err := e.svc.RunManual(e.ctx(), oper, r.ID, "a-pc")
	e.must(err)
	if sum.Refused != 1 || len(e.actions()) != 0 || !notPublishableLogged(e) {
		t.Fatalf("manual run: %+v, %d requests", sum, len(e.actions()))
	}
	in := func(ip string) response.RuleInput {
		return response.RuleInput{Name: "Block", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{},
			Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": ip}, TTLMin: intp(60)}}, MaxPerHour: 5}
	}
	// A fixed private address is refused when the rule is saved (and simulated); a trigger field is known only when the rule runs.
	_, err = e.svc.AddRule(e.ctx(), admin, in(privIP))
	wantCode(t, err, 400, "not_publishable")
	_, err = e.svc.Simulate(e.ctx(), oper, in(privIP), "")
	wantCode(t, err, 400, "not_publishable")
	e.must(e.svc.StoreEvent(e.ctx(), e.iocEvent("e9", privIP)))
	sim, err := e.svc.Simulate(e.ctx(), oper, in("{{trigger.dest_ip}}"), "e9")
	e.must(err)
	if len(sim.Steps) != 1 || sim.Steps[0].OK || sim.Steps[0].Error == nil || !strings.HasPrefix(*sim.Steps[0].Error, privIP+" is not a public address") {
		t.Fatalf("simulation step: %+v", sim.Steps)
	}
}

func TestD469_AIProposalRefusesAPrivateBlock(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	b := lowBody()
	b.Params = map[string]string{"ip": privIP}
	_, err := e.propose(b)
	wantCode(t, err, 409, "not_publishable")
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || !notPublishableLogged(e) {
		t.Fatal("a request was made or the refusal is not logged")
	}
}

// The plan job does not offer the block list action for a device on a LAN address (a plan proposing it would be refused whole and
// back the finding off), so the plan of a LAN device is still stored; a device on a public address is still offered it.
func TestD469_AIPlanOfALANDeviceIsNotOfferedTheBlockList(t *testing.T) {
	t.Parallel()
	e, fp, targets := aiPlanEnv(t)
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: privIP, Approved: true}
	for i := range *targets {
		(*targets)[i].AssetIP = privIP
	}
	fp.steps = func(response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{{Kind: "check", Title: "Check", Detail: "Look for signs of compromise."}, {Kind: "patch", Title: "Patch", Detail: "Install the vendor fix."}}
	}
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 2 || e.logHas("refused", "plan_invalid") {
		t.Fatalf("saved %d plans for a LAN device, want 2", n)
	}
	offered := func(i int) bool {
		for _, a := range fp.acts[i] {
			if a.ID == "blocklist_add" {
				return true
			}
		}
		return false
	}
	if len(fp.acts) == 0 || offered(0) {
		t.Fatal("the block list action was offered for a LAN device")
	}
	e2, fp2, _ := aiPlanEnv(t) // the fixture device is on a public address
	_, err = e2.svc.PlanOpen(e2.ctx())
	e2.must(err)
	if len(fp2.acts) == 0 || !func() bool {
		for _, a := range fp2.acts[0] {
			if a.ID == "blocklist_add" {
				return true
			}
		}
		return false
	}() {
		t.Fatal("the block list action is not offered for a device on a public address")
	}
}

// A plan stored before the check holds a private block: requesting it is refused, and the proposal shows why.
func TestD469_RequestFromAStoredPlanRefusesAPrivateBlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "critical", Status: "confirmed"}
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: privIP, Approved: true}
	steps := `[{"kind":"contain","title":"t","detail":"d","proposal":{"id":"pr-x","action_id":"blocklist_add","params":{"ip":"` + privIP + `"},"asset_id":"a1","asset_name":"NAS"}}]`
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES ('plan-f1','f1','CVE-2024-0001','a1','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]',?)`, steps)
	_, err := e.svc.RequestProposal(e.ctx(), oper, "pr-x")
	wantCode(t, err, 409, "not_publishable")
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || !notPublishableLogged(e) {
		t.Fatal("a request was made or the refusal is not logged")
	}
	pl, err := e.svc.Plans(e.ctx(), "f1")
	e.must(err)
	if p := pl.Items[0].Steps[0].Proposal; p == nil || p.State != "not_publishable" {
		t.Fatalf("the stored proposal does not say why: %+v", p)
	}
}

// A request made before the check is refused right before it runs: the item fails with not_publishable, a refused line is written,
// the list stays empty, and nothing says "Added".
func TestD469_AnOlderRequestIsRefusedWhenItRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.exec1(`UPDATE resp_actions SET items = replace(items, '198.51.100.7', ?)`, privIP)
	got, err := e.svc.Approve(e.ctx(), oper, e.only().ID, nil, "")
	e.must(err)
	it := got.Items[0]
	if it.Status != response.ItemFailed || it.Result == nil || !strings.HasPrefix(*it.Result, privIP+" is not a public address") || it.Verified != nil {
		t.Fatalf("item %+v", it)
	}
	if !e.logHas("refused", "not_publishable: Add "+privIP+" to the block list: ") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatal("no refused line, or the address reached the list")
	}
}

// Entries a block made before D-469 left on private addresses are removed once, with one line giving the count; public ones stay.
func TestD469_OldPrivateEntriesAreRemovedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i, v := range []string{privIP, "10.9.9.9", "198.51.100.9"} {
		e.exec1(`INSERT INTO resp_block_entries (value, request_id, item_id, source, reason, added_at) VALUES (?, 'x', ?, 's', 'r', '2026-11-09T10:00:00.000Z')`, v, "i"+string(rune('0'+i)))
	}
	_, err := e.svc.Plans(e.ctx(), "") // the first call that seeds the module
	e.must(err)
	if e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 1 || e.count(`SELECT COUNT(*) FROM resp_block_entries WHERE value = '198.51.100.9'`) != 1 {
		t.Fatal("the private entries were not removed, or the public one was")
	}
	if !e.logHas("refused", "not_publishable: removed 2 block list entries") || e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.blocklist.cleanup'`) != 1 {
		t.Fatal("no log or audit line with the count")
	}
}
