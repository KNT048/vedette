package response_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// D-469 (INV-17): the block list publishes public addresses only, so a blocklist_add on any other address is refused when it is
// planned, with not_public and a refused line, on every path; one planned before the check is refused again before it runs.

const privIP = "192.168.1.5"

func notPublicLogged(e *env) bool {
	return e.logHas("refused", "not_public: ") && e.logHas("refused", privIP+" is not a public address")
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
			if !e.logHas("refused", "not_public: Block: "+ip+" is not a public address") {
				t.Fatal("no refused line with not_public")
			}
		})
	}
	// A public address still plans (the IPv4 documentation blocks count as public, INV-17).
	e := newEnv(t)
	e.rule("Block", "ioc_connection", blockAction(60), nil)
	if sum := e.fire(e.iocEvent("e1", "198.51.100.7")); sum.Requests != 1 || e.logHas("refused", "not_public") {
		t.Fatalf("a public address was refused: %+v", sum)
	}
}

func TestD469_ManualRunAndSimulationRefuseAPrivateBlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-HR-01", IP: privIP, Kind: "pc", Approved: true}
	r := e.rule("Block this PC", "manual", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.ip}}"}, TTLMin: intp(60)}}, nil)
	sum, err := e.svc.RunManual(e.ctx(), oper, r.ID, "a-pc")
	e.must(err)
	if sum.Refused != 1 || len(e.actions()) != 0 || !notPublicLogged(e) {
		t.Fatalf("manual run: %+v, %d requests", sum, len(e.actions()))
	}
	sim, err := e.svc.Simulate(e.ctx(), oper, response.RuleInput{Name: "Block", Enabled: true, Live: true, Trigger: "ioc_connection", Match: "all", Conditions: []response.Condition{},
		Actions: []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": privIP}, TTLMin: intp(60)}}, MaxPerHour: 5}, "")
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
	wantCode(t, err, 409, "not_public")
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || !notPublicLogged(e) {
		t.Fatal("a request was made or the refusal is not logged")
	}
}

func TestD469_AIPlanWithAPrivateBlockIsNotStored(t *testing.T) {
	t.Parallel()
	e, fp, targets := aiPlanEnv(t)
	ip := privIP // the AI blocks the device of the finding, an address of the LAN
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: ip, Approved: true}
	for i := range *targets {
		(*targets)[i].AssetIP = ip
	}
	fp.steps = func(response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{{Kind: "contain", Title: "Block", Detail: "d", ActionID: "blocklist_add", Params: []response.DraftParam{{Name: "ip", Value: ip}}}}
	}
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 0 || !e.logHas("refused", "plan_invalid") || !e.logHas("refused", "(not_public): "+ip+" is not a public address") {
		t.Fatalf("saved %d plans; the refusal with not_public is not logged", n)
	}
}

// A plan stored before the check holds a private block: requesting it is refused, and the proposal is shown as not available.
func TestD469_RequestFromAStoredPlanRefusesAPrivateBlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.turnOn()
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "critical", Status: "confirmed"}
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: privIP, Approved: true}
	steps := `[{"kind":"contain","title":"t","detail":"d","proposal":{"id":"pr-x","action_id":"blocklist_add","params":{"ip":"` + privIP + `"},"asset_id":"a1","asset_name":"NAS"}}]`
	e.exec1(`INSERT INTO resp_plans (id, finding_id, cve, asset_id, asset_name, generated_at, model, profile, path, reads, steps) VALUES ('plan-f1','f1','CVE-2024-0001','a1','NAS','2026-11-09T09:00:00.000Z','m','p','path','[]',?)`, steps)
	_, err := e.svc.RequestProposal(e.ctx(), oper, "pr-x")
	wantCode(t, err, 409, "not_public")
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || !notPublicLogged(e) {
		t.Fatal("a request was made or the refusal is not logged")
	}
	pl, err := e.svc.Plans(e.ctx(), "f1")
	e.must(err)
	if p := pl.Items[0].Steps[0].Proposal; p == nil || p.State != "tool_unavailable" {
		t.Fatalf("the stored proposal reads as ready: %+v", p)
	}
}

// A request made before the check is refused right before it runs: the item fails with not_public, a refused line is written, the
// list stays empty, and nothing says "Added".
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
	if !e.logHas("refused", "not_public: Add "+privIP+" to the block list: ") || e.count(`SELECT COUNT(*) FROM resp_block_entries`) != 0 {
		t.Fatal("no refused line, or the address reached the list")
	}
}
