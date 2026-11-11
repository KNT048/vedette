package response_test

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// ai 7 (S-RESP-2, D-310, D-313, D-314): the plan job sends the proposals of a plan it just stored through Propose, as the AI, when the
// admin allowed the finding trigger for AI requests and the execution switch is on. Every gate is Propose's; nothing is retried.

const devIP = "192.168.10.21"

func sendStep(action string, conf float64, reads ...string) []response.DraftStep {
	return []response.DraftStep{
		{Kind: "contain", Title: "Block the address", Detail: "Add it to the block list.", ActionID: action, Params: []response.DraftParam{{Name: "ip", Value: devIP}}, Confidence: conf, Evidence: reads},
		{Kind: "patch", Title: "Patch", Detail: "Install the vendor fix."},
	}
}

// planSendEnv has one device at devIP with open critical findings f2 and f3 and no plan; the AI is available and the reads it made are
// behind the ConfigRead port (rd-fw through the firewall connection cn-fw, rd-other through another one).
func planSendEnv(t *testing.T, steps []response.DraftStep) (*env, *fakePlanner, *[]response.PlanTarget) {
	t.Helper()
	fp := &fakePlanner{on: true, steps: func(response.PlanTarget) []response.DraftStep { return steps }}
	ev := &evFake{cfg: map[string]response.EvidenceRef{
		"rd-fw":    {Summary: `Read "show_addr" on the connection "Office firewall"`, Connection: "cn-fw"},
		"rd-other": {Summary: `Read "show_run" on the connection "Core switch"`, Connection: "cn-other"},
	}}
	targets := &[]response.PlanTarget{}
	e := newEnv(t, func(c *response.Config) {
		c.Planner = fp
		c.Critical = func(context.Context) ([]response.PlanTarget, error) { return *targets, nil }
		c.Evidence = ev.ports()
	})
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "NAS", IP: devIP, Approved: true}
	e.dir.findings["f2"] = response.FindingInfo{ID: "f2", AssetID: "a1", CVE: "CVE-2024-0002", Severity: "critical", Status: "confirmed"}
	*targets = append(*targets, response.PlanTarget{FindingID: "f2", CVE: "CVE-2024-0002", AssetID: "a1", AssetName: "NAS", AssetIP: devIP})
	return e, fp, targets
}

func (e *env) addCritical(targets *[]response.PlanTarget, id string) {
	e.dir.findings[id] = response.FindingInfo{ID: id, AssetID: "a1", CVE: "CVE-2024-0003", Severity: "critical", Status: "confirmed"}
	*targets = append(*targets, response.PlanTarget{FindingID: id, CVE: "CVE-2024-0003", AssetID: "a1", AssetName: "NAS", AssetIP: devIP})
}

func (e *env) aiRefusals() int {
	return e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'ai:response'`)
}

func TestPlanJobSendsNothingUntilTheAdminAllowsIt(t *testing.T) {
	e, fp, targets := planSendEnv(t, sendStep("blocklist_add", 0.95))
	// Execution off (the default): the plan is stored, nothing is sent, nothing is refused in the log.
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 1 || len(fp.sent) != 0 || e.count(`SELECT COUNT(*) FROM resp_actions`)+e.count(`SELECT COUNT(*) FROM resp_ai_notes`) != 0 || e.aiRefusals() != 0 {
		t.Fatalf("execution off: saved %d, sent %v, actions %d", n, fp.sent, e.count(`SELECT COUNT(*) FROM resp_actions`))
	}
	// Execution on, but the AI may not send requests for the finding trigger: the same.
	e.turnOn()
	e.saveSettings(func(in *response.SettingsInput) { in.AI.Triggers = []string{"ioc_connection"} })
	e.addCritical(targets, "f3")
	n, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 1 || len(fp.sent) != 0 || e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 || e.aiRefusals() != 0 {
		t.Fatalf("finding not allowed: saved %d, sent %v", n, fp.sent)
	}
}

func TestPlanJobSendsTheProposalAsTheAI(t *testing.T) {
	e, fp, targets := planSendEnv(t, sendStep("blocklist_add", 0.95))
	e.turnOn()
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 1 {
		t.Fatalf("saved %d", n)
	}
	pl, err := e.svc.Plans(e.ctx(), "f2")
	e.must(err)
	sent := fp.sent["f2"]
	if len(sent) != 1 || sent[0].Outcome != response.OutcomeRequest || sent[0].RequestID == "" || sent[0].ActionID != "blocklist_add" || sent[0].ProposalID != pl.Items[0].Steps[0].Proposal.ID {
		t.Fatalf("sent = %+v, plan %+v", sent, pl.Items[0].Steps[0])
	}
	var source, trigger, finding, status, ai string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT source, trigger, finding_id, status, ai FROM resp_actions WHERE id = ?`, sent[0].RequestID).Scan(&source, &trigger, &finding, &status, &ai))
	if source != "ai" || trigger != "finding" || finding != "f2" || status != "pending" || !strings.Contains(ai, `"f2"`) || !strings.Contains(ai, "0.95") {
		t.Fatalf("request: %s %s %s %s %s", source, trigger, finding, status, ai)
	}
	if actor, _ := e.newest("proposal"); actor != response.AIActor {
		t.Fatalf("the request was logged by %q", actor)
	}
	// A second finding on the same device plans the same action: Propose refuses it (already open), the refusal is logged once, and
	// it is reported as such; nothing is retried on the next run.
	e.addCritical(targets, "f3")
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if s := fp.sent["f3"]; len(s) != 1 || s[0].Outcome != "already_open" || s[0].RequestID != "" {
		t.Fatalf("second proposal: %+v", s)
	}
	refused := e.aiRefusals()
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if e.count(`SELECT COUNT(*) FROM resp_actions`) != 1 || e.aiRefusals() != refused || len(fp.sent["f3"]) != 1 {
		t.Fatalf("a refused proposal was sent again: actions %d, refusals %d -> %d", e.count(`SELECT COUNT(*) FROM resp_actions`), refused, e.aiRefusals())
	}
}

func TestPlanJobLowConfidenceIsASuggestion(t *testing.T) {
	e, fp, _ := planSendEnv(t, sendStep("blocklist_add", 0.5))
	e.turnOn()
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if s := fp.sent["f2"]; len(s) != 1 || s[0].Outcome != response.OutcomeSuggestion || e.count(`SELECT COUNT(*) FROM resp_ai_notes WHERE kind = 'suggestion'`) != 1 || e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 {
		t.Fatalf("low confidence: %+v", s)
	}
}

func TestPlanJobCitedReadsAreLookedUpByResponse(t *testing.T) {
	// A box action: no read can be about it, so none is sent; a made-up id does not cost the proposal the finding carries.
	e, fp, _ := planSendEnv(t, sendStep("blocklist_add", 0.95, "rd-fw", "rd-forged"))
	e.turnOn()
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	s := fp.sent["f2"]
	if n != 1 || len(s) != 1 || s[0].Outcome != response.OutcomeRequest {
		t.Fatalf("box action: saved %d, %+v", n, s)
	}
	var ai string
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT ai FROM resp_actions WHERE id = ?`, s[0].RequestID).Scan(&ai))
	if strings.Contains(ai, "config_read") {
		t.Fatalf("a read was sent for a box action: %s", ai)
	}

	// A device action on the firewall: it is offered with its connection, and only a read the box recorded through that connection is
	// kept as evidence; a read of another connection and an unknown id are dropped before Propose.
	e, fp, _ = planSendEnv(t, sendStep("fgt_addrgrp_add", 0.95, "rd-fw", "rd-other", "rd-forged"))
	e.firewall("fgt_addrgrp_add")
	e.turnOn()
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	offered := false
	for _, a := range fp.acts[0] {
		if a.ID == "fgt_addrgrp_add" {
			offered = a.ConnectionID == "cn-fw"
		}
		if a.ID == "blocklist_add" && a.ConnectionID != "" {
			t.Errorf("a box action was offered with a connection: %+v", a)
		}
	}
	if !offered {
		t.Fatalf("the firewall action was not offered with its connection: %+v", fp.acts[0])
	}
	s = fp.sent["f2"]
	if len(s) != 1 || s[0].Outcome != response.OutcomeRequest {
		t.Fatalf("device action: %+v", s)
	}
	e.must(e.db.Reader().QueryRowContext(e.ctx(), `SELECT ai FROM resp_actions WHERE id = ?`, s[0].RequestID).Scan(&ai))
	if !strings.Contains(ai, `"rd-fw"`) || !strings.Contains(ai, "Office firewall") || strings.Contains(ai, "rd-other") || strings.Contains(ai, "rd-forged") {
		t.Fatalf("evidence of the request: %s", ai)
	}
}

// The switch is read again before sending: turned off while the AI wrote the plan, nothing is sent.
func TestPlanJobRereadsTheSwitchBeforeSending(t *testing.T) {
	e, fp, _ := planSendEnv(t, sendStep("blocklist_add", 0.95))
	e.turnOn()
	fp.steps = func(response.PlanTarget) []response.DraftStep {
		if _, err := e.svc.SetExecution(context.Background(), admin, false, riskPhrase); err != nil {
			t.Error(err)
		}
		return sendStep("blocklist_add", 0.95)
	}
	n, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	if n != 1 || len(fp.sent) != 0 || e.count(`SELECT COUNT(*) FROM resp_actions`) != 0 {
		t.Fatalf("sent after the switch was turned off: %d %v", n, fp.sent)
	}
}
