package response_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/response"
)

// Item 20 (S-RESP-2, D-513): GET /response/plans carries what the plan job did on its last run and, per finding, why nothing was
// proposed, so an empty inbox is explained. The reasons are the job's own decision points; the status is read-only and in memory.

func (e *env) planner() response.PlannerStatus {
	e.t.Helper()
	pl, err := e.svc.Plans(e.ctx(), "")
	e.must(err)
	return pl.Planner
}

func outcomes(st response.PlannerStatus) map[string]response.PlannerFinding {
	m := map[string]response.PlannerFinding{}
	for _, f := range st.Findings {
		m[f.FindingID] = f
	}
	return m
}

func TestPlannerStatusBeforeAnyRunAndWithoutAI(t *testing.T) {
	t.Parallel()
	e, fp, _ := aiPlanEnv(t)
	if st := e.planner(); st.RanAt != nil || st.Findings == nil || len(st.Findings) != 0 {
		t.Fatalf("before the first run: %+v", st)
	}
	fp.on = false // no profile for the job, or the ai module off
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	st := e.planner()
	if st.RanAt == nil || st.Blocked != response.PlannerNoAI || st.Asked != 0 || len(fp.asked) != 0 {
		t.Fatalf("no AI: %+v", st)
	}
}

func TestPlannerStatusSaysWhyNothingWasSent(t *testing.T) {
	t.Parallel()
	e, _, _ := aiPlanEnv(t) // f1 has a plan; execution is off (the default)
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	st := e.planner()
	m := outcomes(st)
	if st.Considered != 3 || st.Asked != 2 || st.Proposed != 0 || st.Blocked != "" {
		t.Fatalf("counts: %+v", st)
	}
	// the API carries it as the contract says (a viewer reads it)
	res, err := response.NewResponseHandlers(e.svc).ResponseGetResponsePlans(server.WithPrincipal(e.ctx(), server.Principal{ID: "u-x", Role: routes.Viewer}), oas.ResponseGetResponsePlansParams{})
	e.must(err)
	if b, err := res.MarshalJSON(); err != nil || !strings.Contains(string(b), `"outcome":"not_sent"`) || !strings.Contains(string(b), `"considered":3`) {
		t.Fatalf("API: %s %v", b, err)
	}
	if m["f1"].Outcome != response.OutcomeHasPlan || m["f1"].CVE != "CVE-2024-0001" || m["f1"].AssetName != "NAS" {
		t.Fatalf("f1: %+v", m["f1"])
	}
	if m["f2"].Outcome != response.OutcomeNotSent || !strings.Contains(m["f2"].Reason, "execution switch is off") {
		t.Fatalf("f2: %+v", m["f2"])
	}
	// Execution on, but the AI may not send requests for critical findings.
	e.turnOn()
	e.saveSettings(func(in *response.SettingsInput) { in.AI.Triggers = []string{"ioc_connection"} })
	e.exec1(`DELETE FROM resp_plans WHERE finding_id = 'f3'`)
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if f := outcomes(e.planner())["f3"]; f.Outcome != response.OutcomeNotSent || !strings.Contains(f.Reason, "critical findings") {
		t.Fatalf("f3: %+v", f)
	}
}

func TestPlannerStatusCountsAProposalAndARefusal(t *testing.T) {
	t.Parallel()
	e, _, targets := planSendEnv(t, sendStep("blocklist_add", 0.95))
	e.turnOn()
	e.addCritical(targets, "f3") // the same device and action: Propose refuses the second one (already open)
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	st := e.planner()
	m := outcomes(st)
	if st.Proposed != 1 || m["f2"].Outcome != response.OutcomeProposed || m["f3"].Outcome != response.OutcomeRefused || m["f3"].Reason == "" {
		t.Fatalf("status: %+v", st)
	}
}

func TestPlannerStatusAFailedAICallBacksOff(t *testing.T) {
	t.Parallel()
	e, fp, _ := aiPlanEnv(t)
	fp.err = errors.New("provider said no")
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	f := outcomes(e.planner())["f2"]
	if f.Outcome != response.OutcomeAIFailed || strings.Contains(f.Reason, "provider said no") {
		t.Fatalf("a failed call: %+v (the provider's text is never shown)", f)
	}
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if f := outcomes(e.planner())["f2"]; f.Outcome != response.OutcomeBackedOff || !strings.Contains(f.Reason, "again after") {
		t.Fatalf("backed off: %+v", f)
	}
	fp.err = response.ErrPlanUnavailable
	e.clock.t = e.clock.t.Add(48 * 3600e9)
	_, err = e.svc.PlanOpen(e.ctx())
	e.must(err)
	if f := outcomes(e.planner())["f2"]; f.Outcome != response.OutcomeAIUnavailable {
		t.Fatalf("budget: %+v", f)
	}
}

func TestPlannerStatusNamesWhyNoActionWasOffered(t *testing.T) {
	t.Parallel()
	e, fp, targets := aiPlanEnv(t)
	// A device on the LAN: the block list never publishes its address (D-469), and no device action is ready.
	for i := range *targets {
		(*targets)[i].AssetIP = "192.168.1.20"
	}
	fp.steps = func(response.PlanTarget) []response.DraftStep {
		return []response.DraftStep{{Kind: "patch", Title: "Patch", Detail: "Install the vendor fix."}}
	}
	_, err := e.svc.PlanOpen(e.ctx())
	e.must(err)
	f := outcomes(e.planner())["f2"]
	if f.Outcome != response.OutcomeNoAction || !strings.Contains(f.Reason, "No action") {
		t.Fatalf("no action: %+v", f)
	}
}
