package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/response"
)

func TestPlanSchemaIsJSON(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(planSchema), &v); err != nil {
		t.Fatal(err)
	}
}

func TestParsePlan(t *testing.T) {
	good := `{"steps":[{"kind":"contain","title":"Block","detail":"d","action_id":"blocklist_add","params":[{"name":"ip","value":"203.0.113.50"}],"confidence":0.9,"evidence":["rd-1"]},` +
		`{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"confidence":0,"evidence":[]}]}`
	d, err := parsePlan(good)
	if err != nil || len(d.Steps) != 2 || d.Steps[0].ActionID != "blocklist_add" || d.Steps[0].Params[0].Value != "203.0.113.50" || d.Steps[0].Confidence != 0.9 ||
		len(d.Steps[0].Evidence) != 1 || d.Steps[0].Evidence[0] != "rd-1" || len(d.Steps[1].Evidence) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	for name, bad := range map[string]string{
		"not json":       `ok`,
		"no steps":       `{"steps":[]}`,
		"extra field":    `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"command":"reboot"}]}`,
		"extra object":   good + `{"steps":[]}`,
		"top-level add":  `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[]}],"run":"x"}`,
		"evidence text":  `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"confidence":0,"evidence":"rd-1"}]}`,
		"confidence str": `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"confidence":"high","evidence":[]}]}`,
	} {
		if _, err := parsePlan(bad); !errors.Is(err, ai.ErrBadOutput) {
			t.Fatalf("%s: err = %v, want ErrBadOutput", name, err)
		}
	}
}

// L1: only "no profile can run the job" and "the daily cap is spent" stop the run. A format failure or a hook that stopped the answer
// also arrives as 409 ai_unavailable (RunJob); with a profile that is ready it is about this finding only.
func TestPlanErrorStopsTheRunOnlyWhenTheAIIsUnavailable(t *testing.T) {
	perFinding := apierr.New(409, "ai_unavailable", "The AI answered, but not in the format Vedette needs, so the answer was discarded.")
	if err := planError(perFinding, nil); errors.Is(err, response.ErrPlanUnavailable) {
		t.Fatal("a format failure stopped the run")
	}
	if err := planError(perFinding, apierr.New(409, "ai_unavailable", "No AI profile is set up.")); !errors.Is(err, response.ErrPlanUnavailable) {
		t.Fatal("no profile did not stop the run")
	}
	if err := planError(apierr.New(429, "budget_reached", "cap"), nil); !errors.Is(err, response.ErrPlanUnavailable) {
		t.Fatal("the daily cap did not stop the run")
	}
	if err := planError(ai.ErrBadOutput, nil); errors.Is(err, response.ErrPlanUnavailable) {
		t.Fatal("a bad output stopped the run")
	}
}

type liveUsers struct{}

func (liveUsers) Lookup(context.Context, string) (response.User, bool, error) {
	return response.User{}, false, nil
}

// TestLiveResponsePlan asks a real model once (kien's machine only: VEDETTE_LIVE_AI=1, never CI). The key is read from ANTHROPIC_API_KEY,
// held in memory for the call, and never printed or stored. It proves the prompt, the schema, the parser and the checks of response fit
// a real answer.
func TestLiveResponsePlan(t *testing.T) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if os.Getenv("VEDETTE_LIVE_AI") != "1" || key == "" {
		t.Skip("set VEDETTE_LIVE_AI=1 and ANTHROPIC_API_KEY to run the live AI test")
	}
	ctx := t.Context()
	db := storetest.New(t)
	for name, m := range map[string]fs.FS{"core": core.Migrations, "ai": ai.Migrations, "response": response.Migrations} {
		if err := store.Migrate(ctx, db, name, m); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	var warned strings.Builder // what the plan job logged: the model's text is never in it, only the kind of failure
	log := slog.New(slog.NewTextHandler(&warned, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Live Haiku", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com",
		Model: "claude-haiku-5-5", APIKey: key, Location: ai.LocationCloud, MonthlyBudget: 60000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: ai.TierMin, MonthlyBudget: 60000, RedactPII: true}); err != nil { // low effort
		t.Fatal(err)
	}
	asg := svc.Assignments()
	asg.Jobs[string(ai.JobResponsePlan)] = ai.SlotView{Primary: &p.ID} // opt-in: the job is not assigned by itself
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	target := response.PlanTarget{FindingID: "f-live", CVE: "CVE-2024-3400", AssetID: "a-live", AssetName: "NAS-01", AssetIP: "192.168.10.21", AssetKind: "nas"}
	rs, err := response.New(response.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Users: liveUsers{}, Log: log,
		Planner: responsePlanner{svc: svc}, Critical: func(context.Context) ([]response.PlanTarget, error) { return []response.PlanTarget{target}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	n, err := rs.PlanOpen(ctx) // parses the answer and runs it through checkDraft; a refused plan is not stored
	if err != nil || n != 1 {
		var why string // the refusal line of response (no secret in it) says which check the answer failed
		_ = db.Reader().QueryRowContext(ctx, `SELECT detail FROM resp_log WHERE kind = 'refused' ORDER BY seq DESC LIMIT 1`).Scan(&why)
		t.Fatalf("live plan: saved %d, err %v, refusal %q, job log %q", n, err, why, warned.String())
	}
	var steps string // what was kept: action ids and checked values, no secret
	_ = db.Reader().QueryRowContext(ctx, `SELECT steps FROM resp_plans WHERE finding_id = 'f-live'`).Scan(&steps)
	t.Logf("stored steps: %s", steps)
}

// planProvider answers every request of the plan job with one plan and keeps the requests.
type planProvider struct {
	mu   sync.Mutex
	reqs []provider.Request
}

func (p *planProvider) Complete(_ context.Context, req provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	text := `{"steps":[{"kind":"contain","title":"Block","detail":"d","action_id":"fgt_addrgrp_add","params":[{"name":"ip","value":"192.168.10.21"}],"confidence":0.9,"evidence":["rd-fw"]}]}`
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopEnd}, nil
}

// ai 7 (D-312, D-313): the plan prompt lists the box's reads of the connections of the offered actions, and only those; the activity row
// of what was sent links the proposals and the requests.
func TestPlannerListsTheBoxReadsAndRecordsWhatWasSent(t *testing.T) {
	ctx := t.Context()
	db := storetest.New(t)
	for name, m := range map[string]fs.FS{"core": core.Migrations, "ai": ai.Migrations} {
		if err := store.Migrate(ctx, db, name, m); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	pp := &planProvider{}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler),
		Factory: func(ai.Profile) (provider.Provider, error) { return pp, nil }})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Local", Kind: "openai-compatible", APIStyle: provider.StyleOpenAI, BaseURL: "http://192.168.10.5:11434/v1",
		Model: "m", Location: ai.LocationInternal, MonthlyBudget: 60000})
	if err != nil {
		t.Fatal(err)
	}
	asg := svc.Assignments()
	asg.Jobs[string(ai.JobResponsePlan)] = ai.SlotView{Primary: &p.ID}
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	fresh := ai.FormatTS(time.Now().Add(-time.Hour))
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO ai_read (id, ts, connection_id, connection_name, tool, job) VALUES ('rd-fw', ?, 'cn-fw', 'Office firewall', 'show_addr', 'ask-my-data'),
			('rd-other', ?, 'cn-other', 'Core switch', 'show_run', 'ask-my-data'), ('rd-old', ?, 'cn-fw', 'Office firewall', 'show_addr', 'ask-my-data')`, fresh, fresh, ai.FormatTS(time.Now().Add(-25*time.Hour)))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	planner := responsePlanner{svc: svc}
	target := response.PlanTarget{FindingID: "f1", CVE: "CVE-2024-3400", AssetID: "a1", AssetName: "NAS-01", AssetIP: "192.168.10.21", AssetKind: "nas"}
	acts := []response.AIAction{{ID: "fgt_addrgrp_add", Name: "Add to address group", Risk: response.RiskMedium, Params: []response.AIParam{{Name: "ip", Type: "ip", Label: "IP address"}}, ConnectionID: "cn-fw"},
		{ID: "blocklist_add", Name: "Block list", Risk: response.RiskLow, Params: []response.AIParam{{Name: "ip", Type: "ip", Label: "IP address"}}}}
	d, err := planner.Plan(ctx, response.PlanAsk{Target: target, Actions: acts})
	if err != nil || len(d.Steps) != 1 || d.Steps[0].Confidence != 0.9 || len(d.Steps[0].Evidence) != 1 || d.Steps[0].Evidence[0] != "rd-fw" {
		t.Fatalf("plan: %+v %v", d, err)
	}
	b, _ := json.Marshal(pp.reqs[len(pp.reqs)-1])
	sent := string(b)
	if !strings.Contains(sent, `rd-fw`) || strings.Contains(sent, "rd-other") || strings.Contains(sent, "rd-old") || !strings.Contains(sent, `through the connection \"cn-fw\"`) {
		t.Fatalf("the reads offered are not the box's reads of cn-fw only: %s", sent)
	}
	// No device action, no read is listed.
	if _, err := planner.Plan(ctx, response.PlanAsk{Target: target, Actions: acts[1:]}); err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(pp.reqs[len(pp.reqs)-1]); strings.Contains(string(b), "rd-") || !strings.Contains(string(b), "cite no read") {
		t.Fatalf("reads listed without a device action: %s", b)
	}
	planner.Proposed(ctx, target, []response.SentProposal{{ProposalID: "pr-1", ActionID: "fgt_addrgrp_add", Outcome: "request", RequestID: "act-1"}, {ProposalID: "pr-2", ActionID: "blocklist_add", Outcome: "already_open"}})
	var links, summary, trigger string
	var tokens int
	if err := db.Reader().QueryRowContext(ctx, `SELECT links, summary, trigger, tokens_in FROM ai_activity ORDER BY seq DESC LIMIT 1`).Scan(&links, &summary, &trigger, &tokens); err != nil {
		t.Fatal(err)
	}
	if links != `[{"kind":"proposal","id":"pr-1"},{"kind":"action","id":"act-1"},{"kind":"proposal","id":"pr-2"}]` || trigger != "system:ai:response" || tokens != 0 ||
		!strings.Contains(summary, "AI-generated") || !strings.Contains(summary, "CVE-2024-3400") {
		t.Fatalf("activity row: %s %q %s %d", links, summary, trigger, tokens)
	}
}
