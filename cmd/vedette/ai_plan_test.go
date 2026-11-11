package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
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
	good := `{"steps":[{"kind":"contain","title":"Block","detail":"d","action_id":"blocklist_add","params":[{"name":"ip","value":"203.0.113.50"}]},{"kind":"check","title":"c","detail":"d","action_id":"","params":[]}]}`
	d, err := parsePlan(good)
	if err != nil || len(d.Steps) != 2 || d.Steps[0].ActionID != "blocklist_add" || d.Steps[0].Params[0].Value != "203.0.113.50" {
		t.Fatalf("%+v %v", d, err)
	}
	for name, bad := range map[string]string{
		"not json":      `ok`,
		"no steps":      `{"steps":[]}`,
		"extra field":   `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[],"command":"reboot"}]}`,
		"extra object":  good + `{"steps":[]}`,
		"top-level add": `{"steps":[{"kind":"check","title":"c","detail":"d","action_id":"","params":[]}],"run":"x"}`,
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
	if err := planError(apierr.New(429, "daily_cap", "cap"), nil); !errors.Is(err, response.ErrPlanUnavailable) {
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
		Model: "claude-haiku-5-5", APIKey: key, Location: ai.LocationCloud, DailyCap: 60000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: ai.TierMin, DailyCap: 60000, RedactPII: true}); err != nil { // low effort
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
}
