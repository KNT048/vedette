package ai_test

import (
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
)

// TestLiveProposePossible_ReadsLikeACarefulPerson asks a real model once (local only: VEDETTE_LIVE_AI=1, never CI) to read a synthetic
// CVE record the way a person would: the record names line 115 of the vendor's browser fixed in 115.42 and nothing for the mail client's
// 115 line, so the mail client's 115.9.0 is affected by inference (named as such); its 140.20.0 is past the mail client's own fix
// 140.17 and must not be called affected. The key is read from ANTHROPIC_API_KEY, held in memory for the call, never printed or stored;
// the model from VEDETTE_LIVE_AI_MODEL (a small, fast one).
func TestLiveProposePossible_ReadsLikeACarefulPerson(t *testing.T) {
	key, model := os.Getenv("ANTHROPIC_API_KEY"), os.Getenv("VEDETTE_LIVE_AI_MODEL")
	if os.Getenv("VEDETTE_LIVE_AI") != "1" || key == "" || model == "" {
		t.Skip("set VEDETTE_LIVE_AI=1, ANTHROPIC_API_KEY and VEDETTE_LIVE_AI_MODEL to run the live AI test")
	}
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "ai", ai.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Live reading", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com",
		Model: model, APIKey: key, Location: ai.LocationCloud, MonthlyBudget: 60000}); err != nil {
		t.Fatal(err)
	}
	const fixed = "This vulnerability was fixed in Quillfeather Browser 157, Quillfeather Browser ESR 115.42, Quillfeather Mail 157 and Quillfeather Mail 140.17."
	ans, err := svc.ProposePossible(ctx, "test", ai.PossibleRequest{CVE: "CVE-2099-99101", Description: "Use-after-free in the layout engine. " + fixed,
		Rows: []string{
			"quillfeather mail: affected before 157.0 [nvd]",
			"quillfeather mail (edition esr): affected from 140.0 before 140.17.0 [nvd]",
			"quillfeather browser: affected before 157.0 [nvd]",
			"quillfeather browser (edition esr): affected from 115.1.0 before 115.42.0 [nvd]",
			"quillfeather browser (edition esr): affected from 140.0 before 140.17.0 [nvd]",
		},
		Items: []ai.PossibleItem{
			{Index: 0, Vendor: "quillfeather", Product: "Mail", Version: "115.9.0", Line: "115.9.0", Edition: "esr"},
			{Index: 1, Vendor: "quillfeather", Product: "Mail", Version: "140.20.0", Line: "140.20.0", Edition: "esr"},
		}})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	by := map[int]ai.PossibleVerdict{}
	for _, v := range ans.Verdicts {
		t.Logf("item %d: %s line %q fixed_in %q inferred_from %q quote %q reason %q", v.Index, v.Status, v.Line, v.FixedIn, v.InferredFrom, v.Quote, v.Reason)
		by[v.Index] = v
	}
	if v := by[0]; v.Status != "affected" || v.InferredFrom == "" || !strings.Contains(v.Quote, "115.42") {
		t.Errorf("115.9.0: %+v; want affected, inferred from the browser's 115 line, quoting 115.42", v)
	}
	if v := by[1]; v.Status == "affected" {
		t.Errorf("140.20.0 is past the mail client's own fix 140.17 but was read affected: %+v", v)
	}
}
