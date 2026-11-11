package ai_test

import (
	"context"
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

type liveFacts struct{}

func (liveFacts) CVE(_ context.Context, id string) (ai.CVEFacts, bool, error) {
	if id != "CVE-2024-3400" {
		return ai.CVEFacts{}, false, nil
	}
	return ai.CVEFacts{CVE: id, Vendor: "Palo Alto Networks", Product: "PAN-OS", Name: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
		Description: "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability.", RequiredAction: "Apply mitigations per vendor instructions.",
		DateAdded: "2024-04-12", Links: []string{"https://security.paloaltonetworks.com/CVE-2024-3400", "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"}}, true, nil
}

func (liveFacts) AffectedAssets(context.Context, string) ([]ai.AssetFact, error) { return nil, nil }

// TestLiveCVENews fetches the real public sources and asks a real model once (kien's machine only: VEDETTE_LIVE_AI=1, never CI).
// The key is read from ANTHROPIC_API_KEY, held in memory for the call, and never printed or stored. It proves the fetcher, the
// parsers, the prompt, the schema and the parser of the answer fit the real Internet and a real model.
func TestLiveCVENews(t *testing.T) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if os.Getenv("VEDETTE_LIVE_AI") != "1" || key == "" {
		t.Skip("set VEDETTE_LIVE_AI=1 and ANTHROPIC_API_KEY to run the live AI test")
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
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler), Facts: liveFacts{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Live Haiku", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com",
		Model: "claude-haiku-5-5", APIKey: key, Location: ai.LocationCloud, DailyCap: 60000}); err != nil {
		t.Fatal(err)
	}
	r, err := svc.NewsCVE(ctx, "test", "CVE-2024-3400")
	if err != nil {
		t.Fatalf("news: %v", err)
	}
	ok := 0
	for _, s := range r.Sources {
		t.Logf("source %-8s %-6s %s: %s", s.Kind, s.Status, s.Title, s.Note)
		if s.Status == "ok" {
			ok++
		}
	}
	for _, l := range r.Lines {
		t.Logf("line: %s", l)
	}
	if ok < 3 || len(r.Lines) < 3 || !strings.HasPrefix(r.Lines[0], "Exploited: ") || r.Tokens.Input == 0 {
		t.Fatalf("news = %+v", r)
	}
}
