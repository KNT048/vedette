package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
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
	"github.com/knt048/vedette/modules/findings"
)

// readProvider answers every reading call "unsure" for item 0 and keeps what it was sent.
type readProvider struct {
	mu   sync.Mutex
	reqs []provider.Request
}

func (p *readProvider) Complete(_ context.Context, req provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	text := `{"items":[{"index":0,"status":"unsure","introduced":"","fixed_in":"","last_affected":"","line":"","reason":"No range.","quote":"","source":0}]}`
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopEnd}, nil
}

// The reading's errors through the binary's checker: a hook that stops one call's text is that item's refusal (the check goes on with
// the next item and the automatic reading leaves it for a day), not a stop of the whole check; a CERT/CC reference page whose text
// carries the institute's phone number is read; the reading switched off still stops the check.
func TestPossibleChecker_ARefusedCallIsTheItemsAlone(t *testing.T) {
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
	rp := &readProvider{}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler),
		Factory: func(ai.Profile) (provider.Provider, error) { return rp, nil }})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Local", Kind: "openai-compatible", APIStyle: provider.StyleOpenAI, BaseURL: "http://192.168.10.5:11434/v1",
		Model: "m", Location: ai.LocationInternal, MonthlyBudget: 600000})
	if err != nil {
		t.Fatal(err)
	}
	asg := svc.Assignments()
	asg.Jobs[string(ai.JobExplainFinding)] = ai.SlotView{Primary: &p.ID}
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	c := possibleChecker{ai: svc}
	page := "Vulnerability Note VU#644655: Widget 3.4 is affected.\n\nCarnegie Mellon University\n\nPittsburgh, PA 15213-2612\n\n412-268-5800"
	req := findings.ProposeRequest{CVE: "CVE-2099-72003", Description: "A flaw in Widget.",
		Items: []findings.ProposeItem{{Index: 0, Vendor: "acme", Product: "Widget", Version: "3.4.1", Line: "3.4"}},
		Pages: []findings.FetchedPage{{URL: "https://www.kb.cert.org/vuls/id/644655", Status: "ok", Text: page}}}
	if ans, err := c.Propose(ctx, findings.SystemUser, req); err != nil || len(ans.Verdicts) != 1 {
		t.Fatalf("the CERT/CC page was not read: %+v %v", ans, err)
	}

	refused := req
	refused.Items = []findings.ProposeItem{{Index: 0, Vendor: "acme", Product: "Widget 079201234567", Version: "3.4.1", Line: "3.4"}}
	_, err = c.Propose(ctx, findings.SystemUser, refused)
	var item *findings.ItemRefused
	if !errors.As(err, &item) || item.RetryAfter < time.Hour || !strings.Contains(item.Reason, "hook") {
		t.Fatalf("a call a hook stopped: %#v, want the item refused with a retry time", err)
	}
	if _, err := c.Propose(ctx, findings.SystemUser, req); err != nil {
		t.Fatalf("the call after a refused one: %v", err)
	}

	if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: ai.TierMed, MonthlyBudget: 6000000, RedactPII: true, AutoReadOff: true}); err != nil {
		t.Fatal(err)
	}
	var stop *findings.CheckStop
	if _, err := c.Propose(ctx, findings.SystemUser, req); !errors.As(err, &stop) {
		t.Fatalf("the reading switched off: %#v, want the check stopped", err)
	}
}

// How each error of a call of a background run (the reading of advisories, the identification of software) is sorted: refusals of the
// call are its items' alone and the run goes on, the AI unavailable, a budget or the fuse stops the run, the rest is the call's failure
// for a later run.
func TestAICallError_SortsRefusalsStopsAndFailures(t *testing.T) {
	t.Parallel()
	refused, stop, other := "refused", "stop", "other"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{apierr.New(http.StatusConflict, "blocked_by_hook", "a hook stopped it"), refused},
		{apierr.New(http.StatusBadGateway, "ai_bad_format", "bad format"), refused},
		{apierr.New(http.StatusBadGateway, "ai_cut_off", "cut off"), refused},
		{apierr.New(http.StatusConflict, "ai_unavailable", "no profile"), stop},
		{apierr.New(http.StatusTooManyRequests, "budget_reached", "used up"), stop},
		{apierr.New(http.StatusTooManyRequests, "rate_limited", "fuse"), stop},
		{apierr.New(http.StatusBadGateway, "unreachable", "no route"), stop},
		{apierr.New(http.StatusBadGateway, "provider_error", "HTTP 500"), other},
		{apierr.New(http.StatusGatewayTimeout, "ai_timeout", "slow"), other},
		{errors.New("plain"), other},
	} {
		got := aiCallError(tc.err)
		var r *findings.ItemRefused
		var s *findings.CheckStop
		kind := other
		switch {
		case errors.As(got, &r):
			kind = refused
		case errors.As(got, &s):
			kind = stop
		}
		if kind != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, kind, tc.want)
		}
	}
}
