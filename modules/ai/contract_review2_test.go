package ai_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The review of slice 2 (PR #179): M1, M2 and the low findings.

func TestContract_INV17_ACancelledRequestStillLeavesItsRow(t *testing.T) {
	for name, fail := range map[string]error{"answered": nil, "failed": &provider.Error{Kind: provider.ErrNetwork}} {
		t.Run(name, func(t *testing.T) {
			a := newAPI(t)
			a.withProfile()
			ctx, cancel := context.WithCancel(a.ctx())
			defer cancel()
			a.fake.setOnCall(cancel) // the person closes the tab while the box is asking the AI
			if fail != nil {
				a.fake.failWith("Claude", fail)
			}
			_, _ = a.svc.ExplainCVE(ctx, "it@acme.example", "CVE-2022-27593")
			if a.fake.total() == 0 {
				t.Fatal("the provider was never asked")
			}
			rows := a.activity()
			if len(rows) != 1 || rows[0].Job != "explain-finding" || rows[0].Trigger != "user:it@acme.example" {
				t.Fatalf("activity after a cancelled request = %+v", rows)
			}
			if name == "answered" {
				// the answer came back: its row says so with its tokens, and a restart counts them
				if rows[0].Result != ai.ResultOK || rows[0].TokensIn != 14 || rows[0].TokensOut != 3 {
					t.Fatalf("row = %+v", rows[0])
				}
				b := newAPIOver(a.env)
				if list := b.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any); list[0].(map[string]any)["used_month"] != float64(17) {
					t.Fatalf("used_month after a restart = %v", list[0])
				}
				return
			}
			if rows[0].Result != ai.ResultError || !strings.Contains(rows[0].Summary, "cancelled") {
				t.Fatalf("row = %+v", rows[0])
			}
		})
	}
}

func TestContract_INV17_TheResultAndItsRowCommitTogether(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	var linked int
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT COUNT(*) FROM ai_result r JOIN ai_activity a ON a.id = r.activity_id WHERE r.kind = 'explain' AND a.result = 'ok'`).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("explanations linked to their ok row = %d, %v", linked, err)
	}
	// a result that cannot be stored is not kept, and the call still has its row, saying that it failed
	b := newAPI(t)
	b.withProfile()
	if err := b.exec(`CREATE TRIGGER ai_result_refuse BEFORE INSERT ON ai_result BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := b.do("POST", "/ai/cve/CVE-2022-27593/explain", "operator", ""); got != 500 {
		t.Fatalf("status = %d, want 500", got)
	}
	rows := b.activity()
	if len(rows) != 1 || rows[0].Result != ai.ResultError || rows[0].TokensIn != 14 || !strings.Contains(rows[0].Summary, "not stored") {
		t.Fatalf("rows = %+v", rows)
	}
	var n int
	if err := b.db.Reader().QueryRowContext(b.ctx(), `SELECT COUNT(*) FROM ai_result`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("ai_result rows = %d, %v", n, err)
	}
}

func TestContract_POST2_CachedAnswerFollowsTheInventory(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.explain("CVE-2022-27593", 200, "")
	explain := func() any {
		return a.want("GET", "/ai/cve/CVE-2022-27593/cached", "viewer", "", 200, "")["explain"]
	}
	if explain() == nil {
		t.Fatal("nothing cached right after an explanation")
	}
	// the device is patched: no device matches any more, so "affected" must not be served from before
	a.facts.mu.Lock()
	saved := a.facts.assets["CVE-2022-27593"]
	a.facts.assets["CVE-2022-27593"] = nil
	a.facts.mu.Unlock()
	calls := a.fake.total()
	if got := explain(); got != nil {
		t.Fatalf("a stale explanation was served after the inventory changed: %v", got)
	}
	if a.fake.total() != calls {
		t.Fatal("reading the cache called the AI")
	}
	// the inventory is as it was when the answer was made: the answer is served again
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"] = saved
	a.facts.mu.Unlock()
	if explain() == nil {
		t.Fatal("the matching answer was not served")
	}
	// a changed feed entry is a changed question too
	a.facts.mu.Lock()
	f := a.facts.cves["CVE-2022-27593"]
	f.RequiredAction = "Remove the product."
	a.facts.cves["CVE-2022-27593"] = f
	a.facts.mu.Unlock()
	if got := explain(); got != nil {
		t.Fatalf("a stale explanation was served after the feed entry changed: %v", got)
	}
}

func TestContract_INV4_UsageFollowsTheProfileNotItsName(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	a.explain("CVE-2022-27593", 200, "") // 17 tokens
	a.want("PUT", "/ai/profiles/"+id, "admin", noKey(cloudBody("Claude renamed", keyA)), 200, "")
	b := newAPIOver(a.env)
	list := b.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)
	if p := list[0].(map[string]any); p["name"] != "Claude renamed" || p["used_month"] != float64(17) {
		t.Fatalf("after a rename and a restart = %v", p)
	}
	// a new profile that takes the old name does not inherit its usage
	fresh := b.addProfile(cloudBody("Claude", keyB))
	if fresh["used_month"] != float64(0) {
		t.Fatalf("a new profile named like an old one starts with %v tokens", fresh["used_month"])
	}
	c := newAPIOver(b.env)
	for _, p := range c.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any) {
		m := p.(map[string]any)
		want := float64(0)
		if m["name"] == "Claude renamed" {
			want = 17
		}
		if m["used_month"] != want {
			t.Fatalf("after a second restart %v has %v tokens, want %v", m["name"], m["used_month"], want)
		}
	}
}

type fakeModules struct{ on bool }

func (m fakeModules) Enabled(string) bool { return m.on }

func TestBriefAndAvailableAreOffWhenTheModuleIsOff(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	build := func(on bool) *ai.Service {
		svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now,
			Factory: a.fake.factory, Facts: a.facts, Modules: fakeModules{on}})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	if !build(true).Available(ai.JobExplainFinding) {
		t.Fatal("not available with the module on")
	}
	off := build(false)
	if off.Available(ai.JobExplainFinding) {
		t.Fatal("available with the module off")
	}
	calls := a.fake.total()
	_, err := off.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Question: "Explain."})
	if ae, ok := apierr.As(err); !ok || ae.Code != "ai_unavailable" || !strings.Contains(ae.Message, "off") {
		t.Fatalf("Brief with the module off = %v", err)
	}
	if a.fake.total() != calls {
		t.Fatal("the AI was asked with the module off")
	}
}
