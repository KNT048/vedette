package ai_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/modules/ai"
)

type sentAlert struct {
	id, title, text string
	high            bool
}

// budgetWatch builds a service over a's database with Alert wired (a restart: the meter is seeded from ai_activity) and returns its
// budget-watch job.
func budgetWatch(t *testing.T, a *api, alerts *[]sentAlert) func(context.Context) error {
	t.Helper()
	svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now,
		Alert: func(_ context.Context, id, title, text string, high bool) error {
			*alerts = append(*alerts, sentAlert{id, title, text, high})
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range svc.Jobs() {
		if j.Name == "budget-watch" {
			if j.Housekeeping {
				t.Fatal("the budget watch calls out, so it is not housekeeping")
			}
			return j.Run
		}
	}
	t.Fatal("no budget-watch job although Alert is wired")
	return nil
}

// D-531: the box's monthly budget warns once at 80 % (medium) and once at 100 % (high), across restarts; raising the budget arms its
// alerts again. The text says the use, the renewal day and where to raise it.
func TestBudgetWatchWarnsAt80AndStopsAt100(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":10000,"redact_pii":true}`, 200, "")
	var alerts []sentAlert
	if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil || len(alerts) != 0 {
		t.Fatalf("nothing used: %v %v", err, alerts)
	}
	a.fake.setUsage(4000, 4500)
	a.explain("CVE-2022-27593", 200, "")
	for range 2 { // a second run and a restart send nothing more
		if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != 1 || alerts[0].high || !strings.Contains(alerts[0].title, "80 %") ||
		!strings.Contains(alerts[0].text, "8,500 of 10,000 tokens used this month (85 %)") || !strings.Contains(alerts[0].text, "renews on 1 December 2026") ||
		!strings.Contains(alerts[0].text, "Settings, AI assistant") {
		t.Fatalf("alerts at 85 %% = %+v", alerts)
	}
	// past 100 %: the call that passed it keeps its answer, the next is refused, and one high alert goes out
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-2"
	a.facts.mu.Unlock()
	a.fake.setUsage(1000, 1000)
	a.explain("CVE-2022-27593", 200, "")
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-3"
	a.facts.mu.Unlock()
	if msg := a.explain("CVE-2022-27593", 429, "budget_reached")["error"].(map[string]any)["message"].(string); !strings.HasPrefix(msg, "This month's AI budget of 10,000 tokens is used up, so AI jobs are stopped until it renews on 1 December 2026.") {
		t.Fatalf("message = %q", msg)
	}
	for range 2 {
		if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != 2 || !alerts[1].high || !strings.Contains(alerts[1].title, "is used up") || !strings.Contains(alerts[1].text, "AI jobs are stopped until the budget renews") {
		t.Fatalf("alerts at 105 %% = %+v", alerts)
	}
	// a higher budget arms its alerts again: at 105 % of 10,000 that is 42 % of 25,000, so nothing yet
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":25000,"redact_pii":true}`, 200, "")
	if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil || len(alerts) != 2 {
		t.Fatalf("after raising: %v %+v", err, alerts)
	}
	// a new month starts again from nothing
	a.clock.Add(31 * 24 * time.Hour)
	a.want("PUT", "/ai/config", "admin", `{"tier":"med","monthly_budget":10000,"redact_pii":true}`, 200, "")
	if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil || len(alerts) != 2 {
		t.Fatalf("new month: %v %+v", err, alerts)
	}
}

// D-531: a profile's own budget warns with the profile's name; the box's budget, far from 80 %, says nothing.
func TestBudgetWatchNamesTheProfile(t *testing.T) {
	a := newAPI(t)
	a.addProfile(strings.Replace(cloudBody("Claude", keyA), `"monthly_budget":60000`, `"monthly_budget":10000`, 1))
	a.fake.setAnswer(goodExplain)
	a.fake.setUsage(4000, 4500)
	a.explain("CVE-2022-27593", 200, "")
	var alerts []sentAlert
	if err := budgetWatch(t, a, &alerts)(a.ctx()); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].high || !strings.Contains(alerts[0].text, `The monthly budget of the AI profile "Claude"`) || !strings.Contains(alerts[0].text, "8,500 of 10,000") {
		t.Fatalf("alerts = %+v", alerts)
	}
	if p := a.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)[0].(map[string]any); p["used_month"] != float64(8500) || p["monthly_budget"] != float64(10000) {
		t.Fatalf("profile = %v", p)
	}
}

// D-531: the runaway fuse. A job may call the AI 30 times in a minute; the next call is refused before anything is sent (429
// rate_limited), the trip writes one audit line for the minute, and the next minute the job runs again.
func TestRunawayFuseCutsALoopAndSaysSo(t *testing.T) {
	a := newAskAPI(t)
	for range 30 {
		a.fake.play(turn{text: "Nothing."})
		a.ask("Which machines still expose RDP?", 200, "")
	}
	calls := a.fake.total()
	for range 2 {
		m := a.ask("Which machines still expose RDP?", 429, "rate_limited")
		if msg := m["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "more than 30 times in one minute, which looks like a loop") || !strings.Contains(msg, "Nothing was sent") {
			t.Fatalf("message = %q", msg)
		}
	}
	if a.fake.total() != calls {
		t.Fatal("a call past the fuse reached the provider")
	}
	n := 0
	for _, r := range a.auditRows() {
		if strings.HasPrefix(r, "ai.fuse ask-my-data ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("fuse audit lines = %d: %v", n, a.auditRows())
	}
	// another job is not held by this one's fuse, and the next minute this one runs again
	a.fake.setAnswer(goodExplain)
	a.explain("CVE-2022-27593", 200, "")
	a.clock.Add(time.Minute)
	a.fake.play(turn{text: "Nothing."})
	a.ask("Which machines still expose RDP?", 200, "")
}
