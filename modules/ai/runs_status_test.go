package ai_test

import (
	"strings"
	"testing"
)

// GET /ai/runs tells the end of a call by a stable marker beside the activity row (POST-5, S-AI-4), never by its summary text: a
// profile that has used its own daily cap is capped; a call no profile could take (nothing was sent) is failed and its summary says
// it was not sent. Neither reads as a provider that did not answer.
func TestRunsTellAProfileCapAndANotSentCallFromAProviderFailure(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	a.addProfile(strings.Replace(cloudBody("Claude", keyA), `"daily_cap":60000`, `"daily_cap":1000`, 1))
	a.fake.setAnswer(goodExplain)
	a.fake.setUsage(1200, 300) // the first call passes the profile's own cap of 1,000
	a.explain("CVE-2022-27593", 200, "")
	a.facts.mu.Lock()
	a.facts.assets["CVE-2022-27593"][0].Name = "NAS-2" // a cache miss
	a.facts.mu.Unlock()
	calls := a.fake.total()
	a.explain("CVE-2022-27593", 409, "ai_unavailable")
	if a.fake.total() != calls {
		t.Fatal("the capped profile was asked")
	}
	runs := a.want("GET", "/ai/runs", "viewer", "", 200, "")["items"].([]any)
	if st := runs[0].(map[string]any)["status"]; st != "capped" {
		t.Fatalf("a profile over its own cap reads %v, want capped", st)
	}
	if got := a.outcomes(); got != "|capped" {
		t.Fatalf("outcomes = %q", got)
	}

	b := newAPI(t)
	b.withProfile()
	b.fake.mu.Lock()
	b.fake.noClient = "Claude"
	b.fake.mu.Unlock()
	b.explain("CVE-2022-27593", 409, "ai_unavailable")
	if b.fake.total() != 0 {
		t.Fatal("a request was sent")
	}
	runs = b.want("GET", "/ai/runs", "viewer", "", 200, "")["items"].([]any)
	if st := runs[0].(map[string]any)["status"]; st != "failed" {
		t.Fatalf("a call nothing was sent for reads %v, want failed", st)
	}
	if rows := b.activity(); len(rows) != 1 || !strings.HasPrefix(rows[0].Summary, "Not sent: no AI profile could take the call: Claude: ") {
		t.Fatalf("activity = %+v", rows)
	}
	if got := b.outcomes(); got != "not_sent" {
		t.Fatalf("outcomes = %q", got)
	}
}

// outcomes lists the outcome column of ai_activity, oldest first, joined by |.
func (a *api) outcomes() string {
	a.t.Helper()
	rows, err := a.db.Reader().QueryContext(a.ctx(), `SELECT COALESCE(outcome, '') FROM ai_activity ORDER BY seq`)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, o)
	}
	return strings.Join(out, "|")
}
