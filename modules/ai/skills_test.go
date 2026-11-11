package ai_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The ids and jobs of SKILL_DEFS in web/src/features/ai/harness.ts, in order.
var skillIDs = []string{"explain-finding", "cve-news", "log-digest", "log-investigate", "mitigation-config", "fingerprint-fallback",
	"translate-advisory", "weekly-report", "pdpl-assessment", "ask-my-data", "response-plan"}

func TestSkillsListAndSwitchPersist(t *testing.T) {
	a := newAPI(t)
	items := a.want("GET", "/ai/skills", "admin", "", 200, "")["items"].([]any)
	if len(items) != len(skillIDs) {
		t.Fatalf("skills = %d, want %d", len(items), len(skillIDs))
	}
	for i, it := range items {
		s := it.(map[string]any)
		if s["id"] != skillIDs[i] || s["enabled"] != true || s["name"] == "" || s["what"] == "" || s["jobs"] == nil {
			t.Fatalf("skill %d = %v", i, s)
		}
		want := 1
		if s["id"] == "fingerprint-fallback" {
			want = 0
		}
		if len(s["jobs"].([]any)) != want || (want == 1 && s["jobs"].([]any)[0] != s["id"]) {
			t.Errorf("jobs of %v = %v", s["id"], s["jobs"])
		}
	}
	got := a.want("PUT", "/ai/skills/log-digest", "admin", `{"enabled":false}`, 200, "")
	if got["id"] != "log-digest" || got["enabled"] != false || got["name"] != "Log digest" || len(got["jobs"].([]any)) != 1 {
		t.Fatalf("put = %v", got)
	}
	a.want("PUT", "/ai/skills/log-digest", "admin", `{"enabled":false}`, 200, "") // the same again is fine
	a.svc = a.newService()
	for _, it := range a.want("GET", "/ai/skills", "admin", "", 200, "")["items"].([]any) {
		s := it.(map[string]any)
		if s["enabled"] != (s["id"] != "log-digest") {
			t.Errorf("after a restart %v enabled = %v", s["id"], s["enabled"])
		}
	}
	a.want("PUT", "/ai/skills/log-digest", "admin", `{"enabled":true}`, 200, "")
	a.want("PUT", "/ai/skills/no-such-skill", "admin", `{"enabled":true}`, 404, "not_found")
	for _, body := range []string{`{}`, `{"enabled":"yes"}`, `{"enabled":true,"x":1}`, `[]`} {
		a.want("PUT", "/ai/skills/log-digest", "admin", body, 400, "")
	}
	rows := strings.Join(a.auditRows(), "\n")
	for _, want := range []string{"ai.skill log-digest off", "ai.skill log-digest on"} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %q: %s", want, rows)
		}
	}
}

// What a skill does at run time: a job whose skill is off does not run, and its button is not offered.
func TestSkillOffStopsItsJob(t *testing.T) {
	a := newAPI(t)
	id := a.withProfile()
	a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"log-digest": {id, ""}, "weekly-report": {id, ""}}), 200, "")
	spec := ai.JobSpec{Job: ai.JobLogDigest, Actor: "system", Task: "Do it.", Question: "Go.", Schema: &provider.Schema{Name: "s", JSON: []byte(`{"type":"object"}`)}, MaxTokens: 100}
	if !a.svc.Available(ai.JobLogDigest) {
		t.Fatal("the job is not available with its skill on")
	}
	a.want("PUT", "/ai/skills/log-digest", "admin", `{"enabled":false}`, 200, "")
	before := len(a.fake.reqsSent())
	_, err := a.svc.RunJob(a.ctx(), spec)
	var ae *apierr.Error
	if !asAPI(err, &ae) || ae.Status != 409 || ae.Code != "ai_unavailable" || !strings.Contains(ae.Message, "Log digest") {
		t.Fatalf("err = %#v", err)
	}
	if a.svc.Available(ai.JobLogDigest) || len(a.fake.reqsSent()) != before {
		t.Fatal("the job ran, or is offered, with its skill off")
	}
	if len(a.activity()) != 0 {
		t.Fatal("a refused job left an activity row")
	}
	spec.Job = ai.JobWeeklyReport // another skill is untouched
	if _, err := a.svc.RunJob(a.ctx(), spec); err != nil {
		t.Fatal(err)
	}
	a.want("PUT", "/ai/skills/log-digest", "admin", `{"enabled":true}`, 200, "")
	spec.Job = ai.JobLogDigest
	if _, err := a.svc.RunJob(a.ctx(), spec); err != nil {
		t.Fatal(err)
	}
}
