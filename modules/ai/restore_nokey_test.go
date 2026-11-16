package ai_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/ai"
)

// #847 (J7 #812): a backup restored without its decryption key leaves every saved API key sealed under another master key.

const aiLostWords = "was not restored (the backup was restored without its decryption key, or the box key changed)"

// restartWithoutTheKey starts the service again over the same database with another master key, as such a restore does, and serves it.
func (a *api) restartWithoutTheKey() (*api, *logBuffer) {
	a.t.Helper()
	other, err := secrets.New([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		a.t.Fatal(err)
	}
	buf := &logBuffer{}
	svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: other, Audit: audit.New(a.clock.Now), Log: slog.New(slog.NewTextHandler(buf, nil)), Clock: a.clock.Now, Factory: a.fake.factory, Facts: a.facts})
	if err != nil {
		a.t.Fatalf("the box must start: %v", err)
	}
	a.svc = svc
	return &api{env: a.env, h: a.handler(servertest.NewGate())}, buf
}

func lostMessage(t *testing.T, m map[string]any) string {
	t.Helper()
	msg, _ := m["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, aiLostWords) {
		t.Fatalf("message %q does not say the key was not restored", msg)
	}
	return msg
}

// A profile whose key cannot be opened is listed with key_lost (no 500, the module is not degraded); Test, the model list and an Edit
// with the key left blank are 409 secret_lost and send nothing; an Edit with the key typed again fixes it; Delete works without it.
func TestRestoreWithoutTheKeyProfileIsListedFixedOrDeleted(t *testing.T) {
	a := newAPI(t)
	claude := a.withProfile()
	gem := a.addProfile(strings.Replace(strings.Replace(cloudBody("Gem", keyB), `"kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com"`, `"kind":"gemini","api_style":"gemini","base_url":"https://generativelanguage.googleapis.com"`, 1), "claude-haiku-5-5", "gemini-2.5-flash", 1))["id"].(string)
	h, logs := a.restartWithoutTheKey()
	if d := a.svc.Degraded(); d != "" {
		t.Fatalf("a lost key degrades the whole module: %q", d)
	}
	if n := logs.count("cannot be opened with this box's master key"); n != 2 {
		t.Fatalf("%d warnings for two lost keys", n)
	}

	items := h.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("profiles = %v", items)
	}
	for _, it := range items {
		p := it.(map[string]any)
		if p["key_lost"] != true || p["usable"] != false || p["key_last4"] == nil {
			t.Fatalf("profile with a lost key = %v", p)
		}
	}
	if h.svc.Config().Configured || h.svc.Config().JobsReady["explain-finding"] {
		t.Fatal("a profile with a lost key counts as usable")
	}

	before := a.fake.total()
	lostMessage(t, h.want("POST", "/ai/profiles/test", "admin", `{"id":"`+claude+`","kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com","model":"claude-haiku-5-5","location":"cloud"}`, 409, "secret_lost"))
	h.want("POST", "/ai/profiles/models", "admin", `{"id":"`+claude+`","kind":"anthropic","api_style":"anthropic","base_url":"https://api.anthropic.com","location":"cloud"}`, 409, "secret_lost")
	h.want("PUT", "/ai/profiles/"+claude, "admin", strings.Replace(cloudBody("Claude", ""), `"api_key":"",`, "", 1), 409, "secret_lost")
	m := h.want("POST", "/ai/cve/CVE-2022-27593/explain", "operator", "", 409, "secret_lost")
	if msg := lostMessage(t, m); !strings.Contains(msg, `"Claude"`) || !strings.Contains(msg, "enters the key again") {
		t.Fatalf("job refusal %q", msg)
	}
	if a.fake.total() != before {
		t.Fatal("a request left the box with a lost key")
	}

	// Edit with the key typed again: usable at once, the job runs on it
	v := h.want("PUT", "/ai/profiles/"+claude, "admin", cloudBody("Claude", keyA), 200, "")
	if v["key_lost"] != false || v["usable"] != true || v["key_last4"] != "1111" {
		t.Fatalf("edited = %v", v)
	}
	h.want("POST", "/ai/cve/CVE-2022-27593/explain", "operator", "", 200, "")

	// it cannot be chosen to build the knowledge index either
	h.want("PUT", "/ai/knowledge/settings", "admin", `{"index_profile":"`+gem+`"}`, 409, "secret_lost")

	// Delete of the profile still lost: no key is opened, its secret row goes
	h.want("DELETE", "/ai/profiles/"+gem, "admin", "", 200, "")
	if n := len(h.want("GET", "/ai/profiles", "viewer", "", 200, "")["items"].([]any)); n != 1 {
		t.Fatalf("%d profiles after the delete", n)
	}
	var left int
	if err := a.db.Reader().QueryRowContext(a.ctx(), `SELECT count(*) FROM core_secret WHERE purpose = 'ai_profile.api_key'`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("%d keys left, %v", left, err)
	}
}

// A job whose primary profile lost its key falls over to the fallback (INV-2, never sent to the lost one); the lost profile stays where it
// was assigned but cannot be given a new job.
func TestRestoreWithoutTheKeyJobsFallOverAndAssignmentsKeepTheProfile(t *testing.T) {
	a := newAPI(t)
	claude := a.withProfile()
	h, _ := a.restartWithoutTheKey()
	lan := h.addProfile(internalBody("Lan"))["id"].(string)
	h.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"explain-finding": {claude, lan}}), 200, "")
	got := h.want("POST", "/ai/cve/CVE-2022-27593/explain", "operator", "", 200, "")
	if got["profile"] != "Lan" || a.fake.called("Claude") != 0 {
		t.Fatalf("answered by %v; calls to Claude %d", got["profile"], a.fake.called("Claude"))
	}
	for _, k := range a.fake.keysSeen() {
		if k != "" {
			t.Fatalf("a key was sent: %q", k)
		}
	}
	m := h.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"explain-finding": {claude, lan}, "cve-news": {claude, ""}}), 409, "secret_lost")
	lostMessage(t, m)
}
