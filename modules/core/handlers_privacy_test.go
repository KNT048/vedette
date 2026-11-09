package core_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/knt048/vedette/modules/core"
)

type flowRow struct {
	state, control string
	configured     any
}

func flowsOf(t *testing.T, r reply) map[int]flowRow {
	t.Helper()
	list, _ := r.JSON["flows"].([]any)
	out := map[int]flowRow{}
	for _, f := range list {
		m := f.(map[string]any)
		out[int(m["id"].(float64))] = flowRow{m["state"].(string), m["control"].(string), m["configured"]}
	}
	return out
}

func TestPrivacy_GetDefaultsAndShape(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	r := admin.get("/core/privacy")
	wantOK(t, r, 200)
	f := flowsOf(t, r)
	if len(f) != 11 {
		t.Fatalf("flows = %s", r.Raw)
	}
	for id := 1; id <= 11; id++ {
		if _, ok := f[id]; !ok {
			t.Fatalf("flow %d missing", id)
		}
	}
	want := map[int]flowRow{
		1: {"on", "reason", nil}, 2: {"on", "switch", nil}, 3: {"off", "reason", false}, 4: {"conditional", "reason", nil},
		5: {"conditional", "reason", nil}, 6: {"on", "switch", nil}, 7: {"conditional", "reason", nil}, 8: {"off", "reason", nil},
		9: {"off", "reason", nil}, 10: {"on", "reason", nil}, 11: {"off", "reason", nil},
	}
	for id, w := range want {
		if f[id] != w {
			t.Errorf("flow %d = %+v, want %+v", id, f[id], w)
		}
	}
	tel, _ := r.JSON["telemetry"].(map[string]any)
	payload, _ := tel["payload"].(map[string]any)
	// D-82: the anonymous signal is never sent, so there is no last send and nothing to show, switch on or off.
	if tel["enabled"] != true || tel["last_sent"] != nil || payload == nil || len(payload) != 0 || r.JSON["update_check"] != true {
		t.Fatalf("privacy = %s", r.Raw)
	}
}

func TestPrivacy_PatchIsPartialAuditedAndFollowsModules(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	r := admin.patch("/core/privacy", map[string]any{"telemetry": false})
	wantOK(t, r, 200)
	tel := r.JSON["telemetry"].(map[string]any)
	if tel["enabled"] != false || tel["last_sent"] != nil || len(tel["payload"].(map[string]any)) != 0 || r.JSON["update_check"] != true {
		t.Fatalf("patch = %s", r.Raw)
	}
	if f := flowsOf(t, r); f[2].state != "off" || f[6].state != "on" {
		t.Fatalf("flows = %+v", f)
	}
	wantOK(t, admin.patch("/core/privacy", map[string]any{"update_check": false}), 200)
	g := admin.get("/core/privacy") // both stick: the second patch did not touch the first switch
	if g.JSON["update_check"] != false || g.JSON["telemetry"].(map[string]any)["enabled"] != false {
		t.Fatalf("get = %s", g.Raw)
	}
	if f := flowsOf(t, g); f[2].state != "off" || f[6].state != "off" {
		t.Fatalf("flows = %+v", f)
	}
	for _, a := range [][2]string{{"privacy.telemetry", "off"}, {"privacy.update_check", "off"}} {
		if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ? AND detail = ? AND user = 'admin@acme.example'", a[0], a[1]); n != 1 {
			t.Errorf("audit %v rows = %d", a, n)
		}
	}
	wantOK(t, admin.patch("/core/privacy", map[string]any{}), 200)
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action LIKE 'privacy.%'"); n != 2 {
		t.Errorf("an empty patch left audit rows: %d", n)
	}

	// Flows that follow a module: AI flows need the module on; exposure is on with its module.
	wantOK(t, admin.patch("/modules/exposure", map[string]any{"enabled": true}), 200)
	if f := flowsOf(t, admin.get("/core/privacy")); f[9].state != "on" {
		t.Errorf("flow 9 with exposure on = %+v", f[9])
	}
}

func TestPrivacy_PatchIsStrict(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	for _, body := range []map[string]any{{"telemetry": "yes"}, {"update_check": 1}, {"telemetry": nil}, {"other": true}} {
		r := admin.patch("/core/privacy", body)
		if r.Code != 400 || r.code() != "invalid" {
			t.Errorf("%v = %d %s", body, r.Code, r.Raw)
		}
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action LIKE 'privacy.%'"); n != 0 {
		t.Errorf("a refused patch left %d audit rows", n)
	}
}

func TestPrivacy_Roles(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	for _, role := range []string{"viewer", "operator"} {
		wantOK(t, admin.post("/core/users", map[string]any{"name": "U " + role, "email": role + "@acme.example", "role": role}), 201)
	}
	wantStatus(t, w.client().get("/core/privacy"), 401, "unauthenticated")
	for _, role := range []string{"viewer", "operator"} {
		c := w.client()
		reset := admin.get("/core/users")
		id := ""
		for _, it := range reset.JSON["items"].([]any) {
			if it.(map[string]any)["email"] == role+"@acme.example" {
				id = it.(map[string]any)["id"].(string)
			}
		}
		pw := admin.post("/core/users/"+id+"/reset-password", nil).str("temp_password")
		wantOK(t, c.post("/auth/login", map[string]any{"email": role + "@acme.example", "password": pw}), 200)
		wantOK(t, c.get("/core/privacy"), 200)
		wantStatus(t, c.patch("/core/privacy", map[string]any{"telemetry": false}), 403, "forbidden")
	}
}

type fakeFacts struct{ ai, ntp, oidc bool }

func (f fakeFacts) AIConfigured(context.Context) bool   { return f.ai }
func (f fakeFacts) NTPPublic(context.Context) bool      { return f.ntp }
func (f fakeFacts) OIDCConfigured(context.Context) bool { return f.oidc }

// The "configured" facts of other modules come through the port: AI needs the module on as well.
func TestPrivacy_FactsPort(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	mk := func(f core.PrivacyFacts) *core.APIHandlers {
		h, err := core.NewAPIHandlers(core.HandlersConfig{DB: w.env.DB, Auth: w.env.Svc, Reg: w.reg, Audit: w.env.Audit, Secrets: w.env.Secrets, Log: slog.New(slog.DiscardHandler), Facts: f})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	state := func(h *core.APIHandlers, id int) (string, bool) {
		v, err := h.CoreGetCorePrivacy(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f := v.Flows[id-1]
		return string(f.State), f.Configured.Or(false)
	}
	h := mk(fakeFacts{ai: true, ntp: false, oidc: true})
	if s, c := state(h, 3); s != "off" || c { // ai configured, module off
		t.Errorf("flow 3 with the module off = %s %v", s, c)
	}
	if s, _ := state(h, 10); s != "off" {
		t.Errorf("flow 10 with internal NTP = %s", s)
	}
	if s, _ := state(h, 11); s != "off" { // auth-oidc module is off
		t.Errorf("flow 11 with the module off = %s", s)
	}
	r := admin.patch("/modules/ai", map[string]any{"enabled": true})
	wantOK(t, r, 200)
	if s, c := state(h, 3); s != "on" || !c {
		t.Errorf("flow 3 with the module on = %s %v", s, c)
	}
	if s, _ := state(h, 8); s != "conditional" {
		t.Errorf("flow 8 with ai on = %s", s)
	}
	if s, c := state(mk(nil), 3); s != "off" || c { // no port: no provider configured
		t.Errorf("flow 3 without a port = %s %v", s, c)
	}
	if s, _ := state(mk(nil), 10); s != "on" { // no port: default NTP servers, public
		t.Errorf("flow 10 without a port = %s", s)
	}
}
