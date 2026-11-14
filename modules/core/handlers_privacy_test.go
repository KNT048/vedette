package core_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
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
	if len(f) != 16 {
		t.Fatalf("flows = %s", r.Raw)
	}
	for id := 1; id <= 16; id++ {
		if _, ok := f[id]; !ok {
			t.Fatalf("flow %d missing", id)
		}
	}
	want := map[int]flowRow{
		1: {"on", "reason", nil}, 2: {"off", "switch", nil}, 3: {"off", "reason", false}, 4: {"conditional", "reason", nil},
		5: {"conditional", "reason", nil}, 6: {"on", "switch", nil}, 7: {"conditional", "reason", nil}, 8: {"off", "reason", nil},
		9: {"off", "reason", nil}, 10: {"on", "reason", nil}, 11: {"off", "reason", nil}, 12: {"off", "reason", nil},
		13: {"off", "reason", nil}, // mcp-server is off by default (D-234)
		15: {"off", "reason", nil}, // exposure is off by default; on, Shodan is asked only on a click (D-558)
		16: {"off", "reason", nil}, // Greenbone is off by default (D-563)
	}
	for id, w := range want {
		if f[id] != w {
			t.Errorf("flow %d = %+v, want %+v", id, f[id], w)
		}
	}
	tel, _ := r.JSON["telemetry"].(map[string]any)
	payload, _ := tel["payload"].(map[string]any)
	// D-82: the anonymous signal is never sent, so there is no last send and nothing to show, switch on or off.
	if tel["enabled"] != false || tel["last_sent"] != nil || payload == nil || len(payload) != 0 || r.JSON["update_check"] != true {
		t.Fatalf("privacy = %s", r.Raw)
	}
}

func TestPrivacy_PatchIsPartialAuditedAndFollowsModules(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	wantOK(t, admin.patch("/core/privacy", map[string]any{"update_check": false}), 200)
	r := admin.patch("/core/privacy", map[string]any{"telemetry": false})
	wantOK(t, r, 200)
	tel := r.JSON["telemetry"].(map[string]any)
	if tel["enabled"] != false || tel["last_sent"] != nil || len(tel["payload"].(map[string]any)) != 0 || r.JSON["update_check"] != false {
		t.Fatalf("patch = %s", r.Raw)
	}
	if f := flowsOf(t, r); f[2].state != "off" || f[6].state != "off" {
		t.Fatalf("flows = %+v", f)
	}
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

// D-154: nothing sends the anonymous signal, so PATCH {"telemetry": true} is 400 telemetry_unavailable (nothing written, no audit
// row, the update check untouched), also together with a valid update_check; GET says it is off, also on a box whose stored
// setting still says on from before.
func TestContract_INV10_TelemetryCannotBeTurnedOn(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	for _, body := range []map[string]any{{"telemetry": true}, {"telemetry": true, "update_check": false}} {
		wantStatus(t, admin.patch("/core/privacy", body), 400, "telemetry_unavailable")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action LIKE 'privacy.%'"); n != 0 {
		t.Errorf("a refused patch left %d audit rows", n)
	}
	g := admin.get("/core/privacy")
	if g.JSON["update_check"] != true || g.JSON["telemetry"].(map[string]any)["enabled"] != false || flowsOf(t, g)[2].state != "off" {
		t.Fatalf("get after the refusals = %s", g.Raw)
	}
	w.exec(`INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('core_privacy', '{"telemetry":true}', '2026-11-09T08:00:00.000Z', 'old')`)
	g = admin.get("/core/privacy")
	if g.JSON["telemetry"].(map[string]any)["enabled"] != false || flowsOf(t, g)[2].state != "off" {
		t.Fatalf("a stored telemetry:true must read as off: %s", g.Raw)
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
		c.loginTemp(role+"@acme.example", pw)
		wantOK(t, c.get("/core/privacy"), 200)
		wantStatus(t, c.patch("/core/privacy", map[string]any{"telemetry": false}), 403, "forbidden")
	}
}

type fakeFacts struct{ ai, ntp, oidc, conn, wazuh bool }

func (f fakeFacts) AIConfigured(context.Context) bool   { return f.ai }
func (f fakeFacts) NTPPublic(context.Context) bool      { return f.ntp }
func (f fakeFacts) OIDCConfigured(context.Context) bool { return f.oidc }
func (f fakeFacts) ConnectionsConfigured(context.Context) bool {
	return f.conn
}
func (f fakeFacts) WazuhConnected(context.Context) bool { return f.wazuh }

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
	// Flow 12 (D-93): on when the port says a connection is enabled, off otherwise, with a reason (no switch); no module condition.
	if s, _ := state(mk(fakeFacts{conn: true}), 12); s != "on" {
		t.Errorf("flow 12 with a connection = %s", s)
	}
	if s, _ := state(mk(fakeFacts{}), 12); s != "off" {
		t.Errorf("flow 12 without a connection = %s", s)
	}
	if s, _ := state(mk(nil), 12); s != "off" { // no port: nothing is configured
		t.Errorf("flow 12 without a port = %s", s)
	}
	if v, err := mk(fakeFacts{conn: true}).CoreGetCorePrivacy(t.Context()); err != nil || string(v.Flows[11].Control) != "reason" || v.Flows[11].ID != 12 {
		t.Errorf("flow 12 = %+v, %v", v.Flows[11], err)
	}
	if s, c := state(mk(nil), 3); s != "off" || c { // no port: no provider configured
		t.Errorf("flow 3 without a port = %s %v", s, c)
	}
	// Flow 14 (D-309): on only while a Wazuh server is saved and agent-intake is on.
	if s, _ := state(mk(fakeFacts{wazuh: true}), 14); s != "off" {
		t.Errorf("flow 14 with agent-intake off = %s", s)
	}
	wantOK(t, admin.patch("/modules/inventory", map[string]any{"enabled": true}), 200)
	wantOK(t, admin.patch("/modules/agent-intake", map[string]any{"enabled": true}), 200)
	if s, _ := state(mk(fakeFacts{wazuh: true}), 14); s != "on" {
		t.Errorf("flow 14 with Wazuh saved and the module on = %s", s)
	}
	if s, _ := state(mk(fakeFacts{}), 14); s != "off" {
		t.Errorf("flow 14 without a Wazuh server = %s", s)
	}
	if s, _ := state(mk(nil), 10); s != "on" { // no port: default NTP servers, public
		t.Errorf("flow 10 without a port = %s", s)
	}
	// A container-only install sends no time request of its own (S-CORE-4): flow 10 is off whatever the port says.
	cw := newWorldKind(t, true, nil)
	ch, err := core.NewAPIHandlers(core.HandlersConfig{DB: cw.env.DB, Auth: cw.env.Svc, Reg: cw.reg, Audit: cw.env.Audit, Secrets: cw.env.Secrets, Log: slog.New(slog.DiscardHandler), Facts: fakeFacts{ntp: true}})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := state(ch, 10); s != "off" {
		t.Errorf("flow 10 on a container-only install = %s", s)
	}
}

// rawPatch sends PATCH /core/privacy with a body as written (nil = no body at all).
func rawPatch(c *client, body *string) reply {
	c.w.t.Helper()
	return c.request("PATCH", "/core/privacy", nil, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		if body != nil {
			r.Body = io.NopCloser(strings.NewReader(*body))
			r.ContentLength = int64(len(*body))
		}
	})
}

func storedPrivacy(t *testing.T, w *world) (value, by string, ok bool) {
	t.Helper()
	err := w.env.DB.Reader().QueryRowContext(t.Context(), "SELECT value, updated_by FROM core_setting WHERE key = 'core_privacy'").Scan(&value, &by)
	if err != nil {
		return "", "", false
	}
	return value, by, true
}

// A PATCH of telemetry alone must keep an update_check that is OFF. (The branch's own test only shows that an
// update_check that is on by default stays on, which a wipe to "absent = on" would also give.)
func TestPrivacy_PatchOfOneSwitchKeepsTheOtherOff(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	wantOK(t, admin.patch("/core/privacy", map[string]any{"update_check": false}), 200)
	for _, v := range []bool{false, false} { // true is refused (TestPrivacy_TelemetryCannotBeTurnedOn)
		r := admin.patch("/core/privacy", map[string]any{"telemetry": v})
		wantOK(t, r, 200)
		if r.JSON["update_check"] != false {
			t.Fatalf("PATCH telemetry=%v turned update_check back on: %s", v, r.Raw)
		}
		if g := admin.get("/core/privacy"); g.JSON["update_check"] != false || g.JSON["telemetry"].(map[string]any)["enabled"] != v {
			t.Fatalf("GET after PATCH telemetry=%v = %s", v, g.Raw)
		}
	}
	val, _, ok := storedPrivacy(t, w)
	if !ok || val != `{"update_check":false,"telemetry":false}` {
		t.Fatalf("stored core_privacy = %q", val)
	}
}

// Two admins turning different switches at the same moment: neither change is lost (read-modify-write runs in
// the single writer).
func TestPrivacy_ConcurrentPatchesOfDifferentSwitchesLoseNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	for i := range 15 {
		wantOK(t, admin.patch("/core/privacy", map[string]any{"telemetry": false, "update_check": true}), 200)
		var wg sync.WaitGroup
		for _, f := range []string{"telemetry", "update_check"} {
			wg.Go(func() { wantOK(t, admin.patch("/core/privacy", map[string]any{f: false}), 200) })
		}
		wg.Wait()
		g := admin.get("/core/privacy")
		if g.JSON["update_check"] != false || g.JSON["telemetry"].(map[string]any)["enabled"] != false {
			t.Fatalf("round %d: a concurrent PATCH was lost: %s", i, g.Raw)
		}
	}
}

// Every malformed body is refused with 400 invalid and changes nothing (no setting row, no audit row).
func TestPrivacy_PatchRefusesMalformedBodiesAndChangesNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	s := func(v string) *string { return &v }
	for _, body := range []*string{nil, s(""), s("null"), s("[]"), s("true"), s(`"x"`), s(`{"telemetry":false,"x":1}`),
		s(`{"telemetry":"false"}`), s(`{"telemetry":0}`), s(`{"update_check":null}`), s(`{"telemetry":false}{}`), s(`{"telemetry":false`)} {
		r := rawPatch(admin, body)
		label := "<no body>"
		if body != nil {
			label = *body
		}
		if r.Code != 400 || r.code() != "invalid" {
			t.Errorf("%s = %d %s", label, r.Code, r.Raw)
		}
	}
	if _, _, ok := storedPrivacy(t, w); ok {
		t.Error("a refused PATCH wrote core_privacy")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action LIKE 'privacy.%'"); n != 0 {
		t.Errorf("a refused PATCH left %d audit rows", n)
	}
}

// An empty PATCH changes no switch, so it must not rewrite the setting either (INV-2: a write without an audit
// row). Today it upserts core_privacy and sets updated_by to the caller.
func TestPrivacy_EmptyPatchWritesNothingAndAuditsNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	wantOK(t, admin.patch("/core/privacy", map[string]any{}), 200)
	if v, by, ok := storedPrivacy(t, w); ok {
		t.Fatalf("an empty PATCH wrote core_privacy = %q by %s, with no audit row", v, by)
	}
}

// GET and PATCH answers have exactly the keys of the OpenAPI schema (additionalProperties: false, required).
func TestPrivacy_AnswersHaveExactlyTheSchemaKeys(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	keys := func(m map[string]any) []string {
		var k []string
		for x := range m {
			k = append(k, x)
		}
		slices.Sort(k)
		return k
	}
	check := func(name string, r reply) {
		t.Helper()
		if got := keys(r.JSON); !slices.Equal(got, []string{"flows", "telemetry", "update_check"}) {
			t.Errorf("%s keys = %v", name, got)
		}
		tel, _ := r.JSON["telemetry"].(map[string]any)
		if got := keys(tel); !slices.Equal(got, []string{"enabled", "last_sent", "payload"}) {
			t.Errorf("%s telemetry keys = %v", name, got)
		}
		if _, ok := r.JSON["update_check"].(bool); !ok {
			t.Errorf("%s update_check = %v", name, r.JSON["update_check"])
		}
		flows, _ := r.JSON["flows"].([]any)
		if len(flows) != 16 {
			t.Fatalf("%s flows = %d", name, len(flows))
		}
		for i, f := range flows {
			m := f.(map[string]any)
			for k := range m {
				if !slices.Contains([]string{"id", "state", "control", "configured"}, k) {
					t.Errorf("%s flow %d has key %q", name, i+1, k)
				}
			}
			if m["id"] != float64(i+1) || !slices.Contains([]any{"on", "off", "conditional"}, m["state"]) || !slices.Contains([]any{"switch", "reason"}, m["control"]) {
				t.Errorf("%s flow %d = %v", name, i+1, m)
			}
			if _, has := m["configured"]; has != (i+1 == 3) {
				t.Errorf("%s flow %d configured present = %v", name, i+1, has)
			}
		}
	}
	check("GET", admin.get("/core/privacy"))
	check("PATCH", admin.patch("/core/privacy", map[string]any{"telemetry": false}))
}
