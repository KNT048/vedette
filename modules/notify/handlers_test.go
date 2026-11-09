package notify_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules/notify"
)

type composite struct {
	server.Fallback
	*notify.NotifyHandlers
}

type api struct {
	*env
	h    http.Handler
	gate *servertest.Gate
}

func newAPI(t *testing.T) *api {
	t.Helper()
	e := newEnv(t)
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:     composite{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, NotifyHandlers: notify.NewNotifyHandlers(e.svc)},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: gate,
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &api{env: e, h: h, gate: gate}
}

func (a *api) do(method, path, user, body string) (int, map[string]any, string) {
	a.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(a.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, r)
	var out map[string]any
	raw := w.Body.String()
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, raw)
		}
	}
	return w.Code, out, raw
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (a *api) want(method, path, user, body string, status int, code string) map[string]any {
	a.t.Helper()
	got, m, raw := a.do(method, path, user, body)
	if got != status || (code != "" && errCode(m) != code) {
		a.t.Fatalf("%s %s as %s = %d %s (want %d %s): %s", method, path, user, got, errCode(m), status, code, raw)
	}
	return m
}

const tgBody = `{"enabled":true,"fields":{"chat_id":"-1002145678901"},"secret":"` + tgToken + `","min_severity":"medium"}`

func TestHandlersRolesAndShapes(t *testing.T) {
	a := newAPI(t)

	// who may do what comes from the route table
	a.want("GET", "/notify/channels", "", "", 401, "unauthenticated")
	a.want("GET", "/notify/channels", "operator", "", 403, "forbidden")
	a.want("GET", "/notify/history", "operator", "", 403, "forbidden")
	a.want("PUT", "/notify/rules", "operator", `{}`, 403, "forbidden")
	a.want("PATCH", "/notify/incidents/in-1", "viewer", `{"status":"resolved"}`, 403, "forbidden")
	a.want("POST", "/notify/history/sd-1/resend", "viewer", "", 403, "forbidden")

	ch := a.want("GET", "/notify/channels", "admin", "", 200, "")
	list := ch["channels"].([]any)
	if len(list) != 6 || ch["email_code_users"] != float64(0) {
		t.Fatalf("channels = %v", ch)
	}
	var order []string
	for _, c := range list {
		m := c.(map[string]any)
		order = append(order, m["type"].(string))
		if m["configured"] != false || m["enabled"] != false || m["secret_last4"] != nil || m["last_test"] != nil || m["approvals"] != false || m["min_severity"] != "medium" ||
			len(m["fields"].(map[string]any)) != 0 || len(m["approvers"].([]any)) != 0 {
			t.Fatalf("blank channel = %v", m)
		}
		if al := m["approval_last4"].(map[string]any); al["app_token"] != nil || al["bot_token"] != nil {
			t.Fatalf("approval_last4 = %v", al)
		}
	}
	if strings.Join(order, ",") != "telegram,slack,zalo,zalo-personal,email,webhook" {
		t.Fatalf("order = %v", order)
	}
	if q := ch["quiet"].(map[string]any); q["from"] != "22:00" || q["to"] != "06:30" {
		t.Fatalf("quiet = %v", q)
	}

	// save
	a.want("PUT", "/notify/channels/telegram", "admin", `{"enabled":true,"fields":{"chat_id":"x"},"secret":"`+tgToken+`","min_severity":"medium"}`, 400, "bad_chat_id")
	got, saved, raw := a.do("PUT", "/notify/channels/telegram", "admin", tgBody)
	if got != 200 || strings.Contains(raw, tgSecret) || saved["secret_last4"] != tgToken[len(tgToken)-4:] || saved["configured"] != true || saved["last_test"] != nil {
		t.Fatalf("save = %d %s", got, raw)
	}
	a.want("PUT", "/notify/channels/fax", "admin", tgBody, 400, "invalid") // the mock says 404 not_found: ogen checks the enum first
	a.want("PUT", "/notify/channels/telegram", "admin", `{"enabled":true,"fields":{},"min_severity":"info"}`, 400, "invalid")

	// test
	a.want("POST", "/notify/channels/webhook/test", "admin", "", 400, "not_configured")
	tr := a.want("POST", "/notify/channels/telegram/test", "admin", "", 200, "")
	if tr["ok"] != true || tr["detail"] == "" || tr["at"] == "" {
		t.Fatalf("test = %v", tr)
	}
	if c := a.want("GET", "/notify/channels", "admin", "", 200, "")["channels"].([]any)[0].(map[string]any); c["last_test"] == nil {
		t.Fatalf("last_test missing: %v", c)
	}

	// rules
	a.want("PUT", "/notify/rules", "admin", `{"quiet":{"enabled":true,"from":"22:00","to":"22:00","allow_critical":true},"grouping":{"enabled":true,"window_min":60}}`, 400, "bad_quiet")
	a.want("PUT", "/notify/rules", "admin", `{"quiet":{"enabled":true,"from":"22:00","to":"23:00","allow_critical":true},"grouping":{"enabled":true,"window_min":30}}`, 400, "invalid")
	r := a.want("PUT", "/notify/rules", "admin", `{"quiet":{"enabled":true,"from":"22:00","to":"06:30","allow_critical":true},"grouping":{"enabled":false,"window_min":240}}`, 200, "")
	if r["grouping"].(map[string]any)["window_min"] != float64(240) || r["quiet"].(map[string]any)["enabled"] != true {
		t.Fatalf("rules = %v", r)
	}

	// delete
	a.want("DELETE", "/notify/channels/telegram", "admin", "", 204, "")
	a.want("DELETE", "/notify/channels/webhook", "admin", "", 204, "")
	if c := a.want("GET", "/notify/channels", "admin", "", 200, "")["channels"].([]any)[0].(map[string]any); c["configured"] != false || c["secret_last4"] != nil {
		t.Fatalf("after delete: %v", c)
	}

	// module off: no route
	a.gate.Set("notify", false)
	a.want("GET", "/notify/channels", "admin", "", 404, "")
	a.gate.Set("notify", true)
}

func TestHandlersIncidentsHistoryAndNotices(t *testing.T) {
	a := newAPI(t)
	a.want("GET", "/notify/incidents", "viewer", "", 200, "")
	if m := a.want("GET", "/notify/incidents", "viewer", "", 200, ""); len(m["incidents"].([]any)) != 0 {
		t.Fatalf("incidents = %v", m)
	}
	a.want("GET", "/notify/incidents/in-nope", "viewer", "", 404, "not_found")
	a.want("PATCH", "/notify/incidents/in-nope", "operator", `{"status":"resolved"}`, 404, "not_found")
	a.want("GET", "/notify/alerts/al-nope/target", "viewer", "", 404, "not_found")
	if m := a.want("GET", "/notify/findings/f-1/notices", "viewer", "", 200, ""); m["sends"] == nil || len(m["sends"].([]any)) != 0 {
		t.Fatalf("notices = %v", m)
	}
	a.want("GET", "/notify/history", "admin", "", 200, "")
	h := a.want("GET", "/notify/history", "admin", "", 200, "")
	if len(h["items"].([]any)) != 0 || h["suppressed"].(map[string]any)["days"] != float64(7) {
		t.Fatalf("history = %v", h)
	}

	a.telegram(notify.Low)
	id, _, err := a.svc.OpenIncident(a.ctx(), notify.IncidentInput{Kind: notify.IncidentBadAddress, Source: "192.168.10.105", Target: "185.220.101.47", Title: "PC-SALES-02 connected to 185.220.101.47",
		Severity: notify.High, What: "w", Action: "a", Link: "/logs", Devices: []notify.Device{{ID: "a-pc05", Name: "PC-SALES-02"}}})
	if err != nil {
		t.Fatal(err)
	}
	a.flush()
	l := a.want("GET", "/notify/incidents", "viewer", "", 200, "")["incidents"].([]any)
	if len(l) != 1 {
		t.Fatalf("incidents = %v", l)
	}
	i := l[0].(map[string]any)
	if i["id"] != id || i["kind"] != "bad_address" || i["count"] != float64(1) || i["status"] != "new" || i["handled_by"] != nil || i["handled_at"] != nil || i["note"] != nil ||
		len(i["sends"].([]any)) != 1 || i["devices"].([]any)[0].(map[string]any)["name"] != "PC-SALES-02" || i["link"] != "/logs" {
		t.Fatalf("incident = %v", i)
	}
	d := a.want("GET", "/notify/incidents/"+id, "viewer", "", 200, "")
	if p := d["previews"].([]any); len(p) != 1 || p[0].(map[string]any)["channel"] != "telegram" {
		t.Fatalf("previews = %v", d["previews"])
	}
	p := a.want("PATCH", "/notify/incidents/"+id, "operator", `{"status":"acknowledged","note":"on it"}`, 200, "")
	if inc := p["incident"].(map[string]any); inc["status"] != "acknowledged" || inc["handled_by"] != "it@acme.example" || inc["note"] != "on it" {
		t.Fatalf("patched = %v", inc)
	}
	a.want("PATCH", "/notify/incidents/"+id, "operator", `{"status":"resolved","note":"`+strings.Repeat("x", 501)+`"}`, 400, "invalid") // the schema has maxLength 500: ogen answers before note_too_long
	a.want("PATCH", "/notify/incidents/"+id, "operator", `{"status":"nope"}`, 400, "invalid")
	if to := a.want("GET", "/notify/alerts/"+id+"/target", "viewer", "", 200, ""); to["to"] != "/incidents/"+id {
		t.Fatalf("target = %v", to)
	}

	hist := a.want("GET", "/notify/history", "admin", "", 200, "")["items"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history = %v", hist)
	}
	it := hist[0].(map[string]any)
	if it["kind"] != "incident" || it["channel"] != "telegram" || it["ok"] != true || it["link"] != "/incidents/"+id {
		t.Fatalf("history item = %v", it)
	}
	if _, has := it["error"]; has {
		t.Fatalf("a send that worked has an error field: %v", it)
	}
	rs := a.want("POST", "/notify/history/"+it["id"].(string)+"/resend", "operator", "", 200, "")
	if rs["ok"] != true || rs["id"] == it["id"] || rs["kind"] != "incident" {
		t.Fatalf("resend = %v", rs)
	}
	a.want("POST", "/notify/history/sd-nope/resend", "operator", "", 404, "not_found")
	a.want("DELETE", "/notify/channels/telegram", "admin", "", 204, "")
	a.want("POST", "/notify/history/"+it["id"].(string)+"/resend", "operator", "", 409, "channel_not_ready")

	// vulnerability notices
	a.telegram(notify.Low)
	a.plain()
	if err := a.svc.Publish(a.ctx(), a.vulnNotice("v1", "WordPress", "CVE-2026-7", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	a.flush()
	fn := a.want("GET", "/notify/findings/f-v1/notices", "viewer", "", 200, "")["sends"].([]any)
	if len(fn) != 1 || fn[0].(map[string]any)["channel"] != "telegram" || fn[0].(map[string]any)["ok"] != true {
		t.Fatalf("finding notices = %v", fn)
	}
	if to := a.want("GET", "/notify/alerts/v1/target", "viewer", "", 200, ""); to["to"] != "/findings/f-v1" {
		t.Fatalf("target = %v", to)
	}
}
