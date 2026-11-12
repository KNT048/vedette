package inventory_test

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
	"github.com/knt048/vedette/modules/inventory"
)

type composite struct {
	server.Fallback
	*inventory.Handlers
}

type api struct {
	*env
	h    http.Handler
	gate *servertest.Gate
}

func newAPI(t *testing.T) *api {
	t.Helper()
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001"}}}))
	if _, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2"}); err != nil {
		t.Fatal(err)
	}
	gate := servertest.NewGate()
	h, err := server.New(server.Config{
		API:     composite{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, Handlers: inventory.NewHandlers(e.svc)},
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

func code(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (a *api) want(method, path, user, body string, status int, errCode string) map[string]any {
	a.t.Helper()
	got, m, raw := a.do(method, path, user, body)
	if got != status || (errCode != "" && code(m) != errCode) {
		a.t.Fatalf("%s %s as %s = %d %s (want %d %s): %s", method, path, user, got, code(m), status, errCode, raw)
	}
	return m
}

func TestHandlersRolesAndShapes(t *testing.T) {
	t.Parallel()
	a := newAPI(t)

	// who may do what comes from the route table
	a.want("GET", "/inventory/devices", "", "", 401, "unauthenticated")
	a.want("POST", "/inventory/devices", "viewer", `{"catalog_id":"fortigate"}`, 403, "forbidden")
	a.want("PUT", "/inventory/notify-new", "viewer", `{"enabled":false}`, 403, "forbidden")
	a.want("GET", "/inventory/settings", "operator", "", 403, "forbidden")
	a.want("PUT", "/inventory/settings", "operator", `{}`, 403, "forbidden")

	list := a.want("GET", "/inventory/devices", "viewer", "", 200, "")
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["is_box"] != true || list["notify_new"] != true || list["notify_available"] != false {
		t.Fatalf("list = %v", list)
	}
	if c := list["counts"].(map[string]any); c["all"] != float64(1) || c["manual"] != float64(0) {
		t.Fatalf("counts = %v", c)
	}

	created := a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","version":"7.2.5","name":"Branch FW","ip":"192.168.30.1"}`, 201, "")
	if created["display"] != "FortiGate" || created["kev_cves"].(float64) < 1 || created["id"] == "" {
		t.Fatalf("created = %v", created)
	}
	id := created["id"].(string)
	a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","ip":"192.168.30.1"}`, 409, "duplicate_ip")
	a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","name":"a<b"}`, 400, "bad_name")
	a.want("POST", "/inventory/devices", "operator", `{}`, 400, "unknown_product")
	if code := func() int { c, _, _ := a.do("POST", "/inventory/devices", "operator", `{not json`); return c }(); code != 400 {
		t.Fatalf("bad JSON = %d", code)
	}

	d := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")
	asset := d["asset"].(map[string]any)
	sw := asset["software"].([]any)[0].(map[string]any)
	if asset["origin"] != "manual" || asset["ip"] != "192.168.30.1" || asset["site"] != "hq" || sw["source"] != "manual" || len(sw["kev_cves"].([]any)) != 1 || len(d["kinds"].([]any)) != 13 {
		t.Fatalf("detail = %v", d)
	}
	var cur int
	for _, o := range d["observations"].([]any) {
		if o.(map[string]any)["current"] == true {
			cur++
		}
	}
	if cur != 3 { // vendor, hostname, kind
		t.Fatalf("%d current observations", cur)
	}
	a.want("GET", "/inventory/devices/a-nope", "viewer", "", 404, "not_found")

	a.want("PATCH", "/inventory/devices/"+id, "operator", `{"kind":"router","notes":"rack 2","regular_scan":"never"}`, 200, "")
	a.want("PATCH", "/inventory/devices/"+id, "operator", `{"kind":"toaster"}`, 400, "invalid")
	a.want("PATCH", "/inventory/devices/a-nope", "operator", `{"notes":"x"}`, 404, "not_found")
	a.want("POST", "/inventory/devices/"+id+"/suspicious", "operator", `{"suspicious":true}`, 200, "")
	if m := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, ""); m["suspicious"] != true {
		t.Fatalf("suspicious = %v", m["suspicious"])
	}
	a.want("POST", "/inventory/devices/"+id+"/approve", "operator", "", 200, "")

	// software
	c := a.want("POST", "/inventory/devices/"+id+"/software", "operator", `{"catalog_id":"openvpn-access-server","version":"2.13"}`, 201, "")
	if _, ok := c["kev_cves"]; !ok {
		t.Fatalf("software created = %v", c)
	}
	a.want("POST", "/inventory/devices/"+id+"/software", "operator", `{"catalog_id":"openvpn-access-server"}`, 409, "duplicate_software")
	var swID string
	for _, s := range a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")["asset"].(map[string]any)["software"].([]any) {
		if s.(map[string]any)["product"] == "Access Server" {
			swID = s.(map[string]any)["id"].(string)
		}
	}
	a.want("DELETE", "/inventory/devices/"+id+"/software/"+swID, "operator", "", 204, "")
	a.want("DELETE", "/inventory/devices/"+id+"/software/"+swID, "operator", "", 404, "not_found")

	// catalog
	cat := a.want("GET", "/inventory/catalog?q=forti", "viewer", "", 200, "")
	first := cat["items"].([]any)[0].(map[string]any)
	if first["id"] != "fortigate" || len(cat["items"].([]any)) > 30 || cat["total"].(float64) < 1 || first["kind"] != "firewall" {
		t.Fatalf("catalog = %v", cat)
	}
	a.want("GET", "/inventory/catalog", "viewer", "", 400, "invalid") // q is required by the contract

	// notify-new, settings
	if m := a.want("PUT", "/inventory/notify-new", "operator", `{"enabled":false}`, 200, ""); m["enabled"] != false {
		t.Fatalf("notify-new = %v", m)
	}
	set := a.want("GET", "/inventory/settings", "admin", "", 200, "")
	if set["scope_confirmed_at"] != nil || len(set["fragile_kinds"].([]any)) != 6 {
		t.Fatalf("settings = %v", set)
	}
	body := func(ranges string, on, confirmed bool) string {
		return `{"lan_ranges":` + ranges + `,"active":{"enabled":` + boolStr(on) + `,"days":[1,2,3],"from":"23:00","to":"05:00","rate":50,"exclusions":[]},"fragile_kinds":["nas"],"regular_scan_kinds":[],"scope_confirmed":` + boolStr(confirmed) + `,"scope_confirmed_at":null,"scope_confirmed_by":null}`
	}
	a.want("PUT", "/inventory/settings", "admin", body(`["192.168.18.0"]`, false, false), 400, "no_prefix")
	a.want("PUT", "/inventory/settings", "admin", body(`["192.168.18.0/24"]`, true, false), 400, "scope_not_confirmed")
	saved := a.want("PUT", "/inventory/settings", "admin", body(`["192.168.18.0/25"]`, true, true), 200, "")
	if saved["scope_confirmed_by"] != "admin@acme.example" || saved["scope_confirmed_at"] == nil || len(saved["adjusted"].([]any)) != 0 || saved["lan_ranges"].([]any)[0] != "192.168.18.0/25" {
		t.Fatalf("saved = %v", saved)
	}

	adj := a.want("PUT", "/inventory/settings", "admin", body(`["10.1.2.3/24"," 10.1.2.77/24"]`, false, false), 200, "")
	if adj["lan_ranges"].([]any)[0] != "10.1.2.0/24" || len(adj["lan_ranges"].([]any)) != 1 || adj["adjusted"].([]any)[0].(map[string]any)["from"] != "10.1.2.3/24" || len(adj["adjusted"].([]any)) != 2 {
		t.Fatalf("adjusted = %v", adj)
	}

	// 404 before 400, and schema errors name the full field path
	a.want("POST", "/inventory/devices/a-nope/software", "operator", `{"vendor":"only a vendor"}`, 404, "not_found")
	bad := a.want("PUT", "/inventory/settings", "admin", strings.Replace(body(`["10.0.0.0/8"]`, false, false), `"days":[1,2,3]`, `"days":[9]`, 1), 400, "invalid")
	if f := bad["error"].(map[string]any)["field"]; f != "active.days[0]" {
		t.Fatalf("field = %v: %v", f, bad)
	}
	seventeen := `["` + strings.Join([]string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16", "10.5.0.0/16", "10.6.0.0/16", "10.7.0.0/16", "10.8.0.0/16", "10.9.0.0/16", "10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16", "10.13.0.0/16", "10.14.0.0/16", "10.15.0.0/16", "10.16.0.0/16", "10.17.0.0/16"}, `","`) + `"]`
	bad = a.want("PUT", "/inventory/settings", "admin", body(seventeen, false, false), 400, "invalid")
	if f := bad["error"].(map[string]any)["field"]; f != "lan_ranges" {
		t.Fatalf("field = %v: %v", f, bad)
	}

	// import and export
	imp := a.want("POST", "/inventory/import", "operator", `{"filename":"d.csv","size":50,"sha256":"x","text":"name,product\nA,FortiGate\nB,Nope\n"}`, 200, "")
	if imp["created"] != float64(1) || imp["skipped"] != float64(1) || imp["errors"].([]any)[0].(map[string]any)["line"] != float64(3) {
		t.Fatalf("import = %v", imp)
	}
	a.want("POST", "/inventory/import", "operator", `{"filename":"d.csv","size":1,"sha256":"x","text":"  "}`, 400, "empty_file")
	status, _, raw := a.do("GET", "/inventory/export.csv", "viewer", "")
	if status != 200 || !strings.HasPrefix(raw, "\xef\xbb\xbfname,ip,") || !strings.Contains(raw, "Branch FW") {
		t.Fatalf("export = %d %q", status, raw)
	}
	status, _, raw = a.do("GET", "/inventory/import-template.csv", "viewer", "")
	if status != 200 || !strings.Contains(raw, "Branch firewall") {
		t.Fatalf("template = %d %q", status, raw)
	}
	for path, file := range map[string]string{"/inventory/export.csv": `attachment; filename="vedette-devices-`, "/inventory/import-template.csv": `attachment; filename="vedette-devices-template.csv"`} {
		r := httptest.NewRequestWithContext(t.Context(), "GET", server.Prefix+path, nil)
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "viewer", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w := httptest.NewRecorder()
		a.h.ServeHTTP(w, r)
		if h := w.Header(); h.Get("Content-Type") != "text/csv; charset=utf-8" || !strings.HasPrefix(h.Get("Content-Disposition"), file) || h.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s headers: %v", path, h)
		}
	}

	// delete: the box is 409, a device goes
	boxID := items[0].(map[string]any)["id"].(string)
	a.want("DELETE", "/inventory/devices/"+boxID, "operator", "", 409, "box_device")
	a.want("DELETE", "/inventory/devices/"+id, "operator", "", 204, "")
	a.want("GET", "/inventory/devices/"+id, "viewer", "", 404, "not_found")

	// the actor of every change is the signed-in user
	if a.count(`SELECT count(*) FROM core_audit WHERE user = 'it@acme.example' AND action = 'inventory.delete'`) != 1 ||
		a.count(`SELECT count(*) FROM core_audit WHERE user = 'admin@acme.example' AND action = 'inventory.settings'`) != 2 {
		t.Fatalf("audit = %v", a.auditActions())
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestHandlersModuleOffIsNotFound(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	a.gate.Set("inventory", false)
	a.want("GET", "/inventory/devices", "viewer", "", 404, "not_found")
	a.want("GET", "/inventory/catalog?q=x", "viewer", "", 404, "not_found")
	a.gate.Set("inventory", true)
	a.want("GET", "/inventory/devices", "viewer", "", 200, "")
}
