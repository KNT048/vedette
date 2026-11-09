package core_test

import (
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/modules/core"
)

// matrixRoute is one route of core that this package implements, with the role CONTRACT.md gives it and a
// request that is harmless when the role is allowed (an unknown id, a body that is refused after the checks).
type matrixRoute struct {
	method, path, url string
	min               routes.Role
	body              any
}

var matrix = []matrixRoute{
	{"GET", "/me", "/me", routes.Viewer, nil},
	{"GET", "/modules", "/modules", routes.Viewer, nil},
	{"PATCH", "/modules/{id}", "/modules/core", routes.Admin, map[string]any{"enabled": false}},
	{"GET", "/core/general", "/core/general", routes.Viewer, nil},
	{"PUT", "/core/general", "/core/general", routes.Admin, map[string]any{"name": "x", "timezone": "UTC"}},
	{"GET", "/core/account", "/core/account", routes.Viewer, nil},
	{"PATCH", "/core/account", "/core/account", routes.Viewer, map[string]any{"name": " "}},
	{"POST", "/core/account/password", "/core/account/password", routes.Viewer, map[string]any{"current": "x", "next": "y"}},
	{"POST", "/core/account/2fa/start", "/core/account/2fa/start", routes.Viewer, map[string]any{"password": "x"}},
	{"POST", "/core/account/2fa/confirm", "/core/account/2fa/confirm", routes.Viewer, map[string]any{"code": "x"}},
	{"POST", "/core/account/2fa/email/start", "/core/account/2fa/email/start", routes.Viewer, map[string]any{"password": "x"}},
	{"POST", "/core/account/2fa/email/confirm", "/core/account/2fa/email/confirm", routes.Viewer, map[string]any{"code": "x"}},
	{"POST", "/core/account/2fa/disable", "/core/account/2fa/disable", routes.Viewer, map[string]any{"password": "x"}},
	{"DELETE", "/core/account/sessions/{id}", "/core/account/sessions/ses-nope", routes.Viewer, nil},
	{"POST", "/core/account/sessions/revoke-others", "/core/account/sessions/revoke-others", routes.Viewer, nil},
	{"GET", "/core/users", "/core/users", routes.Admin, nil},
	{"POST", "/core/users", "/core/users", routes.Admin, map[string]any{"name": "", "email": "x", "role": "viewer"}},
	{"PATCH", "/core/users/{id}", "/core/users/u-nope", routes.Admin, map[string]any{"disabled": true}},
	{"POST", "/core/users/{id}/reset-password", "/core/users/u-nope/reset-password", routes.Admin, nil},
	{"POST", "/core/users/{id}/2fa/reset", "/core/users/u-nope/2fa/reset", routes.Admin, nil},
	{"GET", "/core/audit", "/core/audit", routes.Admin, nil},
	{"GET", "/core/audit/export", "/core/audit/export?q=zzz", routes.Admin, nil},
}

var publicRoutes = []matrixRoute{
	{"GET", "/setup", "/setup", routes.Public, nil},
	{"GET", "/core/setup/modules", "/core/setup/modules", routes.Public, nil},
	{"POST", "/core/setup", "/core/setup", routes.Public, map[string]any{}},
	{"GET", "/core/auth-options", "/core/auth-options", routes.Public, nil},
	{"POST", "/auth/login", "/auth/login", routes.Public, map[string]any{"email": "x@y.zz", "password": "x"}},
	{"POST", "/auth/login/resend-code", "/auth/login/resend-code", routes.Public, map[string]any{"email": "x@y.zz", "password": "x"}},
	{"POST", "/auth/logout", "/auth/logout", routes.Public, nil},
}

func rankOf(r routes.Role) int {
	switch r {
	case routes.Viewer:
		return 1
	case routes.Operator:
		return 2
	case routes.Admin:
		return 3
	}
	return 0
}

// The role and authentication matrix of every core route this package implements: the role in the route
// table is the role of CONTRACT.md, anonymous gets 401 on every non-public route, a role below the minimum
// gets 403 forbidden, an allowed role gets anything but 401 and 403, and a state-changing request without
// the CSRF header is 403 csrf_invalid however high the role.
func TestContract_RoleAndAuthMatrix(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	byRole := map[routes.Role]*client{}
	for _, role := range []routes.Role{routes.Viewer, routes.Operator, routes.Admin} {
		c, _ := w.signIn(string(role)+"@acme.example", string(role))
		byRole[role] = c
	}
	anon := w.client()
	for _, rt := range append(append([]matrixRoute{}, matrix...), publicRoutes...) {
		op := ""
		for id, o := range routes.Operations {
			if o.Method == rt.method && o.Path == rt.path {
				op = id
				if o.MinRole != rt.min {
					t.Errorf("%s %s: the route table says %s, CONTRACT.md says %s", rt.method, rt.path, o.MinRole, rt.min)
				}
			}
		}
		if op == "" {
			t.Errorf("%s %s is not in the route table", rt.method, rt.path)
			continue
		}
		name := rt.method + " " + rt.path
		if rt.min == routes.Public {
			// Public means no session needed: 401 and the 501 stub never; the only 403 is the setup code's.
			if r := anon.request(rt.method, rt.url, rt.body); r.Code == http.StatusUnauthorized || (r.Code == http.StatusForbidden && r.code() != "invalid_setup_code") || r.Code == http.StatusNotImplemented {
				t.Errorf("%s (public) = %d %s", name, r.Code, r.Raw)
			}
			continue
		}
		if r := anon.request(rt.method, rt.url, rt.body); r.Code != 401 || r.code() != "unauthenticated" {
			t.Errorf("%s anonymous = %d %s", name, r.Code, r.Raw)
		}
		for role, c := range byRole {
			r := c.request(rt.method, rt.url, rt.body)
			switch {
			case rankOf(role) < rankOf(rt.min):
				if r.Code != 403 || r.code() != "forbidden" {
					t.Errorf("%s as %s = %d %s, want 403 forbidden", name, role, r.Code, r.Raw)
				}
			default:
				if r.Code == 401 || r.Code == 403 || r.Code == 501 {
					t.Errorf("%s as %s = %d %s, want it allowed", name, role, r.Code, r.Raw)
				}
				if rt.method != "GET" {
					nocsrf := c.request(rt.method, rt.url, rt.body, func(q *http.Request) { q.Header.Del("X-CSRF-Token") })
					if nocsrf.Code != 403 || nocsrf.code() != "csrf_invalid" {
						t.Errorf("%s as %s without CSRF = %d %s, want 403 csrf_invalid", name, role, nocsrf.Code, nocsrf.Raw)
					}
					wrong := c.request(rt.method, rt.url, rt.body, func(q *http.Request) { q.Header.Set("X-CSRF-Token", "x") })
					if wrong.Code != 403 || wrong.code() != "csrf_invalid" {
						t.Errorf("%s as %s with a wrong CSRF = %d, want 403 csrf_invalid", name, role, wrong.Code)
					}
				}
			}
		}
	}
}

// auditStep is one state-changing operation of core, run with valid input; run is the call alone (the state it
// needs is made before), and world is the world whose log it writes (the main one when nil).
type auditStep struct {
	op    string
	world *world
	run   func() reply
}

// implementedCoreMutations returns the operations of the core tag that change state (every method but GET)
// and that this package has a handler for: the method set of the handlers is the source, so a route added
// to the contract and implemented here cannot be missed by INV-2's harness. The ogen method name of an
// operation is its operationId in CamelCase, so both compare as lower-case letters and digits.
func implementedCoreMutations(t *testing.T, w *world) []string {
	t.Helper()
	have := map[string]bool{}
	for _, v := range []any{w.h, core.NewModuleHandlers(w.env.DB, w.reg)} {
		typ := reflect.TypeOf(v)
		for i := range typ.NumMethod() {
			have[strings.ToLower(typ.Method(i).Name)] = true
		}
	}
	var out []string
	for id, o := range routes.Operations {
		if o.Tag == "core" && o.Method != http.MethodGet && have[strings.ReplaceAll(id, "_", "")] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// Every state-changing operation of core that this package implements wrote core_audit in the same
// transaction (INV-2, SYS-3): each one, run with valid input, leaves a row. The list of operations to run
// comes from the route table and the handlers (implementedCoreMutations), not from a hand-written list: an
// operation without a step here fails the test, and so does a step for an operation that does not exist.
func TestContract_INV2_EveryCoreMutationIsAudited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	const adminEmail = "admin@acme.example"
	// State the steps need, made before any row is counted: other sessions of the administrator, and a user
	// with two-step sign-in on.
	c2, c3, c4 := w.client(), w.client(), w.client()
	wantOK(t, c2.login(adminEmail), 200)
	var c2ID string
	for _, s := range admin.get("/core/account").JSON["sessions"].([]any) { // the only other session is c2's
		if m := s.(map[string]any); m["current"] == false {
			c2ID = m["id"].(string)
		}
	}
	wantOK(t, c3.login(adminEmail), 200)
	wantOK(t, c4.login(adminEmail), 200)
	cy := w.env.User(t, "cy@acme.example", routes.Viewer)
	cySetup, err := w.env.Svc.StartTOTP(t.Context(), cy.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err := only(w.env.Svc.ConfirmTOTP(t.Context(), cy.ID, "", auth.TOTPCode(decodeBase32(t, cySetup.Secret), auth.TOTPStep(w.env.Clock.Now())))); err != nil {
		t.Fatal(err)
	}
	// The connection of the script has a LAN address; its Test goes to an in-process fake instead.
	conntest.NewHTTPS(t, nil).Redirect(t, "192.168.10.63:443")
	// The first-run setup needs a box of its own.
	w2 := newWorld(t)
	code2 := w2.openSetup()

	var bobID string
	var totpKey []byte
	var connID string
	const newPassword = "a brand new long password"
	steps := []auditStep{
		{"core_post_core_setup", w2, func() reply { return w2.client().post("/core/setup", setupBody(code2)) }},
		{"core_post_auth_login", nil, func() reply { return w.client().login(adminEmail) }},
		{"core_delete_core_account_sessions_id", nil, func() reply { return admin.delete("/core/account/sessions/" + c2ID) }},
		{"core_post_auth_logout", nil, func() reply { return c4.post("/auth/logout", nil) }},
		{"core_post_core_account_sessions_revoke_others", nil, func() reply { return admin.post("/core/account/sessions/revoke-others", nil) }},
		{"core_post_core_users", nil, func() reply {
			r := admin.post("/core/users", map[string]any{"name": "Bob", "email": "bob@acme.example", "role": "viewer"})
			bobID, _ = r.JSON["user"].(map[string]any)["id"].(string)
			return r
		}},
		{"core_patch_core_users_id", nil, func() reply { return admin.patch("/core/users/"+bobID, map[string]any{"role": "operator"}) }},
		{"core_post_core_users_id_reset_password", nil, func() reply { return admin.post("/core/users/"+bobID+"/reset-password", nil) }},
		{"core_post_core_users_id_2fa_reset", nil, func() reply { return admin.post("/core/users/"+cy.ID+"/2fa/reset", nil) }},
		{"core_patch_core_privacy", nil, func() reply { return admin.patch("/core/privacy", map[string]any{"telemetry": false}) }},
		{"core_put_core_general", nil, func() reply { return admin.putGeneral(map[string]any{"name": "Acme 2", "timezone": "UTC"}) }},
		{"core_patch_core_account", nil, func() reply { return admin.patch("/core/account", map[string]any{"name": "Ann 2"}) }},
		{"core_post_core_account_password", nil, func() reply {
			return admin.post("/core/account/password", map[string]any{"current": authtest.Password, "next": newPassword})
		}},
		{"core_patch_modules_id", nil, func() reply {
			return admin.patch("/modules/ai", map[string]any{"enabled": true, "with_dependencies": true})
		}},
		{"core_post_core_account_2fa_start", nil, func() reply {
			r := admin.post("/core/account/2fa/start", map[string]any{"password": newPassword})
			totpKey = decodeBase32(t, r.str("secret"))
			return r
		}},
		{"core_post_core_account_2fa_confirm", nil, func() reply {
			return admin.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(totpKey, auth.TOTPStep(w.env.Clock.Now()))})
		}},
		{"core_post_core_account_2fa_disable", nil, func() reply {
			return admin.post("/core/account/2fa/disable", map[string]any{"password": newPassword})
		}},
		{"core_post_core_account_2fa_email_start", nil, func() reply {
			return admin.post("/core/account/2fa/email/start", map[string]any{"password": newPassword})
		}},
		{"core_post_core_account_2fa_email_confirm", nil, func() reply {
			return admin.post("/core/account/2fa/email/confirm", map[string]any{"code": w.env.Mailer.LastCode()})
		}},
		{"core_post_core_connections", nil, func() reply {
			r := admin.post("/core/connections", connBody("Lab firewall", lanAt("192.168.10.63")))
			connID, _ = r.JSON["id"].(string)
			return r
		}},
		{"core_put_core_connections_id", nil, func() reply {
			return admin.put("/core/connections/"+connID, connBody("Lab firewall 2", map[string]any{"secret": "a-new-long-secret-value", "target": "https://192.168.10.63", "allow": []string{"https://192.168.10.63/api/"}})) //nolint:gosec // a test value
		}},
		{"core_post_core_connections_id_test", nil, func() reply { return admin.post("/core/connections/"+connID+"/test", nil) }},
		{"core_delete_core_connections_id", nil, func() reply { return admin.delete("/core/connections/" + connID) }},
		{"core_post_auth_login_resend_code", nil, func() reply {
			w.env.Clock.Advance(2 * time.Minute) // past the resend wait of the code mailed above
			return w.client().post("/auth/login/resend-code", map[string]any{"email": adminEmail, "password": newPassword})
		}},
	}

	byOp := map[string]bool{}
	for _, st := range steps {
		if _, ok := routes.Operations[st.op]; !ok {
			t.Errorf("step %q is not an operation of the contract", st.op)
		}
		if byOp[st.op] {
			t.Errorf("two steps for %q", st.op)
		}
		byOp[st.op] = true
	}
	implemented := implementedCoreMutations(t, w)
	for _, op := range implemented {
		if !byOp[op] {
			t.Errorf("%s is implemented and changes state, and has no step here: add one that shows it writes core_audit", op)
		}
	}
	for op := range byOp {
		if !slices.Contains(implemented, op) {
			t.Errorf("step %q is for an operation this package does not implement (or the handler lookup is broken)", op)
		}
	}
	for _, st := range steps {
		sw := st.world
		if sw == nil {
			sw = w
		}
		before := sw.env.Count(t, "SELECT count(*) FROM core_audit")
		r := st.run()
		if r.Code >= 400 {
			t.Fatalf("%s = %d %s", st.op, r.Code, r.Raw)
		}
		if sw.env.Count(t, "SELECT count(*) FROM core_audit") <= before {
			t.Errorf("%s changed state and left no core_audit row", st.op)
		}
	}
	// Refused requests change nothing and leave no row.
	before := w.env.Count(t, "SELECT count(*) FROM core_audit")
	wantStatus(t, admin.post("/core/users/"+bobID+"/2fa/reset", nil), 409, "not_on")
	if w.env.Count(t, "SELECT count(*) FROM core_audit") != before {
		t.Error("a refused reset left a core_audit row")
	}
}
