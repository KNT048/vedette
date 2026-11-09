package core_test

import (
	"net/http"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
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

// Every mutation of every route above wrote core_audit in the same transaction (INV-2, SYS-3): the routes
// that change state, run with valid input, each leave a row.
func TestContract_INV2_EveryCoreMutationIsAudited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	rows := func() int { return w.env.Count(t, "SELECT count(*) FROM core_audit") }
	step := func(name string, f func() reply) {
		t.Helper()
		before := rows()
		r := f()
		if r.Code >= 400 {
			t.Fatalf("%s = %d %s", name, r.Code, r.Raw)
		}
		if rows() <= before {
			t.Errorf("%s changed state and left no core_audit row", name)
		}
	}
	var bobID string
	step("POST /core/users", func() reply {
		r := admin.post("/core/users", map[string]any{"name": "Bob", "email": "bob@acme.example", "role": "viewer"})
		bobID, _ = r.JSON["user"].(map[string]any)["id"].(string)
		return r
	})
	step("PATCH /core/users/{id}", func() reply { return admin.patch("/core/users/"+bobID, map[string]any{"role": "operator"}) })
	step("POST /core/users/{id}/reset-password", func() reply { return admin.post("/core/users/"+bobID+"/reset-password", nil) })
	step("PUT /core/general", func() reply { return admin.putGeneral(map[string]any{"name": "Acme 2", "timezone": "UTC"}) })
	step("PATCH /core/account", func() reply { return admin.patch("/core/account", map[string]any{"name": "Ann 2"}) })
	step("POST /core/account/password", func() reply {
		return admin.post("/core/account/password", map[string]any{"current": "correct horse battery staple", "next": "a brand new long password"})
	})
	step("PATCH /modules/{id}", func() reply {
		return admin.patch("/modules/ai", map[string]any{"enabled": true, "with_dependencies": true})
	})
	step("POST /core/account/2fa/email/start", func() reply {
		return admin.post("/core/account/2fa/email/start", map[string]any{"password": "a brand new long password"})
	})
	step("POST /core/account/2fa/email/confirm", func() reply {
		return admin.post("/core/account/2fa/email/confirm", map[string]any{"code": w.env.Mailer.LastCode()})
	})
	// Refused requests change nothing and leave no row.
	before := rows()
	wantStatus(t, admin.post("/core/users/"+bobID+"/2fa/reset", nil), 409, "not_on")
	if rows() != before {
		t.Error("a refused reset left a core_audit row")
	}
}
