package core_test

import (
	"testing"

	"github.com/knt048/vedette/core/api/routes"
)

// The connection routes (D-93, slice 13b-1) are in the contract and the route table, but the store and the
// transports come with slices 13b-4 and 13b-5: until then core answers 501 not_implemented (the Fallback),
// never a made-up success, and the role and sign-in checks of the route table still run first.
func TestConnections_RoutesAreAdminOnlyAnd501UntilTheBackendExists(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin, _ := w.signIn("admin@acme.example", "admin")
	operator, _ := w.signIn("operator@acme.example", "operator")
	viewer, _ := w.signIn("viewer@acme.example", "viewer")
	anon := w.client()
	body := map[string]any{"name": "Lab", "kind": "http", "target": "https://192.168.10.1", "auth_type": "none", "allow": []string{"https://192.168.10.1/"}, "enabled": true}
	for _, rt := range []struct{ method, path string }{
		{"GET", "/core/connections"}, {"POST", "/core/connections"}, {"PUT", "/core/connections/cn-1"},
		{"DELETE", "/core/connections/cn-1"}, {"POST", "/core/connections/cn-1/test"},
	} {
		found := false
		for _, o := range routes.Operations {
			if o.Method == rt.method && o.Path == swapID(rt.path) {
				found = true
				if o.MinRole != routes.Admin {
					t.Errorf("%s %s: role %s in the route table, want admin", rt.method, rt.path, o.MinRole)
				}
			}
		}
		if !found {
			t.Errorf("%s %s is not in the route table", rt.method, rt.path)
		}
		send := func(c *client) reply {
			if rt.method == "POST" || rt.method == "PUT" {
				return c.request(rt.method, rt.path, body)
			}
			return c.request(rt.method, rt.path, nil)
		}
		if r := send(anon); r.Code != 401 {
			t.Errorf("%s %s anonymous = %d %s", rt.method, rt.path, r.Code, r.Raw)
		}
		for name, c := range map[string]*client{"viewer": viewer, "operator": operator} {
			if r := send(c); r.Code != 403 || r.code() != "forbidden" {
				t.Errorf("%s %s as %s = %d %s, want 403 forbidden", rt.method, rt.path, name, r.Code, r.Raw)
			}
		}
		if r := send(admin); r.Code != 501 || r.code() != "not_implemented" {
			t.Errorf("%s %s as admin = %d %s, want 501 not_implemented", rt.method, rt.path, r.Code, r.Raw)
		}
	}
}

// swapID turns the concrete id of a test path into the {id} of the route table.
func swapID(p string) string {
	const id = "cn-1"
	for i := 0; i+len(id) <= len(p); i++ {
		if p[i:i+len(id)] == id {
			return p[:i] + "{id}" + p[i+len(id):]
		}
	}
	return p
}
