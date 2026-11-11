package server_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
)

// D-180: a session opened with an administrator-set password may only read /me and change the password. Every other
// non-public operation of the route table answers 403 password_change_required, whatever its method or role.
func TestLimitedSessionReachesOnlyMeAndThePasswordChange(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.auth.Users["limited"] = server.Principal{ID: "u-new", Email: "new@acme.example", Role: routes.Admin, PasswordChangeRequired: true}
	param := regexp.MustCompile(`\{[^}]+\}`)
	allowed := map[string]bool{"core_get_me": true, "core_post_core_account_password": true}
	checked := 0
	for id, op := range routes.Operations {
		if op.MinRole == routes.Public {
			continue
		}
		rec := r.do(t, req{method: op.Method, path: param.ReplaceAllString(op.Path, "x"), user: "limited", body: "{}", csrf: true})
		limited := rec.Code == 403 && strings.Contains(rec.Body.String(), `"password_change_required"`)
		if allowed[id] == limited {
			t.Errorf("%s %s (%s) = %d %s: limited=%v, want %v", op.Method, op.Path, id, rec.Code, rec.Body, limited, !allowed[id])
		}
		checked++
	}
	if checked < 200 {
		t.Fatalf("only %d operations checked: the route table is not being walked", checked)
	}
	for id := range allowed {
		if _, ok := routes.Operations[id]; !ok {
			t.Errorf("limited-session operation %s is not in the route table", id)
		}
	}
}
