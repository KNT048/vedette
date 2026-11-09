package core_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// prefixOK checks the browser rules of the cookie name prefixes on a raw Set-Cookie line:
// __Host- needs Secure, Path=/ and no Domain; __Secure- needs Secure.
func prefixOK(t *testing.T, where, line string) {
	t.Helper()
	name, _, _ := strings.Cut(line, "=")
	attrs := strings.ToLower(line)
	switch {
	case strings.HasPrefix(name, "__Host-"):
		if !strings.Contains(attrs, "; secure") || !strings.Contains(attrs, "; path=/;") && !strings.HasSuffix(attrs, "; path=/") || strings.Contains(attrs, "domain=") {
			t.Errorf("%s: %q breaks the __Host- rules", where, line)
		}
	case strings.HasPrefix(name, "__Secure-"):
		if !strings.Contains(attrs, "; secure") {
			t.Errorf("%s: %q breaks the __Secure- rules", where, line)
		}
	default:
		t.Errorf("%s: cookie %q has no prefix", where, name)
	}
}

// every Set-Cookie of sign-in, renewal and logout meets its prefix rules; a request
// that still carries the old cookies after a renewal (an in-flight one) gets 401 and sets no cookie, so it
// cannot clear the new ones in the browser.
func TestCookiePrefixesAndStaleRequestAfterRenewal(t *testing.T) {
	w := newWorld(t)
	u := w.env.User(t, "ann@acme.example", "viewer")
	c := w.client()
	r := c.login(u.Email)
	wantOK(t, r, 200)
	names := map[string]bool{}
	for _, line := range r.Header.Values("Set-Cookie") {
		prefixOK(t, "login", line)
		n, _, _ := strings.Cut(line, "=")
		names[n] = true
	}
	for _, n := range []string{auth.CookieSession, auth.CookieCSRF, auth.CookieDevice} {
		if !names[n] {
			t.Errorf("login did not set %s", n)
		}
	}
	stale := w.client()
	stale.jar[auth.CookieSession], stale.jar[auth.CookieCSRF] = c.cookie(auth.CookieSession), c.cookie(auth.CookieCSRF)

	r = c.post("/core/account/password", map[string]any{"current": authtest.Password, "next": "a brand new long password"})
	wantOK(t, r, 200)
	for _, line := range r.Header.Values("Set-Cookie") {
		prefixOK(t, "password change", line)
	}

	g := stale.get("/me")
	if g.Code != 401 || len(g.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("stale GET = %d, Set-Cookie %v", g.Code, g.Header.Values("Set-Cookie"))
	}
	p := stale.patch("/core/account", map[string]any{"name": "x y"})
	if p.Code != 401 && p.Code != 403 || len(p.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("stale PATCH = %d %s, Set-Cookie %v", p.Code, p.code(), p.Header.Values("Set-Cookie"))
	}
	wantOK(t, c.get("/me"), 200)

	r = c.post("/auth/logout", nil)
	if r.Code/100 != 2 {
		t.Fatalf("logout = %d %s", r.Code, r.Raw)
	}
	cleared := map[string]bool{}
	for _, line := range r.Header.Values("Set-Cookie") {
		prefixOK(t, "logout", line)
		ck, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatal(err)
		}
		if ck.MaxAge < 0 {
			cleared[ck.Name] = true
		}
	}
	if !cleared[auth.CookieSession] || !cleared[auth.CookieCSRF] {
		t.Fatalf("logout cleared %v", cleared)
	}
}

// D-77: the owner has just proved the old password, so a browser that came with a valid device cookie gets a
// new one for the new password (the old one died with the credential version); a browser without one gets
// none.
// A password change proves the current password in this browser, as a sign-in does, so the browser gets a device
// cookie for the new password whether or not it sent one (the cookie path is /api/v1/auth/: browsers do not send it
// to /core/account/password).
func TestPasswordChangeIssuesADeviceCookieLikeASignIn(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ann := w.env.User(t, "ann@acme.example", "viewer")
	bob := w.env.User(t, "bob@acme.example", "viewer")
	next := "a brand new long password"

	c := w.client()
	wantOK(t, c.login(ann.Email), 200)
	old := c.cookie(auth.CookieDevice)
	if old == nil {
		t.Fatal("no device cookie after sign-in")
	}
	r := c.post("/core/account/password", map[string]any{"current": authtest.Password, "next": next})
	wantOK(t, r, 200)
	fresh := c.cookie(auth.CookieDevice)
	if fresh == nil || fresh.Value == old.Value {
		t.Fatalf("device cookie after the change = %v, want a new one", fresh)
	}
	for _, line := range r.Header.Values("Set-Cookie") {
		prefixOK(t, "password change", line)
	}
	if !w.env.Svc.ValidDevice(t.Context(), ann.ID, fresh.Value) || w.env.Svc.ValidDevice(t.Context(), ann.ID, old.Value) {
		t.Fatal("the new device cookie is not valid for the new password, or the old one still is")
	}
	if w.env.Svc.ValidDevice(t.Context(), bob.ID, fresh.Value) {
		t.Fatal("ann's device cookie is valid for bob")
	}

	d := w.client()
	wantOK(t, d.login(bob.Email), 200)
	delete(d.jar, auth.CookieDevice)
	r = d.post("/core/account/password", map[string]any{"current": authtest.Password, "next": next})
	wantOK(t, r, 200)
	got := d.cookie(auth.CookieDevice)
	if got == nil || !w.env.Svc.ValidDevice(t.Context(), bob.ID, got.Value) {
		t.Fatalf("device cookie after a password change without one = %v, want a valid new one", got)
	}
}
