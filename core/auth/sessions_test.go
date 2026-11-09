package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/server"
)

func reqWith(res auth.LoginResult, method string, csrf string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/me", nil)
	for _, c := range res.Session.Cookies() {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // a request cookie: the browser sends only name and value
	}
	if csrf != "" {
		r.Header.Set(auth.HeaderCSRF, csrf)
	}
	return r
}

func lastSeen(t *testing.T, env *authtest.Env, id string) string {
	t.Helper()
	var s string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT last_seen FROM core_session WHERE id = ?", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}

	p, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", ""))
	if err != nil || p != (server.Principal{ID: u.ID, Email: u.Email, Role: routes.Viewer}) {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	// The role comes from the database on every request, not from the cookie.
	op := routes.Operator
	if _, err := env.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, u.ID, auth.UserPatch{Role: &op}); err != nil {
		t.Fatal(err)
	}
	if p, _ := env.Svc.Sessions.Authenticate(reqWith(res, "GET", "")); p.Role != routes.Operator {
		t.Fatalf("role after the change = %s", p.Role)
	}

	// Anything that is not a live session is server.ErrNoSession.
	noCookie := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	junk := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	junk.AddCookie(&http.Cookie{Name: auth.CookieSession, Value: "not-a-token"}) //nolint:gosec // a request cookie
	unknown := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	unknown.AddCookie(&http.Cookie{Name: auth.CookieSession, Value: res.Session.CSRFToken}) //nolint:gosec // a request cookie // well-formed, never issued as a session token
	for name, r := range map[string]*http.Request{"no cookie": noCookie, "malformed": junk, "unknown": unknown} {
		if _, err := env.Svc.Sessions.Authenticate(r); !errors.Is(err, server.ErrNoSession) {
			t.Errorf("%s: err = %v, want ErrNoSession", name, err)
		}
	}
}

func TestSessionLifetimes(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	alive := func(res auth.LoginResult) bool {
		_, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", ""))
		if err != nil && !errors.Is(err, server.ErrNoSession) {
			t.Fatal(err)
		}
		return err == nil
	}

	// Idle: 4 hours without a request.
	idle, _ := env.Login(t, u.Email, "")
	env.Clock.Advance(auth.IdleTimeout - time.Second)
	if !alive(idle) {
		t.Fatal("expired before the idle timeout")
	}
	env.Clock.Advance(auth.IdleTimeout - time.Second) // the request above was activity
	if !alive(idle) {
		t.Fatal("activity did not keep the session alive")
	}
	env.Clock.Advance(auth.IdleTimeout + time.Second)
	if alive(idle) {
		t.Fatal("still alive after the idle timeout")
	}

	// Absolute: 7 days from sign-in, however active.
	abs, _ := env.Login(t, u.Email, "")
	for range 55 { // 55 x 3 h = 165 h < 168 h
		env.Clock.Advance(3 * time.Hour)
		if !alive(abs) {
			t.Fatal("expired early")
		}
	}
	env.Clock.Advance(3*time.Hour + time.Second) // 168 h and a second in
	if alive(abs) {
		t.Fatal("alive past the absolute timeout")
	}
	if auth.IdleTimeout != 4*time.Hour || auth.AbsoluteTimeout != 7*24*time.Hour {
		t.Fatal("lifetimes changed: D-71 and API_CONVENTIONS must change with them")
	}
}

func TestLastSeenIsRefreshedAtMostOncePerMinute(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, _ := env.Login(t, u.Email, "")
	start := lastSeen(t, env, res.Session.SessionID)
	env.Clock.Advance(59 * time.Second)
	if _, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", "")); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(t, env, res.Session.SessionID); got != start {
		t.Fatalf("last_seen written after 59 s: %s -> %s", start, got)
	}
	env.Clock.Advance(2 * time.Second)
	if _, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", "")); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(t, env, res.Session.SessionID); got == start {
		t.Fatal("last_seen not refreshed after a minute")
	}
}

func TestCheckCSRF(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	a := env.User(t, "ann@acme.example", routes.Viewer)
	b := env.User(t, "bob@acme.example", routes.Viewer)
	resA, _ := env.Login(t, a.Email, "")
	resB, _ := env.Login(t, b.Email, "")
	pa, _ := env.Svc.Sessions.Authenticate(reqWith(resA, "POST", ""))

	tests := []struct {
		name string
		req  *http.Request
		ok   bool
	}{
		{"its own token", reqWith(resA, "POST", resA.Session.CSRFToken), true},
		{"no header", reqWith(resA, "POST", ""), false},
		{"wrong token", reqWith(resA, "POST", resB.Session.CSRFToken), false},
		{"the session token in the header", reqWith(resA, "POST", resA.Session.Token), false},
		{"garbage", reqWith(resA, "POST", "x"), false},
		{"no session cookie", func() *http.Request {
			r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
			r.Header.Set(auth.HeaderCSRF, resA.Session.CSRFToken)
			return r
		}(), false},
	}
	for _, tc := range tests {
		err := env.Svc.Sessions.CheckCSRF(tc.req, pa)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil {
			wantAPI(t, err, 403, "csrf_invalid")
		}
	}
	// A principal that is not the session's owner is refused too.
	pb, _ := env.Svc.Sessions.Authenticate(reqWith(resB, "POST", ""))
	wantAPI(t, env.Svc.Sessions.CheckCSRF(reqWith(resA, "POST", resA.Session.CSRFToken), pb), 403, "csrf_invalid")
}

func TestDisabledUserSessionIs403(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, _ := env.Login(t, u.Email, "")
	// Disabled behind the service's back (disabling through UpdateUser also ends the sessions).
	err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_user SET disabled = 1 WHERE id = ?", u.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.Sessions.Authenticate(reqWith(res, "GET", ""))
	wantAPI(t, err, 403, "disabled")
	_ = admin
}

func TestRevocation(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	other := env.User(t, "bob@acme.example", routes.Viewer)
	s1, _ := env.Login(t, u.Email, "")
	s2, _ := env.Login(t, u.Email, "")
	s3, _ := env.Login(t, u.Email, "")
	b1, _ := env.Login(t, other.Email, "")
	ok := func(r auth.LoginResult) bool {
		_, err := env.Svc.Sessions.Authenticate(reqWith(r, "GET", ""))
		return err == nil
	}

	list, err := env.Svc.Sessions.List(t.Context(), u.ID)
	if err != nil || len(list) != 3 || list[0].Device != "authtest" || list[0].IP != "192.0.2.1" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	cur, err := env.Svc.Sessions.CurrentID(reqWith(s1, "GET", ""))
	if err != nil || cur != s1.Session.SessionID {
		t.Fatalf("CurrentID = %q, %v", cur, err)
	}

	// Someone else's session is "not found", not an error that leaks it exists.
	wantAPI(t, env.Svc.Sessions.Revoke(t.Context(), u.Email, u.ID, b1.Session.SessionID), 404, "not_found")
	if !ok(b1) {
		t.Fatal("revoked another user's session")
	}
	if err := env.Svc.Sessions.Revoke(t.Context(), u.Email, u.ID, s2.Session.SessionID); err != nil {
		t.Fatal(err)
	}
	wantAPI(t, env.Svc.Sessions.Revoke(t.Context(), u.Email, u.ID, s2.Session.SessionID), 404, "not_found")
	if ok(s2) || !ok(s1) || !ok(s3) {
		t.Fatalf("after revoking s2: s1=%v s2=%v s3=%v", ok(s1), ok(s2), ok(s3))
	}

	n, err := env.Svc.Sessions.RevokeOthers(t.Context(), u.Email, u.ID, s1.Session.SessionID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeOthers = %d, %v", n, err)
	}
	if !ok(s1) || ok(s3) || !ok(b1) {
		t.Fatalf("after RevokeOthers: s1=%v s3=%v b1=%v", ok(s1), ok(s3), ok(b1))
	}
	if list, _ := env.Svc.Sessions.List(t.Context(), u.ID); len(list) != 1 {
		t.Fatalf("list after revocations = %d", len(list))
	}
	for _, action := range []string{"auth.session_revoke", "auth.sessions_revoke_others"} {
		if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ?", action) == 0 {
			t.Errorf("no %s audit row", action)
		}
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, _ := env.Login(t, u.Email, "")
	if err := env.Svc.Sessions.Logout(t.Context(), res.Session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", "")); !errors.Is(err, server.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}
	// Logging out again, with a stranger's token or with junk, is not an error and writes nothing.
	before := env.Count(t, "SELECT count(*) FROM core_audit")
	for _, tok := range []string{res.Session.Token, res.Session.CSRFToken, "junk", ""} {
		if err := env.Svc.Sessions.Logout(t.Context(), tok); err != nil {
			t.Fatalf("Logout(%q) = %v", tok, err)
		}
	}
	if env.Count(t, "SELECT count(*) FROM core_audit") != before {
		t.Fatal("repeat logouts wrote audit rows")
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.logout' AND target = ?", u.Email) != 1 {
		t.Fatal("expected exactly one auth.logout row")
	}
}
