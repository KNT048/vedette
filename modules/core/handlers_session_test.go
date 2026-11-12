package core_test

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// setupAdmin runs the real first-run setup and returns the administrator's signed-in client.
func (w *world) setupAdmin() *client {
	w.t.Helper()
	code := w.openSetup()
	c := w.client()
	wantOK(w.t, c.post("/core/setup", setupBody(code)), 200)
	return c
}

func TestLogin_SetsOnlyTheThreeCookies(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.env.User(t, "ann@acme.example", "viewer")
	c := w.client()
	rec := c.post("/auth/login", map[string]any{"email": " Ann@Acme.Example ", "password": authtest.Password})
	wantOK(t, rec, 200)
	if rec.JSON["ok"] != true {
		t.Fatalf("login = %s", rec.Raw)
	}
	got := map[string]*http.Cookie{}
	for _, ck := range (&http.Response{Header: rec.Header}).Cookies() {
		got[ck.Name] = ck
	}
	if len(got) != 3 || got["__Host-vedette_session"] == nil || got["__Host-vedette_csrf"] == nil || got["__Secure-vedette_device"] == nil {
		t.Fatalf("cookies = %v", rec.Header.Values("Set-Cookie"))
	}
	type attr struct {
		httpOnly bool
		path     string
	}
	for name, want := range map[string]attr{"__Host-vedette_session": {true, "/"}, "__Host-vedette_csrf": {false, "/"}, "__Secure-vedette_device": {true, "/api/v1/auth/"}} {
		ck := got[name]
		if ck.HttpOnly != want.httpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != want.path || ck.Domain != "" || ck.MaxAge <= 0 {
			t.Errorf("%s = %+v", name, ck)
		}
	}
	if len(got["__Host-vedette_session"].Value) != 43 || len(got["__Host-vedette_csrf"].Value) != 43 || got["__Host-vedette_session"].Value == got["__Host-vedette_csrf"].Value {
		t.Error("session and CSRF tokens must be two distinct 256-bit values")
	}
	if rec.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header.Get("Cache-Control"))
	}
	if me := c.get("/me"); me.Code != 200 || me.str("email") != "ann@acme.example" {
		t.Fatalf("/me = %s", me.Raw)
	}
}

func TestLogin_ErrorsAreTheMocks(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.env.User(t, "ann@acme.example", "viewer")
	c := w.client()
	wrong := c.post("/auth/login", map[string]any{"email": "ann@acme.example", "password": "wrong password here"})
	unknown := c.post("/auth/login", map[string]any{"email": "nobody@acme.example", "password": "wrong password here"})
	wantStatus(t, wrong, 400, "invalid_credentials")
	wantStatus(t, unknown, 400, "invalid_credentials")
	if wrong.str("error", "message") != unknown.str("error", "message") {
		t.Fatal("an unknown email and a wrong password are told apart")
	}
	if c.signedIn() {
		t.Fatal("a failed login set a session")
	}
	// A body that is not the contract's shape is the generic 400, not a 500.
	wantStatus(t, c.request("POST", "/auth/login", nil), 400, "invalid")
}

// The walk of 2026-11-12 (findings G6): nine wrong passwords for one account, then the right one, signs in (the limit is ten
// failures, API_CONVENTIONS section 8). The tenth wrong one starts the wait: the right password is then refused with 429, the
// sentence the sign-in page shows, and Retry-After. Every client here shares one address, as behind the port proxy of a
// container-only install (the tester's sessions came from the bridge, 172.18.0.1).
func TestLogin_ThrottleAfterTenFailures(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.env.User(t, "ann@acme.example", "viewer")
	w.env.User(t, "bob@acme.example", "viewer")
	wrong := func(c *client, email string, n int) {
		for range n {
			wantStatus(t, c.post("/auth/login", map[string]any{"email": email, "password": "wrong password here"}), 400, "invalid_credentials")
		}
	}
	c := w.client()
	wrong(c, "ann@acme.example", 9)
	wantOK(t, c.login("ann@acme.example"), 200)

	c = w.client()
	wrong(c, "bob@acme.example", 10)
	r := c.login("bob@acme.example")
	wantStatus(t, r, 429, "rate_limited")
	if msg := r.str("error", "message"); msg != "Too many failed sign-in attempts. Try again in 30 seconds." {
		t.Fatalf("message = %q", msg)
	}
	if r.Header.Get("Retry-After") != "30" {
		t.Fatalf("Retry-After = %q", r.Header.Get("Retry-After"))
	}
}

func TestLogin_DisabledAccount(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	ann := w.env.User(t, "ann@acme.example", "viewer")
	ac := w.client()
	wantOK(t, ac.login(ann.Email), 200)
	wantOK(t, admin.patch("/core/users/"+ann.ID, map[string]any{"disabled": true}), 200)
	wantStatus(t, w.client().login(ann.Email), 403, "disabled")
	// Disabling ends every session of the account (INV-7): the live one is refused the next request.
	wantStatus(t, ac.get("/me"), 401, "unauthenticated")
}

// INV-8 over HTTP: no code gives 401 twofa_required with the method; wrong, expired, used-up and missing codes
// create no session; email-method accounts whose channel cannot send are 503, never password-only.
func TestContract_INV8_HTTPLoginFlows(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret := func() []byte {
		u := w.env.User(t, "app@acme.example", "viewer")
		c := w.client()
		wantOK(t, c.login(u.Email), 200)
		start := c.post("/core/account/2fa/start", map[string]any{"password": authtest.Password})
		wantOK(t, start, 200)
		key := decodeBase32(t, start.str("secret"))
		wantOK(t, c.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(key, auth.TOTPStep(w.env.Clock.Now()))}), 200)
		return key
	}()
	w.env.Clock.Advance(time.Minute)
	c := w.client()

	// app method
	r := c.login("app@acme.example")
	wantStatus(t, r, 401, "twofa_required")
	if r.str("error", "method") != "app" || c.signedIn() {
		t.Fatalf("twofa_required = %s", r.Raw)
	}
	bad := c.post("/auth/login", map[string]any{"email": "app@acme.example", "password": authtest.Password, "code": authtest.WrongTOTP(secret, w.env.Clock.Now())})
	wantStatus(t, bad, 400, "invalid_code")
	if c.signedIn() {
		t.Fatal("a wrong code created a session")
	}
	good := auth.TOTPCode(secret, auth.TOTPStep(w.env.Clock.Now()))
	wantOK(t, c.post("/auth/login", map[string]any{"email": "app@acme.example", "password": authtest.Password, "code": good}), 200)
	if !c.signedIn() {
		t.Fatal("the right code did not sign in")
	}
	// a code is used once
	c2 := w.client()
	wantStatus(t, c2.post("/auth/login", map[string]any{"email": "app@acme.example", "password": authtest.Password, "code": good}), 400, "invalid_code")

	// email method: the code is mailed by the first call, never returned.
	e := w.env.User(t, "mail@acme.example", "viewer")
	ec := w.client()
	wantOK(t, ec.login(e.Email), 200)
	wantOK(t, ec.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 200)
	wantOK(t, ec.post("/core/account/2fa/email/confirm", map[string]any{"code": w.env.Mailer.LastCode()}), 200)
	w.env.Clock.Advance(2 * time.Minute)
	c3 := w.client()
	r = c3.login(e.Email)
	wantStatus(t, r, 401, "twofa_required")
	if r.str("error", "method") != "email" || r.str("error", "sent_to") != "m•••@acme.example" || r.JSON["error"].(map[string]any)["resend_after"] != float64(60) {
		t.Fatalf("email twofa_required = %s", r.Raw)
	}
	code := w.env.Mailer.LastCode()
	if strings.Contains(r.Raw, code) || strings.Contains(r.Raw, "preview_code") {
		t.Fatal("the mailed code is in the response")
	}
	wantStatus(t, c3.post("/auth/login", map[string]any{"email": e.Email, "password": authtest.Password, "code": authtest.WrongCode(code)}), 400, "wrong_code")
	wantStatus(t, c3.post("/auth/login", map[string]any{"email": e.Email, "password": authtest.Password, "code": "12"}), 400, "invalid_code")
	if c3.signedIn() {
		t.Fatal("a wrong email code created a session")
	}
	// resend-code needs the password and the gap
	wantStatus(t, c3.post("/auth/login/resend-code", map[string]any{"email": e.Email, "password": "wrong password here"}), 400, "invalid_credentials")
	wantStatus(t, c3.post("/auth/login/resend-code", map[string]any{"email": e.Email, "password": authtest.Password}), 429, "resend_too_soon")
	w.env.Clock.Advance(61 * time.Second)
	sent := c3.post("/auth/login/resend-code", map[string]any{"email": e.Email, "password": authtest.Password})
	wantOK(t, sent, 200)
	if sent.str("sent_to") != "m•••@acme.example" || sent.JSON["resend_after"] != float64(60) || strings.Contains(sent.Raw, w.env.Mailer.LastCode()) {
		t.Fatalf("resend-code = %s", sent.Raw)
	}
	wantStatus(t, c3.post("/auth/login/resend-code", map[string]any{"email": "app@acme.example", "password": authtest.Password}), 409, "not_email_method")
	wantOK(t, c3.post("/auth/login", map[string]any{"email": e.Email, "password": authtest.Password, "code": w.env.Mailer.LastCode()}), 200)

	// the channel goes down: 503, with and without a code, and no session.
	w.env.Mailer.SetAvailable(false)
	c4 := w.client()
	wantStatus(t, c4.login(e.Email), 503, "twofa_email_unavailable")
	wantStatus(t, c4.post("/auth/login", map[string]any{"email": e.Email, "password": authtest.Password, "code": "123456"}), 503, "twofa_email_unavailable")
	wantStatus(t, c4.post("/auth/login/resend-code", map[string]any{"email": e.Email, "password": authtest.Password}), 503, "twofa_email_unavailable")
	if c4.signedIn() {
		t.Fatal("a dead email channel let the password alone in")
	}
}

// With no mailer at all (the process before notify exists) an email-method account gets 503 and GET
// /core/account says the email method is not available.
func TestContract_INV8_NoMailerMeansUnavailable(t *testing.T) {
	t.Parallel()
	w := newWorld(t, func(c *auth.Config) { c.Mailer = nil })
	u := w.env.User(t, "mail@acme.example", "viewer")
	if err := w.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_user SET twofa_method = 'email' WHERE id = ?", u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c := w.client()
	wantStatus(t, c.login(u.Email), 503, "twofa_email_unavailable")
	wantStatus(t, c.post("/auth/login", map[string]any{"email": u.Email, "password": authtest.Password, "code": "123456"}), 503, "twofa_email_unavailable")
	if c.signedIn() {
		t.Fatal("password-only sign-in for an email-method account")
	}
	v := w.env.User(t, "ann@acme.example", "viewer")
	vc := w.client()
	wantOK(t, vc.login(v.Email), 200)
	acc := vc.get("/core/account")
	wantOK(t, acc, 200)
	tw := acc.JSON["twofa_email"].(map[string]any)
	if tw["available"] != false || tw["reason"] == nil || tw["sent_to"] != "a•••@acme.example" {
		t.Fatalf("twofa_email = %v", tw)
	}
	wantStatus(t, vc.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 409, "email_channel_not_ready")
}

func TestLogout_ClearsCookiesAndNeverFails(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, _ := w.signIn("ann@acme.example", "viewer")
	sess := c.cookie("__Host-vedette_session").Value
	rec := c.post("/auth/logout", nil)
	if rec.Code != 204 || rec.Raw != "" {
		t.Fatalf("logout = %d %q", rec.Code, rec.Raw)
	}
	cleared := map[string]bool{}
	for _, ck := range (&http.Response{Header: rec.Header}).Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			cleared[ck.Name] = true
		}
	}
	if !cleared["__Host-vedette_session"] || !cleared["__Host-vedette_csrf"] || cleared["__Secure-vedette_device"] {
		t.Fatalf("cleared cookies = %v (%v)", cleared, rec.Header.Values("Set-Cookie"))
	}
	if c.signedIn() {
		t.Fatal("cookie still in the jar")
	}
	// The old cookie value is dead on the server too.
	old := w.client()
	old.jar["__Host-vedette_session"] = &http.Cookie{Name: "__Host-vedette_session", Value: sess, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	wantStatus(t, old.get("/me"), 401, "unauthenticated")
	// Already out, no cookie at all, garbage cookie: all 204.
	for _, cl := range []*client{c, w.client(), func() *client {
		g := w.client()
		g.jar["__Host-vedette_session"] = &http.Cookie{Name: "__Host-vedette_session", Value: "garbage", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
		return g
	}()} {
		if r := cl.post("/auth/logout", nil); r.Code != 204 {
			t.Fatalf("logout when out = %d %s", r.Code, r.Raw)
		}
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.logout'"); n != 1 {
		t.Fatalf("auth.logout rows = %d, want exactly 1", n)
	}
}

// INV-9 over HTTP: whatever the box answers, the only cookies it ever sets are the session, CSRF and device cookies.
func TestContract_INV9_HTTPOnlyTheNamedCookies(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	c := w.client()
	calls := []func() reply{
		func() reply { return c.get("/setup") }, func() reply { return c.get("/core/setup/modules") },
		func() reply { return c.get("/core/auth-options") }, func() reply { return c.login("admin@acme.example") },
		func() reply { return c.get("/me") }, func() reply { return c.get("/core/account") },
		func() reply { return c.post("/auth/logout", nil) }, func() reply { return c.get("/me") },
		func() reply { return admin.get("/core/users") }, func() reply { return admin.get("/core/audit") },
		func() reply { return admin.get("/core/audit/export") }, func() reply { return admin.get("/core/general") },
		func() reply { return c.login("nobody@acme.example") },
	}
	for _, f := range calls {
		r := f()
		for _, ck := range (&http.Response{Header: r.Header}).Cookies() {
			switch ck.Name {
			case "__Host-vedette_session", "__Host-vedette_csrf", "__Secure-vedette_device":
			default:
				t.Errorf("unexpected cookie %q", ck.Name)
			}
		}
	}
	for name := range c.seen {
		if name != "__Host-vedette_session" && name != "__Host-vedette_csrf" && name != "__Secure-vedette_device" {
			t.Errorf("seen cookie %q", name)
		}
	}
}

// D-77 through HTTP: the owner signs in from an IPv6 /64 whose key an insider has blocked, thanks to the cookie.
func TestContract_INV9_HTTPDeviceCookieBeatsTheInsider(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.env.User(t, "admin@acme.example", "admin")
	owner := w.client()
	owner.remote = "[2001:db8:0:1::2]:5000"
	wantOK(t, owner.login("admin@acme.example"), 200)
	if owner.cookie("__Secure-vedette_device") == nil {
		t.Fatal("no device cookie")
	}
	insider := w.client()
	for i := range 100 {
		insider.remote = fmt.Sprintf("[2001:db8:0:1::%x]:7000", i+0x100)
		wantStatus(t, insider.post("/auth/login", map[string]any{"email": "admin@acme.example", "password": "wrong password here"}), 400, "invalid_credentials")
	}
	insider.remote = "[2001:db8:0:1::99]:7000"
	r := insider.login("admin@acme.example")
	wantStatus(t, r, 429, "rate_limited")
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	owner.dropSession()
	wantOK(t, owner.login("admin@acme.example"), 200) // sends __Secure-vedette_device, which only reaches /api/v1/auth/*
	if !owner.signedIn() {
		t.Fatal("the owner with a device cookie was locked out")
	}
}
