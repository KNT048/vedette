package core_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func TestAccount_GetAndRename(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, u := w.signIn("ann@acme.example", "operator")
	other := w.client()
	wantOK(t, other.login(u.Email), 200)
	r := c.get("/core/account")
	wantOK(t, r, 200)
	user := r.JSON["user"].(map[string]any)
	if user["email"] != "ann@acme.example" || user["role"] != "operator" || user["twofa"] != false || user["twofa_method"] != nil || user["last_login"] == nil || user["created_at"] == nil {
		t.Fatalf("user = %v", user)
	}
	ss := r.JSON["sessions"].([]any)
	if len(ss) != 2 {
		t.Fatalf("sessions = %v", ss)
	}
	cur := 0
	for _, s := range ss {
		m := s.(map[string]any)
		if m["current"] == true {
			cur++
		}
		if m["device"] != "Test Browser/1.0" || m["ip"] != "192.0.2.10" {
			t.Fatalf("session = %v", m)
		}
	}
	if cur != 1 {
		t.Fatalf("%d current sessions", cur)
	}
	tw := r.JSON["twofa_email"].(map[string]any)
	if tw["available"] != true || tw["reason"] != nil {
		t.Fatalf("twofa_email = %v", tw)
	}

	wantOK(t, c.patch("/core/account", map[string]any{"name": "  Ann B  "}), 200)
	if got := c.get("/core/account").JSON["user"].(map[string]any)["name"]; got != "Ann B" {
		t.Fatalf("name = %v", got)
	}
	wantStatus(t, c.patch("/core/account", map[string]any{"name": "  "}), 400, "invalid_name")
	wantStatus(t, c.patch("/core/account", map[string]any{"name": strings.Repeat("n", 81)}), 400, "invalid_name")
	wantStatus(t, c.patch("/core/account", map[string]any{"name": "a\x07b"}), 400, "invalid_name")
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'account.profile' AND user = 'ann@acme.example'"); n != 1 {
		t.Fatalf("account.profile rows = %d", n)
	}
}

func TestAccount_TwofaEmailAvailability(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin() // the small bundle turns notify on
	r := admin.get("/core/account").JSON["twofa_email"].(map[string]any)
	if r["available"] != true {
		t.Fatalf("with notify on and a channel: %v", r)
	}
	w.env.Mailer.SetAvailable(false)
	r = admin.get("/core/account").JSON["twofa_email"].(map[string]any)
	if r["available"] != false || r["reason"] != "channel_not_ready" {
		t.Fatalf("channel down: %v", r)
	}
	wantOK(t, admin.patch("/modules/notify", map[string]any{"enabled": false}), 200)
	r = admin.get("/core/account").JSON["twofa_email"].(map[string]any)
	if r["available"] != false || r["reason"] != "module_off" {
		t.Fatalf("module off: %v", r)
	}
}

func TestAccount_PasswordChange(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, u := w.signIn("ann@acme.example", "viewer")
	phone := w.client()
	wantOK(t, phone.login(u.Email), 200)
	next := "another long password"
	wantStatus(t, c.post("/core/account/password", map[string]any{"current": "wrong password here", "next": next}), 400, "wrong_password")
	wantStatus(t, c.post("/core/account/password", map[string]any{"current": authtest.Password, "next": "short"}), 400, "weak_password")
	wantStatus(t, c.post("/core/account/password", map[string]any{"current": authtest.Password, "next": authtest.Password}), 400, "same_password")
	wantOK(t, c.post("/core/account/password", map[string]any{"current": authtest.Password, "next": next}), 200)
	// Other sessions end, this one stays.
	wantStatus(t, phone.get("/me"), 401, "unauthenticated")
	wantOK(t, c.get("/me"), 200)
	// The old password is dead, the new one works.
	wantStatus(t, w.client().login(u.Email), 400, "invalid_credentials")
	wantOK(t, w.client().post("/auth/login", map[string]any{"email": u.Email, "password": next}), 200)
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'account.password' AND user = 'ann@acme.example'"); n != 1 {
		t.Fatalf("account.password rows = %d", n)
	}
	if strings.Contains(w.logs.String(), next) {
		t.Fatal("the new password is in the logs")
	}
}

// D-76: both ways of turning two-step on need the current password, and a wrong one is counted.
func TestAccount_TwofaApp(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, u := w.signIn("ann@acme.example", "viewer")
	phone := w.client()
	wantOK(t, phone.login(u.Email), 200)

	wantStatus(t, c.post("/core/account/2fa/start", map[string]any{"password": "wrong password here"}), 400, "wrong_password")
	wantStatus(t, c.post("/core/account/2fa/confirm", map[string]any{"code": "123456"}), 409, "no_pending")
	r := c.post("/core/account/2fa/start", map[string]any{"password": authtest.Password})
	wantOK(t, r, 200)
	key := decodeBase32(t, r.str("secret"))
	if len(key) != 20 || !strings.HasPrefix(r.str("otpauth"), "otpauth://totp/Vedette:") || !strings.Contains(r.str("otpauth"), "secret="+r.str("secret")) {
		t.Fatalf("start = %s", r.Raw)
	}
	wantStatus(t, c.post("/core/account/2fa/confirm", map[string]any{"code": "12"}), 400, "invalid_code")
	wantStatus(t, c.post("/core/account/2fa/confirm", map[string]any{"code": "000000"}), 400, "wrong_code")
	if got := c.get("/me"); got.JSON["twofa"] != false {
		t.Fatal("two-step is on before it was confirmed")
	}
	wantOK(t, c.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(key, auth.TOTPStep(w.env.Clock.Now()))}), 200)
	me := c.get("/me")
	if me.JSON["twofa"] != true || me.JSON["twofa_method"] != "app" {
		t.Fatalf("/me = %s", me.Raw)
	}
	// Turning two-step on ends the other sessions, not this one.
	wantStatus(t, phone.get("/me"), 401, "unauthenticated")
	wantStatus(t, c.post("/core/account/2fa/start", map[string]any{"password": authtest.Password}), 409, "already_on")
	wantStatus(t, c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 409, "already_on")
	// Turning it off needs the password.
	wantStatus(t, c.post("/core/account/2fa/disable", map[string]any{"password": "wrong password here"}), 400, "wrong_password")
	wantOK(t, c.post("/core/account/2fa/disable", map[string]any{"password": authtest.Password}), 200)
	wantStatus(t, c.post("/core/account/2fa/disable", map[string]any{"password": authtest.Password}), 409, "not_on")
	if me := c.get("/me"); me.JSON["twofa"] != false || me.JSON["twofa_method"] != nil {
		t.Fatalf("/me = %s", me.Raw)
	}
	for _, a := range []string{"account.2fa_start", "account.2fa_on", "account.2fa_off"} {
		if w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ?", a) == 0 {
			t.Errorf("no %s audit row", a)
		}
	}
}

func TestAccount_TwofaEmail(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, _ := w.signIn("ann@acme.example", "viewer")
	wantStatus(t, c.post("/core/account/2fa/email/start", map[string]any{"password": "wrong password here"}), 400, "wrong_password")
	if len(w.env.Mailer.Sent()) != 0 {
		t.Fatal("a code was mailed on a wrong password")
	}
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "123456"}), 400, "no_code")
	r := c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password})
	wantOK(t, r, 200)
	if r.str("sent_to") != "a•••@acme.example" || r.JSON["resend_after"] != float64(60) || strings.Contains(r.Raw, w.env.Mailer.LastCode()) {
		t.Fatalf("start = %s", r.Raw)
	}
	wantStatus(t, c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 429, "resend_too_soon")
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "12"}), 400, "invalid_code")
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "000000"}), 400, "wrong_code")
	wantOK(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": w.env.Mailer.LastCode()}), 200)
	if me := c.get("/me"); me.JSON["twofa_method"] != "email" {
		t.Fatalf("/me = %s", me.Raw)
	}
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "000000"}), 409, "already_on")
	// 5 wrong tries cancel a code; an expired code is code_expired.
	wantOK(t, c.post("/core/account/2fa/disable", map[string]any{"password": authtest.Password}), 200)
	w.env.Clock.Advance(2 * time.Minute)
	wantOK(t, c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 200)
	for range 4 {
		wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "000000"}), 400, "wrong_code")
	}
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": "000000"}), 400, "too_many_tries")
	w.env.Clock.Advance(2 * time.Minute)
	wantOK(t, c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 200)
	w.env.Clock.Advance(11 * time.Minute)
	wantStatus(t, c.post("/core/account/2fa/email/confirm", map[string]any{"code": w.env.Mailer.LastCode()}), 400, "code_expired")
	// At most 5 codes an hour, whoever asks (the cooldown of 60 s is respected between the sends).
	w2 := newWorld(t)
	c2, _ := w2.signIn("bob@acme.example", "viewer")
	for range 5 {
		wantOK(t, c2.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 200)
		w2.env.Clock.Advance(61 * time.Second)
	}
	wantStatus(t, c2.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 429, "too_many_codes")
	// Channel down: the email method cannot be started.
	w.env.Mailer.SetAvailable(false)
	wantStatus(t, c.post("/core/account/2fa/email/start", map[string]any{"password": authtest.Password}), 409, "email_channel_not_ready")
}

func TestAccount_Sessions(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, u := w.signIn("ann@acme.example", "viewer")
	a, b := w.client(), w.client()
	wantOK(t, a.login(u.Email), 200)
	wantOK(t, b.login(u.Email), 200)
	var cur, otherID string
	for _, s := range c.get("/core/account").JSON["sessions"].([]any) {
		m := s.(map[string]any)
		if m["current"] == true {
			cur = m["id"].(string)
		} else if otherID == "" {
			otherID = m["id"].(string)
		}
	}
	wantStatus(t, c.delete("/core/account/sessions/"+cur), 400, "current_session")
	wantStatus(t, c.delete("/core/account/sessions/ses-nope"), 404, "not_found")
	if r := c.delete("/core/account/sessions/" + otherID); r.Code != 204 || r.Raw != "" {
		t.Fatalf("delete = %d %s", r.Code, r.Raw)
	}
	wantStatus(t, c.delete("/core/account/sessions/"+otherID), 404, "not_found") // already gone
	r := c.post("/core/account/sessions/revoke-others", nil)
	wantOK(t, r, 200)
	if r.JSON["ok"] != true || r.JSON["revoked"] != float64(1) {
		t.Fatalf("revoke-others = %s", r.Raw)
	}
	wantOK(t, c.get("/me"), 200)
	if r := c.post("/core/account/sessions/revoke-others", nil); r.JSON["revoked"] != float64(0) {
		t.Fatalf("revoke-others again = %s", r.Raw)
	}
	// Somebody else's session id is a 404, not a revoke.
	other, _ := w.signIn("bob@acme.example", "viewer")
	var bobSession string
	for _, s := range other.get("/core/account").JSON["sessions"].([]any) {
		bobSession = s.(map[string]any)["id"].(string)
	}
	wantStatus(t, c.delete("/core/account/sessions/"+bobSession), 404, "not_found")
	wantOK(t, other.get("/me"), 200)
}

// The end-to-end path of a new box: setup, sign in, me, change password, old sessions gone, sign out.
func TestEndToEnd_SetupLoginMePasswordLogout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	setup := w.setupAdmin()
	wantOK(t, setup.get("/me"), 200)

	laptop := w.client()
	wantOK(t, laptop.login("admin@acme.example"), 200)
	phone := w.client()
	phone.remote = "198.51.100.7:1111"
	wantOK(t, phone.login("admin@acme.example"), 200)
	me := laptop.get("/me")
	if me.str("name") != "Ann Admin" || me.str("org") != "Acme Co" {
		t.Fatalf("/me = %s", me.Raw)
	}

	next := "a brand new long password"
	wantOK(t, laptop.post("/core/account/password", map[string]any{"current": authtest.Password, "next": next}), 200)
	for name, old := range map[string]*client{"setup session": setup, "phone": phone} {
		if r := old.get("/me"); r.Code != 401 {
			t.Fatalf("%s survived the password change: %d", name, r.Code)
		}
	}
	wantOK(t, laptop.get("/me"), 200)
	wantStatus(t, w.client().login("admin@acme.example"), 400, "invalid_credentials")
	again := w.client()
	wantOK(t, again.post("/auth/login", map[string]any{"email": "admin@acme.example", "password": next}), 200)

	if r := laptop.post("/auth/logout", nil); r.Code != 204 {
		t.Fatalf("logout = %d", r.Code)
	}
	wantStatus(t, laptop.get("/me"), 401, "unauthenticated")
	wantOK(t, again.get("/me"), 200)
	// Every step left its audit row, in order, on one chain that verifies.
	var actions []string
	rows, err := w.env.DB.Reader().QueryContext(t.Context(), "SELECT action FROM core_audit ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
	}
	got := strings.Join(actions, " ")
	for _, want := range []string{"user.create", "core.setup", "auth.login", "account.password", "auth.logout"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit trail %q lacks %s", got, want)
		}
	}
	if res, err := auditVerify(t, w); err != nil || !res {
		t.Fatalf("the audit chain does not verify: %v", err)
	}
}

// A wrong password typed to turn two-step on, off or to change the password leaves auth.reauth_failed in the
// audit log: a stolen session guessing the password is visible to the administrator, as a wrong sign-in is.
func TestAccount_WrongReauthPasswordIsAudited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c, _ := w.signIn("ann@acme.example", "viewer")
	for path, body := range map[string]map[string]any{
		"/core/account/2fa/start":       {"password": "wrong password here"},
		"/core/account/2fa/disable":     {"password": "wrong password here"},
		"/core/account/password":        {"current": "wrong password here", "next": "a brand new long password"},
		"/core/account/2fa/email/start": {"password": "wrong password here"},
	} {
		before := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.reauth_failed'")
		wantStatus(t, c.post(path, body), 400, "wrong_password")
		if w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.reauth_failed'") != before+1 {
			t.Errorf("a wrong password at %s left no auth.reauth_failed row", path)
		}
	}
}

// Through HTTP, a second session of the owner (a stolen cookie) cannot try codes without bound against the
// authenticator key the owner started: five wrong codes drop the pending key, and the right one is then too
// late. (Before, 30 wrong codes were shown unlimited and the hit ended the owner's own sessions.)
func TestAccount_ConfirmTOTPGuessingByAnotherSessionIsBounded(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	owner, u := w.signIn("ann@acme.example", "viewer")
	thief := w.client()
	thief.remote = "198.51.100.7:1000"
	wantOK(t, thief.login(u.Email), 200) // stands for a stolen session cookie
	r := owner.post("/core/account/2fa/start", map[string]any{"password": authtest.Password})
	wantOK(t, r, 200)
	key := decodeBase32(t, r.str("secret"))
	cur := auth.TOTPStep(w.env.Clock.Now())
	valid := map[string]bool{}
	for d := int64(-1); d <= 1; d++ {
		valid[auth.TOTPCode(key, cur+d)] = true
	}
	var seen []string
	for n, tried := 0, 0; tried < 30; n++ {
		code := fmt.Sprintf("%06d", n)
		if valid[code] {
			continue
		}
		tried++
		g := thief.post("/core/account/2fa/confirm", map[string]any{"code": code})
		seen = append(seen, fmt.Sprintf("%d %s", g.Code, g.code()))
	}
	want := []string{"400 wrong_code", "400 wrong_code", "400 wrong_code", "400 wrong_code", "400 too_many_tries"}
	for i := 5; i < 30; i++ {
		want = append(want, "409 no_pending")
	}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("answers to 30 wrong codes = %v", seen)
	}
	wantStatus(t, thief.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(key, cur)}), 409, "no_pending")
	if owner.get("/me").Code != 200 || owner.get("/core/account").JSON["user"].(map[string]any)["twofa"] != false {
		t.Fatal("the guessing changed the owner's account")
	}
}

// Changing the password renews the session of the browser that did it: the response sets new session and CSRF
// cookies (the user stays signed in), the old token ends, and so does a copy of it that someone else holds.
// (OWASP Session Management: renew the session ID after a change of privilege or re-authentication.)
func TestAccount_PasswordChangeRenewsTheCurrentSession(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	owner, _ := w.signIn("ann@acme.example", "viewer")
	thief := w.client()
	thief.remote = "198.51.100.7:1000"
	thief.jar[auth.CookieSession] = owner.cookie(auth.CookieSession) // malware, an extension or a shared machine
	thief.jar[auth.CookieCSRF] = owner.cookie(auth.CookieCSRF)
	if thief.get("/me").Code != 200 {
		t.Fatal("the copy does not work before the change")
	}
	oldSession, oldCSRF := owner.cookie(auth.CookieSession).Value, owner.cookie(auth.CookieCSRF).Value
	r := owner.post("/core/account/password", map[string]any{"current": authtest.Password, "next": "a brand new long password"})
	wantOK(t, r, 200)
	set := map[string]*http.Cookie{}
	for _, ck := range (&http.Response{Header: r.Header}).Cookies() {
		set[ck.Name] = ck
	}
	for _, name := range []string{auth.CookieSession, auth.CookieCSRF} {
		ck := set[name]
		if ck == nil || ck.Value == "" || !ck.Secure || ck.Path != "/" || ck.Domain != "" || ck.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie %s after the change = %+v", name, ck)
		}
	}
	if set[auth.CookieSession].Value == oldSession || set[auth.CookieCSRF].Value == oldCSRF || set[auth.CookieSession].HttpOnly != true || set[auth.CookieCSRF].HttpOnly {
		t.Fatal("the cookies were not renewed, or lost an attribute")
	}
	if set[auth.CookieDevice] == nil { // the owner signed in here, so the browser sends its device cookie (D-77)
		t.Fatal("no new device cookie after the change")
	}
	delete(set, auth.CookieDevice)
	if len(set) != 2 {
		t.Fatalf("the change set %d other cookies, want the session and CSRF ones", len(set))
	}
	if g := thief.get("/me"); g.Code != 401 {
		t.Fatalf("a copy of the old session cookie = %d after the owner changed the password from that session", g.Code)
	}
	wantOK(t, owner.get("/me"), 200)                                                    // the owner stays signed in, with the new cookies
	wantOK(t, owner.patch("/core/account", map[string]any{"name": "Ann Renewed"}), 200) // and the new CSRF token works
}

// Turning two-step on and off renews the session of the browser that did it, like a password change: the old
// token (and a copy of it) ends, the other sessions end, and the browser keeps working on the new cookies.
func TestAccount_TwoStepChangesRenewTheCurrentSession(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	owner, u := w.signIn("ann@acme.example", "viewer")
	other := w.client()
	wantOK(t, other.login(u.Email), 200)
	copyOf := func() *client {
		c := w.client()
		c.jar[auth.CookieSession], c.jar[auth.CookieCSRF] = owner.cookie(auth.CookieSession), owner.cookie(auth.CookieCSRF)
		return c
	}

	copyOn := copyOf()
	r := owner.post("/core/account/2fa/start", map[string]any{"password": authtest.Password})
	wantOK(t, r, 200)
	key := decodeBase32(t, r.str("secret"))
	before := owner.cookie(auth.CookieSession).Value
	wantOK(t, owner.post("/core/account/2fa/confirm", map[string]any{"code": auth.TOTPCode(key, auth.TOTPStep(w.env.Clock.Now()))}), 200)
	if owner.cookie(auth.CookieSession).Value == before {
		t.Fatal("turning two-step on kept the session cookie")
	}
	if copyOn.get("/me").Code != 401 || other.get("/me").Code != 401 {
		t.Fatal("the old cookie or another session survived turning two-step on")
	}
	wantOK(t, owner.get("/me"), 200)

	copyOff := copyOf()
	before = owner.cookie(auth.CookieSession).Value
	wantOK(t, owner.post("/core/account/2fa/disable", map[string]any{"password": authtest.Password}), 200)
	if owner.cookie(auth.CookieSession).Value == before || copyOff.get("/me").Code != 401 {
		t.Fatal("turning two-step off kept the session cookie, or a copy of it still works")
	}
	wantOK(t, owner.get("/me"), 200)
}
