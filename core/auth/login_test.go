package auth_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store/coredb"
)

func TestLoginSuccess(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Admin)

	res, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: "  Ann@ACME.example ", Password: authtest.Password, IP: ip("::ffff:192.0.2.7"), UserAgent: "Mozilla/5.0\x00 (X11)\n"})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.ID != u.ID || res.User.Role != routes.Admin || res.User.LastLogin == nil {
		t.Fatalf("user = %+v", res.User)
	}
	cs := res.Session.Cookies()
	if len(cs) != 2 {
		t.Fatalf("%d cookies, want exactly the session and CSRF cookies", len(cs))
	}
	for _, c := range cs {
		if !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 7*24*3600 {
			t.Errorf("cookie %s = %+v", c.Name, c)
		}
		if (c.Name == auth.CookieSession) != c.HttpOnly {
			t.Errorf("cookie %s HttpOnly = %v", c.Name, c.HttpOnly)
		}
		if len(c.Value) != 43 {
			t.Errorf("cookie %s value is %d characters, want 43 (32 bytes base64url)", c.Name, len(c.Value))
		}
	}
	if cs[0].Name != "vedette_session" || cs[1].Name != "vedette_csrf" || cs[0].Value == cs[1].Value {
		t.Fatalf("cookies = %v", cs)
	}

	// The database holds hashes only.
	var tokenHash, csrfHash, device, ip string
	err = env.DB.Reader().QueryRowContext(t.Context(), "SELECT token_hash, csrf_hash, device, ip FROM core_session WHERE id = ?", res.Session.SessionID).Scan(&tokenHash, &csrfHash, &device, &ip)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(res.Session.Token))
	c := sha256.Sum256([]byte(res.Session.CSRFToken))
	if tokenHash != hex.EncodeToString(h[:]) || csrfHash != hex.EncodeToString(c[:]) {
		t.Fatal("session row does not hold the SHA-256 of the cookie values")
	}
	if ip != "192.0.2.7" || device != "Mozilla/5.0 (X11)" {
		t.Fatalf("ip %q device %q (control characters and the IPv4-mapped form must be cleaned)", ip, device)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session WHERE token_hash = ? OR csrf_hash = ? OR id = ? OR device = ?", res.Session.Token, res.Session.CSRFToken, res.Session.Token, res.Session.Token); n != 0 {
		t.Fatal("a raw token is stored")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login' AND user = ? AND target = ?", u.Email, u.Email); n != 1 {
		t.Fatalf("auth.login audit rows = %d", n)
	}
	var last sql.NullString
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT last_login FROM core_user WHERE id = ?", u.ID).Scan(&last); err != nil || !last.Valid {
		t.Fatalf("last_login = %v, %v", last, err)
	}
}

func TestLoginWrongPasswordLooksLikeUnknownEmail(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	env.User(t, "ann@acme.example", routes.Viewer)

	_, errWrong := env.Svc.Login(t.Context(), auth.LoginRequest{Email: "ann@acme.example", Password: "not the password", IP: ip("192.0.2.1")})
	_, errUnknown := env.Svc.Login(t.Context(), auth.LoginRequest{Email: "nobody@acme.example", Password: "not the password", IP: ip("192.0.2.1")})
	_, errLong := env.Svc.Login(t.Context(), auth.LoginRequest{Email: "ann@acme.example", Password: strings.Repeat("x", 100_000), IP: ip("192.0.2.1")})
	a := apiErr(t, errWrong, 400, "invalid_credentials")
	b := apiErr(t, errUnknown, 400, "invalid_credentials")
	c := apiErr(t, errLong, 400, "invalid_credentials")
	if a.Message != b.Message || a.Message != c.Message || jsonOf(t, a) != jsonOf(t, b) {
		t.Fatalf("the two failures differ: %q vs %q", jsonOf(t, a), jsonOf(t, b))
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions after failed sign-ins", n)
	}
	// A failure for a real account is audited with a reason; an unknown email leaves no row (an anonymous
	// caller must not be able to grow the audit log), and the password is nowhere in it.
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND target = 'ann@acme.example'"); n != 2 {
		t.Fatalf("failed-login rows for ann = %d, want 2", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE target LIKE '%nobody%'"); n != 0 {
		t.Fatalf("unknown email audited: %d rows", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE detail LIKE '%not the password%' OR target LIKE '%xxxx%'"); n != 0 {
		t.Fatal("password text reached the audit log")
	}
}

func TestLoginDisabledAccount(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	off := true
	if _, err := env.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, u.ID, auth.UserPatch{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	// Right password: 403 disabled, no session. Wrong password: indistinguishable from any other account.
	_, err := env.Login(t, u.Email, "")
	wantAPI(t, err, 403, "disabled")
	_, err = env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: "wrong password here", IP: ip("192.0.2.1")})
	wantAPI(t, err, 400, "invalid_credentials")
	if n := env.Count(t, "SELECT count(*) FROM core_session WHERE user_id = ? AND revoked_at IS NULL", u.ID); n != 0 {
		t.Fatal("a disabled account has a live session")
	}
}

func TestLoginRateLimit(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	bad := func(addr, email string) error {
		_, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: email, Password: "wrong password here", IP: ip(addr)})
		return err
	}
	for range 10 {
		wantAPI(t, bad("192.0.2.1", u.Email), 400, "invalid_credentials")
	}
	// Blocked: even the right password is refused, before any password work.
	_, err := env.Login(t, u.Email, "")
	e := apiErr(t, err, 429, "rate_limited")
	if e.Extra["retry_after"] != 30 {
		t.Fatalf("retry_after = %v, want 30", e.Extra["retry_after"])
	}
	// Other IPs and other emails are not blocked.
	wantAPI(t, bad("192.0.2.2", u.Email), 400, "invalid_credentials")
	wantAPI(t, bad("192.0.2.1", "other@acme.example"), 400, "invalid_credentials")
	env.Clock.Advance(31 * time.Second)
	if _, err := env.Login(t, u.Email, ""); err != nil {
		t.Fatalf("sign-in after the wait: %v", err)
	}
	// Success cleared the count: another ten are needed.
	for range 9 {
		wantAPI(t, bad("192.0.2.1", u.Email), 400, "invalid_credentials")
	}
	// The wait grows with continued failures.
	wantAPI(t, bad("192.0.2.1", u.Email), 400, "invalid_credentials")
	env.Clock.Advance(31 * time.Second)
	wantAPI(t, bad("192.0.2.1", u.Email), 400, "invalid_credentials")
	e = apiErr(t, func() error { _, err := env.Login(t, u.Email, ""); return err }(), 429, "rate_limited")
	if e.Extra["retry_after"] != 60 {
		t.Fatalf("second wait = %v, want 60", e.Extra["retry_after"])
	}
}

func TestLoginUpgradesOutdatedHash(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	old, err := auth.Params{Memory: 32, Time: 1, Threads: 1}.Hash(authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	err = env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := coredb.New(tx).UpdateUserPassword(t.Context(), coredb.UpdateUserPasswordParams{PasswordHash: old, ID: u.ID})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Login(t, u.Email, ""); err != nil {
		t.Fatal(err)
	}
	var now string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT password_hash FROM core_user WHERE id = ?", u.ID).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if now == old || !strings.HasPrefix(now, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash was not upgraded: %s", now)
	}
	if _, err := env.Login(t, u.Email, ""); err != nil {
		t.Fatalf("sign-in after the upgrade: %v", err)
	}
}

func TestLoginEmailCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	sentBefore := len(env.Mailer.Sent())

	// First call: no session, 401 twofa_required with the method, a masked address and the resend delay.
	_, err := env.Login(t, u.Email, "")
	e := apiErr(t, err, 401, "twofa_required")
	if e.Extra["method"] != "email" || e.Extra["sent_to"] != "a•••@acme.example" || e.Extra["resend_after"] != 60 {
		t.Fatalf("extra = %v", e.Extra)
	}
	if len(env.Mailer.Sent()) != sentBefore+1 || env.Mailer.Sent()[sentBefore].To != u.Email {
		t.Fatalf("mails = %v", env.Mailer.Sent())
	}
	code := env.Mailer.LastCode()
	if contains(jsonOf(t, e), code, "preview_code") {
		t.Fatalf("the code reached the response: %s", jsonOf(t, e))
	}
	// Reloading the page within 60 s does not mail again (INV-8: the reused code stays valid).
	env.Clock.Advance(20 * time.Second)
	_, err = env.Login(t, u.Email, "")
	e = apiErr(t, err, 401, "twofa_required")
	if e.Extra["resend_after"] != 40 || len(env.Mailer.Sent()) != sentBefore+1 {
		t.Fatalf("reload: extra=%v mails=%d", e.Extra, len(env.Mailer.Sent()))
	}

	// Wrong codes: counted, the message says how many are left; no session.
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	_, err = env.Login(t, u.Email, wrong)
	if e := apiErr(t, err, 400, "wrong_code"); !strings.Contains(e.Message, "4 tries left") {
		t.Fatalf("message = %q", e.Message)
	}
	_, err = env.Login(t, u.Email, "12ab")
	wantAPI(t, err, 400, "invalid_code")
	for range 3 {
		_, err = env.Login(t, u.Email, wrong)
		wantAPI(t, err, 400, "wrong_code")
	}
	_, err = env.Login(t, u.Email, wrong) // the fifth wrong code kills the code
	wantAPI(t, err, 400, "too_many_tries")
	_, err = env.Login(t, u.Email, code)
	wantAPI(t, err, 400, "no_code")
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions without a valid code", n)
	}
}

func TestLoginEmailCodeSingleUseAndExpiry(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")

	_, err := env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	code := env.Mailer.LastCode()
	res, err := env.Login(t, u.Email, " "+code[:3]+" "+code[3:]+" ") // spaces are ignored
	if err != nil {
		t.Fatal(err)
	}
	if res.Session.Token == "" {
		t.Fatal("no session")
	}
	_, err = env.Login(t, u.Email, code) // single use
	wantAPI(t, err, 400, "no_code")

	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	old := env.Mailer.LastCode()
	env.Clock.Advance(10*time.Minute + time.Second)
	_, err = env.Login(t, u.Email, old)
	wantAPI(t, err, 400, "code_expired")
	_, err = env.Login(t, u.Email, old)
	wantAPI(t, err, 400, "no_code")
}

func TestLoginEmailChannelDownNeverFallsBackToPassword(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	_, err := env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	code := env.Mailer.LastCode()

	env.Mailer.SetAvailable(false)
	for _, c := range []string{"", code, "000000"} {
		_, err := env.Login(t, u.Email, c)
		wantAPI(t, err, 503, "twofa_email_unavailable")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions while the email channel is down", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND detail LIKE 'email channel unavailable%'"); n != 3 {
		t.Fatalf("audit rows for the refusals = %d", n)
	}
	// A mailer that is nil behaves the same.
	_, err = env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, ip("192.0.2.1"))
	wantAPI(t, err, 503, "twofa_email_unavailable")

	// Back up: sign-in works again, and a mail that fails to send is the same 503 and does not burn a send.
	env.Mailer.SetAvailable(true)
	env.Clock.Advance(2 * time.Minute)
	env.Mailer.FailSend(true)
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 503, "twofa_email_unavailable")
	env.Mailer.FailSend(false)
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
}

func TestResendCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	app := env.User(t, "bob@acme.example", routes.Viewer)
	resend := func() (auth.Sent, error) {
		return env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, ip("192.0.2.1"))
	}

	_, err := env.Svc.ResendCode(t.Context(), u.Email, "wrong password here", ip("192.0.2.1"))
	wantAPI(t, err, 400, "invalid_credentials")
	_, err = env.Svc.ResendCode(t.Context(), app.Email, authtest.Password, ip("192.0.2.1"))
	wantAPI(t, err, 409, "not_email_method")

	// The helper left the clock 2 minutes after the enrolment code. Sends in the last hour so far: 1.
	sent, err := resend()
	if err != nil || sent.SentTo != "a•••@acme.example" || sent.ResendAfter != 60 {
		t.Fatalf("resend = %+v, %v", sent, err)
	}
	_, err = resend()
	if e := apiErr(t, err, 429, "resend_too_soon"); e.Extra["retry_after"] != 60 {
		t.Fatalf("retry_after = %v", e.Extra["retry_after"])
	}
	env.Clock.Advance(59 * time.Second)
	_, err = resend()
	if e := apiErr(t, err, 429, "resend_too_soon"); e.Extra["retry_after"] != 1 {
		t.Fatalf("retry_after = %v", e.Extra["retry_after"])
	}
	// Five sends per hour in all: the enrolment code was one, the resend above two; three more.
	for range 3 {
		env.Clock.Advance(61 * time.Second)
		if _, err := resend(); err != nil {
			t.Fatal(err)
		}
	}
	env.Clock.Advance(61 * time.Second)
	_, err = resend()
	wantAPI(t, err, 429, "too_many_codes")
	// An hour after the oldest send, one is allowed again.
	env.Clock.Advance(time.Hour)
	if _, err := resend(); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_email_code_send"); n > 5 {
		t.Fatalf("%d send records kept, want at most 5 (old ones are pruned)", n)
	}
}

func TestLoginAuthenticatorApp(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	step := func() int64 { return auth.TOTPStep(env.Clock.Now()) }

	_, err := env.Login(t, "ann@acme.example", "")
	e := apiErr(t, err, 401, "twofa_required")
	if e.Extra["method"] != "app" || len(e.Extra) != 1 {
		t.Fatalf("extra = %v", e.Extra)
	}
	_, err = env.Login(t, "ann@acme.example", "000000")
	wantAPI(t, err, 400, "invalid_code")
	_, err = env.Login(t, "ann@acme.example", "abc")
	wantAPI(t, err, 400, "invalid_code")
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions without a valid code", n)
	}

	// The enrolment code (the current step) was used: replaying it fails; the next step's code works.
	_, err = env.Login(t, "ann@acme.example", auth.TOTPCode(secret, step()))
	wantAPI(t, err, 400, "invalid_code")
	if _, err := env.Login(t, "ann@acme.example", auth.TOTPCode(secret, step()+1)); err != nil {
		t.Fatalf("code of the next step: %v", err)
	}
	// ... and then neither it nor an older one can be reused.
	for _, s := range []int64{step() + 1, step(), step() - 1} {
		_, err = env.Login(t, "ann@acme.example", auth.TOTPCode(secret, s))
		wantAPI(t, err, 400, "invalid_code")
	}
	env.Clock.Advance(90 * time.Second)
	if _, err := env.Login(t, "ann@acme.example", auth.TOTPCode(secret, step())); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND detail = 'wrong two-step code'"); n < 4 {
		t.Fatalf("failed two-step attempts audited: %d", n)
	}
}

func TestConcurrentUseOfOneTOTPCodeSignsInOnce(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	code := auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())+1)
	type result struct{ err error }
	out := make(chan result, 6)
	for range 6 {
		go func() { _, err := env.Login(t, "ann@acme.example", code); out <- result{err} }()
	}
	ok := 0
	for range 6 {
		if (<-out).err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent sign-ins with one code succeeded, want 1", ok)
	}
}

func TestAuditHasNoSecrets(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	u := emailUser(t, env, "bob@acme.example")
	_, _ = env.Login(t, "ann@acme.example", "000000")
	_, _ = env.Login(t, u.Email, "")
	code := env.Mailer.LastCode()
	_, _ = env.Login(t, u.Email, code)
	_, _ = env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: "hunter2hunter2", IP: ip("192.0.2.1")})

	rows, err := env.DB.Reader().QueryContext(t.Context(), "SELECT user || '|' || action || '|' || target || '|' || coalesce(detail, '') FROM core_audit")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	banned := []string{authtest.Password, "hunter2", code, auth.SecretBase32(secret), string(secret), "$argon2"}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(line, b) {
				t.Fatalf("audit row %q contains %q", line, b)
			}
		}
	}
	if res, err := audit.Verify(t.Context(), env.DB.Reader()); err != nil || !res.OK || res.Count < 6 {
		t.Fatalf("audit chain: %+v, %v", res, err)
	}
	if contains(env.Logs.String(), code, authtest.Password, "hunter2") {
		t.Fatalf("logs contain a secret:\n%s", env.Logs.String())
	}
}
