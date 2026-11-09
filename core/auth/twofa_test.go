package auth_test

import (
	"bytes"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func b32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTOTPEnrolment(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	ctx := t.Context()

	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", "123456"), 409, "no_pending")
	setup, err := env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(setup.URI, "otpauth://totp/Vedette:ann@acme.example?secret="+setup.Secret) {
		t.Fatalf("uri = %s", setup.URI)
	}
	secret := b32(t, setup.Secret)
	cur := auth.TOTPStep(env.Clock.Now())

	// Not on until confirmed: sign-in still asks for the password only.
	if _, err := env.Login(t, u.Email, ""); err != nil {
		t.Fatalf("unconfirmed key must not change sign-in: %v", err)
	}
	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", "12 34"), 400, "invalid_code")
	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret, cur+5)), 400, "wrong_code")

	// A second Start replaces the first key (and does not leave the old sealed key behind).
	setup2, err := env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	if err != nil || setup2.Secret == setup.Secret {
		t.Fatalf("restart: %+v, %v", setup2, err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'"); n != 1 {
		t.Fatalf("%d sealed TOTP keys after a restart, want 1", n)
	}
	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret, cur)), 400, "wrong_code") // the old key is dead

	// A pending key expires after 10 minutes.
	env.Clock.Advance(10*time.Minute + time.Second)
	secret2 := b32(t, setup2.Secret)
	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret2, auth.TOTPStep(env.Clock.Now()))), 409, "no_pending")

	setup3, _ := env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	secret3 := b32(t, setup3.Secret)
	if err := env.Svc.ConfirmTOTP(ctx, u.ID, "", " "+auth.TOTPCode(secret3, auth.TOTPStep(env.Clock.Now()))+" "); err != nil {
		t.Fatal(err)
	}
	got, _ := env.Svc.GetUser(ctx, u.ID)
	if got.TwofaMethod != "app" {
		t.Fatalf("method = %q", got.TwofaMethod)
	}
	// The key is sealed: neither it nor its base32 form is anywhere in the database rows.
	var ct []byte
	if err := env.DB.Reader().QueryRowContext(ctx, "SELECT ciphertext FROM core_secret WHERE purpose = 'core_user_totp'").Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, secret3) || bytes.Contains(ct, []byte(setup3.Secret)) {
		t.Fatal("the TOTP key is stored in the clear")
	}
	// Both methods are refused while one is on.
	_, err = env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	wantAPI(t, err, 409, "already_on")
	_, err = env.Svc.StartEmail2FA(ctx, u.ID, "", authtest.Password)
	wantAPI(t, err, 409, "already_on")
	wantAPI(t, env.Svc.ConfirmTOTP(ctx, u.ID, "", "123456"), 409, "already_on")
	for _, a := range []string{"account.2fa_start", "account.2fa_on"} {
		if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ?", a) == 0 {
			t.Errorf("no %s audit row", a)
		}
	}
}

func TestEmailEnrolment(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	ctx := t.Context()

	env.Mailer.SetAvailable(false)
	_, err := env.Svc.StartEmail2FA(ctx, u.ID, "", authtest.Password)
	wantAPI(t, err, 409, "email_channel_not_ready")
	wantAPI(t, env.Svc.ConfirmEmail2FA(ctx, u.ID, "", "123456"), 409, "email_channel_not_ready")
	env.Mailer.SetAvailable(true)

	wantAPI(t, env.Svc.ConfirmEmail2FA(ctx, u.ID, "", "123456"), 400, "no_code")
	sent, err := env.Svc.StartEmail2FA(ctx, u.ID, "", authtest.Password)
	if err != nil || sent.SentTo != "a•••@acme.example" || sent.ResendAfter != 60 {
		t.Fatalf("start = %+v, %v", sent, err)
	}
	_, err = env.Svc.StartEmail2FA(ctx, u.ID, "", authtest.Password)
	wantAPI(t, err, 429, "resend_too_soon")
	wrong := "000000"
	if env.Mailer.LastCode() == wrong {
		wrong = "111111"
	}
	wantAPI(t, env.Svc.ConfirmEmail2FA(ctx, u.ID, "", wrong), 400, "wrong_code")
	if got, _ := env.Svc.GetUser(ctx, u.ID); got.TwofaMethod != "" {
		t.Fatal("two-step turned on with a wrong code")
	}
	if err := env.Svc.ConfirmEmail2FA(ctx, u.ID, "", env.Mailer.LastCode()); err != nil {
		t.Fatal(err)
	}
	if got, _ := env.Svc.GetUser(ctx, u.ID); got.TwofaMethod != "email" {
		t.Fatalf("method = %q", got.TwofaMethod)
	}
}

func TestDisableAndResetTwoFA(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	admin := env.User(t, "root@acme.example", routes.Admin)
	appUser(t, env)
	ann := userByEmail(t, env, "ann@acme.example")
	em := emailUser(t, env, "bob@acme.example")

	secretRows := func() int { return env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'") }
	if secretRows() != 1 {
		t.Fatalf("sealed keys = %d", secretRows())
	}

	// Disable: needs the password, and only when it is on.
	wantAPI(t, env.Svc.DisableTwoFA(ctx, ann.ID, "", "not the password"), 400, "wrong_password")
	wantAPI(t, env.Svc.DisableTwoFA(ctx, admin.ID, "", authtest.Password), 409, "not_on")
	if err := env.Svc.DisableTwoFA(ctx, ann.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if secretRows() != 0 || env.Count(t, "SELECT count(*) FROM core_user_totp") != 0 {
		t.Fatal("TOTP key or row left behind (orphan core_secret)")
	}
	if _, err := env.Login(t, ann.Email, ""); err != nil {
		t.Fatalf("sign-in after turning two-step off: %v", err)
	}

	// Reset by an admin: not for yourself, not when off, clears a pending email code too.
	wantAPI(t, env.Svc.ResetTwoFA(ctx, admin.ID, admin.Email, "", admin.ID), 400, "self_reset")
	wantAPI(t, env.Svc.ResetTwoFA(ctx, admin.ID, admin.Email, "", ann.ID), 409, "not_on")
	wantAPI(t, env.Svc.ResetTwoFA(ctx, admin.ID, admin.Email, "", "u-nope"), 404, "not_found")
	if _, err := env.Login(t, em.Email, ""); err == nil { // leaves a pending code
		t.Fatal("expected twofa_required")
	}
	if env.Count(t, "SELECT count(*) FROM core_email_code WHERE user_id = ?", em.ID) != 1 {
		t.Fatal("no pending code")
	}
	if err := env.Svc.ResetTwoFA(ctx, admin.ID, admin.Email, "", em.ID); err != nil {
		t.Fatal(err)
	}
	if env.Count(t, "SELECT count(*) FROM core_email_code WHERE user_id = ?", em.ID) != 0 {
		t.Fatal("pending code survived the reset")
	}
	if _, err := env.Login(t, em.Email, ""); err != nil {
		t.Fatalf("sign-in after reset: %v", err)
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.2fa_reset' AND user = ? AND target = ? AND detail = 'was email code; 0 sessions ended'", admin.Email, em.Email) != 1 {
		t.Fatal("no audit row for the reset")
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'account.2fa_off' AND target = ?", ann.Email) != 1 {
		t.Fatal("no audit row for turning it off")
	}
}

func userByEmail(t *testing.T, env *authtest.Env, email string) auth.User {
	t.Helper()
	var id string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT id FROM core_user WHERE email = ?", email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	u, err := env.Svc.GetUser(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
