package auth_test

import (
	"bytes"
	"encoding/base32"
	"fmt"
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

	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", "123456")), 409, "no_pending")
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
	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", "12 34")), 400, "invalid_code")
	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret, cur+5))), 400, "wrong_code")

	// A second Start replaces the first key (and does not leave the old sealed key behind).
	setup2, err := env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	if err != nil || setup2.Secret == setup.Secret {
		t.Fatalf("restart: %+v, %v", setup2, err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'"); n != 1 {
		t.Fatalf("%d sealed TOTP keys after a restart, want 1", n)
	}
	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret, cur))), 400, "wrong_code") // the old key is dead

	// A pending key expires after 10 minutes.
	env.Clock.Advance(10*time.Minute + time.Second)
	secret2 := b32(t, setup2.Secret)
	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", auth.TOTPCode(secret2, auth.TOTPStep(env.Clock.Now())))), 409, "no_pending")

	setup3, _ := env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	secret3 := b32(t, setup3.Secret)
	if err := only(env.Svc.ConfirmTOTP(ctx, u.ID, "", " "+auth.TOTPCode(secret3, auth.TOTPStep(env.Clock.Now()))+" ")); err != nil {
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
	wantAPI(t, only(env.Svc.ConfirmTOTP(ctx, u.ID, "", "123456")), 409, "already_on")
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
	wantAPI(t, only(env.Svc.ConfirmEmail2FA(ctx, u.ID, "", "123456")), 409, "email_channel_not_ready")
	env.Mailer.SetAvailable(true)

	wantAPI(t, only(env.Svc.ConfirmEmail2FA(ctx, u.ID, "", "123456")), 400, "no_code")
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
	wantAPI(t, only(env.Svc.ConfirmEmail2FA(ctx, u.ID, "", wrong)), 400, "wrong_code")
	if got, _ := env.Svc.GetUser(ctx, u.ID); got.TwofaMethod != "" {
		t.Fatal("two-step turned on with a wrong code")
	}
	if err := only(env.Svc.ConfirmEmail2FA(ctx, u.ID, "", env.Mailer.LastCode())); err != nil {
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
	wantAPI(t, only(env.Svc.DisableTwoFA(ctx, ann.ID, "", "not the password")), 400, "wrong_password")
	wantAPI(t, only(env.Svc.DisableTwoFA(ctx, admin.ID, "", authtest.Password)), 409, "not_on")
	if err := only(env.Svc.DisableTwoFA(ctx, ann.ID, "", authtest.Password)); err != nil {
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

// confirmWrongCodes sends n codes that are valid at no step the pending key accepts, through ConfirmTOTP,
// and returns the error of the last one.
func confirmWrongCodes(t *testing.T, env *authtest.Env, userID string, secret []byte, n int) error {
	t.Helper()
	cur := auth.TOTPStep(env.Clock.Now())
	valid := map[string]bool{}
	for d := int64(-1); d <= 1; d++ {
		valid[auth.TOTPCode(secret, cur+d)] = true
	}
	var err error
	for i, tried := 0, 0; tried < n; i++ {
		code := fmt.Sprintf("%06d", i)
		if valid[code] {
			continue
		}
		tried++
		err = only(env.Svc.ConfirmTOTP(t.Context(), userID, "", code))
	}
	return err
}

// Review of WP-04b part 2 (M2): a holder of any session of the account could try every 6-digit code at
// network speed while the key was pending (three codes are valid at any time) and so turn two-step on and end
// the owner's sessions. Five wrong codes now drop the pending key, like an emailed code.
func TestConfirmTOTPDropsThePendingKeyAfterFiveWrongCodes(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	secret := b32(t, setup.Secret)
	wantAPI(t, confirmWrongCodes(t, env, u.ID, secret, 4), 400, "wrong_code")
	wantAPI(t, confirmWrongCodes(t, env, u.ID, secret, 1), 400, "too_many_tries")
	if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'"); n != 0 {
		t.Fatalf("%d sealed TOTP keys left after the key was dropped", n)
	}
	// Even the right code no longer works: the owner starts again with the password.
	wantAPI(t, only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())))), 409, "no_pending")
	again, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	// The new key has its own count: four wrong codes and the right one still turn it on.
	secret2 := b32(t, again.Secret)
	wantAPI(t, confirmWrongCodes(t, env, u.ID, secret2, 4), 400, "wrong_code")
	if err := only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", auth.TOTPCode(secret2, auth.TOTPStep(env.Clock.Now())))); err != nil {
		t.Fatalf("the right code after four wrong ones: %v", err)
	}
}

// Review of WP-04b part 2 (M2): every confirm code is a guess on the account's two-step limiter (the one
// of sign-in codes), so restarting the key with the password does not reset it.
func TestConfirmTOTPGuessesShareTheAccountsTwoStepLimiter(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	var secret []byte
	for range 2 { // 2 keys x 5 wrong codes = 10 guesses
		setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
		if err != nil {
			t.Fatal(err)
		}
		secret = b32(t, setup.Secret)
		wantAPI(t, confirmWrongCodes(t, env, u.ID, secret, 5), 400, "too_many_tries")
	}
	setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	secret = b32(t, setup.Secret)
	// Blocked: even the right code gets 429, and nothing was turned on.
	wantAPI(t, only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())))), 429, "rate_limited")
	if got, _ := env.Svc.GetUser(t.Context(), u.ID); got.TwofaMethod != "" {
		t.Fatalf("two-step was turned on while blocked: %q", got.TwofaMethod)
	}
	// The wait is the sign-in one (30 s doubling, at most 10 minutes); after it the right code goes through.
	env.Clock.Advance(10 * time.Minute)
	if err := only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())))); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
}

// D-389: the sole administrator lost the phone; `vedette reset-admin` on the box console gives a temporary password,
// turns two-step sign-in off and ends every session, in one transaction with its audit row.
func TestConsoleReset(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	admin := env.User(t, "root@acme.example", routes.Admin)
	setup, err := env.Svc.StartTOTP(ctx, admin.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmTOTP(ctx, admin.ID, "", auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())))); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(time.Minute) // a new step: the confirming code cannot be used again
	if _, err := env.Login(t, admin.Email, auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now()))); err != nil {
		t.Fatal(err)
	}
	viewer := env.User(t, "ann@acme.example", routes.Viewer)

	for _, email := range []string{"nobody@acme.example", viewer.Email} {
		if _, _, err := env.Svc.ConsoleReset(ctx, email); err == nil {
			t.Fatalf("reset of %s: want refused", email)
		}
	}
	temp, ended, err := env.Svc.ConsoleReset(ctx, " Root@Acme.Example ")
	if err != nil {
		t.Fatal(err)
	}
	if ended != 1 || len(temp) != 20 || env.Count(t, "SELECT count(*) FROM core_session WHERE user_id = ? AND revoked_at IS NULL", admin.ID) != 0 {
		t.Fatalf("temp %d characters, %d sessions ended", len(temp), ended)
	}
	if env.Count(t, "SELECT count(*) FROM core_user_totp") != 0 || env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'") != 0 {
		t.Fatal("the TOTP key survived the reset")
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.console_reset' AND user = 'console' AND target = ? AND detail = 'temporary password set; two-step sign-in turned off; 1 sessions ended'", admin.Email) != 1 {
		t.Fatal("no audit row for the console reset")
	}
	res, err := env.Svc.Login(ctx, auth.LoginRequest{Email: admin.Email, Password: temp, IP: ip("192.0.2.1"), UserAgent: "test"})
	if err != nil {
		t.Fatalf("sign-in with the temporary password: %v", err)
	}
	if !res.User.PasswordChangeRequired {
		t.Fatal("the console password must be replaced at sign-in (D-180)")
	}
	if _, err := env.Login(t, admin.Email, ""); err == nil {
		t.Fatal("the old password still signs in")
	}
}
