package auth_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/secrets"
)

// resealUnderOtherKey re-encrypts every core_secret row of purpose under another master key, as a backup restored
// without its decryption key leaves them (#812): the rows are there, this box's key opens none of them.
func resealUnderOtherKey(t *testing.T, env *authtest.Env, purpose string) {
	t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	err = env.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT id FROM core_secret WHERE purpose = ?", purpose)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) == 0 {
			t.Fatalf("no %s secret to reseal", purpose)
		}
		for _, id := range ids {
			if _, err := other.Replace(ctx, tx, id, purpose, bytes.Repeat([]byte{1}, 20), false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// After a restore without the key, an account with app two-step whose key the box cannot open is refused with
// 403 twofa_reset_required (not a 500, and never a sign-in on the password alone), with or without a code, and so is
// its step-up; an administrator resets its two-step sign-in, and then the password signs in.
func TestRestoreWithoutKeyAppTwoStepIsRefusedUntilAnAdministratorResetsIt(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	admin := env.User(t, "root@acme.example", routes.Admin)
	resealUnderOtherKey(t, env, "core_user_totp")
	env.Clock.Advance(auth.TOTPPeriod * time.Second)
	code := auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now()))

	for _, c := range []string{code, ""} {
		_, err := env.Login(t, "ann@acme.example", c)
		e := apiErr(t, err, 403, "twofa_reset_required")
		if !strings.Contains(e.Message, "administrator") || !strings.Contains(e.Message, "Settings, Users") {
			t.Fatalf("message = %q: it must say who resets it and where", e.Message)
		}
	}
	// A wrong password still learns nothing about the key.
	_, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: "ann@acme.example", Password: "not-the-password-at-all", Code: code, IP: ip("192.0.2.9")})
	wantAPI(t, err, 400, "invalid_credentials")
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions without a second factor", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND detail LIKE 'two-step key cannot be opened%'"); n != 2 {
		t.Fatalf("refusals audited: %d, want 2", n)
	}
	// Step-up (a session restored with the backup) is refused the same way.
	ann := annID(t, env)
	_, err = env.Svc.VerifyTwoStep(t.Context(), ann, code, purpose, summary)
	wantAPI(t, err, 403, "twofa_reset_required")
	_, err = env.Svc.VerifyTwoStep(t.Context(), ann, "", purpose, summary)
	wantAPI(t, err, 403, "twofa_reset_required")

	// The administrator without two-step resets it (the restore page promises this); the password then signs in, and the
	// unopenable key is gone with the reset.
	if err := env.Svc.ResetTwoFA(t.Context(), admin.ID, admin.Email, "", ann); err != nil {
		t.Fatal(err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_user_totp'"); n != 0 {
		t.Fatalf("%d TOTP keys left after the reset", n)
	}
	if _, err := env.Login(t, "ann@acme.example", ""); err != nil {
		t.Fatalf("sign-in after the reset: %v", err)
	}
}

// A pending authenticator key sealed under another box key cannot be confirmed: no_pending (start again), not a 500.
func TestRestoreWithoutKeyPendingAuthenticatorKeyIsNoPending(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	if _, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	resealUnderOtherKey(t, env, "core_user_totp")
	wantAPI(t, only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", "123456")), 409, "no_pending")
}

// The box's own HMAC keys sealed under another key (device cookie, email codes, the unknown-email reference) are made
// again instead of failing every sign-in: an unknown email is refused as usual, an email-code account gets its code.
func TestRestoreWithoutKeyBoxKeysAreMadeAgain(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	emailUser(t, env, "eve@acme.example")
	env.User(t, "bob@acme.example", routes.Viewer)
	if _, err := env.Login(t, "bob@acme.example", ""); err != nil { // makes the device cookie key
		t.Fatal(err)
	}
	if _, err := env.Login(t, "nobody@acme.example", ""); err == nil { // makes the unknown-email key
		t.Fatal("unknown email signed in")
	}
	for _, p := range []string{"core_audit.unknown_email_key", "core_email_code.hmac_key", "core_device_cookie.key"} {
		resealUnderOtherKey(t, env, p)
	}
	// A fresh service on the same database: nothing is cached in memory, as after the restart a restore makes.
	svc, err := auth.New(auth.Config{DB: env.DB, Secrets: env.Secrets, Audit: env.Audit, Mailer: env.Mailer, Clock: env.Clock.Now, Log: slog.New(slog.DiscardHandler), Argon2: authtest.Cheap, MaxHashing: 4})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Login(t.Context(), auth.LoginRequest{Email: "nobody@acme.example", Password: authtest.Password, IP: ip("192.0.2.10")})
	wantAPI(t, err, 400, "invalid_credentials")
	_, err = svc.Login(t.Context(), auth.LoginRequest{Email: "eve@acme.example", Password: authtest.Password, IP: ip("192.0.2.10")})
	wantAPI(t, err, 401, "twofa_required")
	res, err := svc.Login(t.Context(), auth.LoginRequest{Email: "eve@acme.example", Password: authtest.Password, Code: env.Mailer.LastCode(), IP: ip("192.0.2.10")})
	if err != nil {
		t.Fatalf("email code after the box keys were made again: %v", err)
	}
	if res.Device == "" {
		t.Fatal("no device cookie: the device key was not made again")
	}
	for _, p := range []string{"core_audit.unknown_email_key", "core_email_code.hmac_key", "core_device_cookie.key"} {
		if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = ?", p); n != 1 {
			t.Fatalf("%s: %d rows, want the one row replaced in place", p, n)
		}
	}
}
