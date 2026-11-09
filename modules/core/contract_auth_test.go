package core_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/secrets"
)

// only drops the renewed session of a call that returns one: these tests care about the error alone.
func only(_ auth.Issued, err error) error { return err }

func apiCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok || e.Status != status || e.Code != code {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
}

func liveSessions(t *testing.T, env *authtest.Env, email string) int {
	t.Helper()
	return env.Count(t, "SELECT count(*) FROM core_session s JOIN core_user u ON u.id = s.user_id WHERE u.email = ? AND s.revoked_at IS NULL", email)
}

// INV-7: no disabling yourself, never zero active administrators, an admin cannot reset their own two-step,
// a temporary password is shown once (only its hash is kept) and a reset ends every session of that user.
func TestContract_INV7_UserRules(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	a1 := env.User(t, "a1@acme.example", routes.Admin)
	a2 := env.User(t, "a2@acme.example", routes.Admin)
	v := env.User(t, "v@acme.example", routes.Viewer)
	yes := true
	viewer := routes.Viewer

	_, err := env.Svc.UpdateUser(ctx, a1.ID, a1.Email, "", a1.ID, auth.UserPatch{Disabled: &yes})
	apiCode(t, err, 400, "self_disable")
	if _, err := env.Svc.UpdateUser(ctx, a1.ID, a1.Email, "", a2.ID, auth.UserPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.UpdateUser(ctx, a1.ID, a1.Email, "", a1.ID, auth.UserPatch{Role: &viewer})
	apiCode(t, err, 400, "last_admin")
	if n := env.Count(t, "SELECT count(*) FROM core_user WHERE role = 'admin' AND disabled = 0"); n != 1 {
		t.Fatalf("active administrators = %d, want 1", n)
	}

	apiCode(t, env.Svc.ResetTwoFA(ctx, a1.ID, a1.Email, "", a1.ID), 400, "self_reset")

	if _, err := env.Login(t, v.Email, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Login(t, v.Email, ""); err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, env, v.Email) != 2 {
		t.Fatal("setup: expected two sessions")
	}
	temp, err := env.Svc.ResetPassword(ctx, a1.ID, a1.Email, "", v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, env, v.Email) != 0 {
		t.Fatal("a password reset left sessions alive")
	}
	// A 2FA reset also ends every session of the user; turning two-step on or off ends the other ones (INV-7).
	home := netip.MustParseAddr("192.0.2.4")
	if _, err := env.Svc.StartEmail2FA(ctx, v.ID, "", temp); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(ctx, v.ID, "", env.Mailer.LastCode())); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(2 * time.Minute)
	req := auth.LoginRequest{Email: v.Email, Password: temp, IP: home}
	_, err = env.Svc.Login(ctx, req)
	apiCode(t, err, 401, "twofa_required")
	req.Code = env.Mailer.LastCode()
	if _, err := env.Svc.Login(ctx, req); err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, env, v.Email) != 1 {
		t.Fatal("setup: expected one session")
	}
	if err := env.Svc.ResetTwoFA(ctx, a1.ID, a1.Email, "", v.ID); err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, env, v.Email) != 0 {
		t.Fatal("a two-step reset left sessions alive")
	}
	if res, err := env.Svc.Login(ctx, auth.LoginRequest{Email: v.Email, Password: temp, IP: home}); err != nil {
		t.Fatal(err)
	} else if err := only(env.Svc.DisableTwoFA(ctx, v.ID, res.Session.SessionID, temp)); err == nil {
		t.Fatal("DisableTwoFA must refuse while two-step is off")
	}
	var hash string
	if err := env.DB.Reader().QueryRowContext(ctx, "SELECT password_hash FROM core_user WHERE id = ?", v.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") || strings.Contains(hash, temp) {
		t.Fatalf("stored password value %q", hash)
	}
}

// INV-8: with two-step on, a missing or wrong code never creates a session; the email method with a dead
// channel is 503, never password-only; email codes are 6 digits, 10 minutes, single use, 5 tries, 60 s
// between sends, 5 sends an hour; TOTP is RFC 6238 SHA-1, 6 digits, 30 s; no response carries a code.
func TestContract_INV8_TwoStep(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()

	// TOTP parameters: the RFC 6238 SHA-1 vector, 6 digits, 30 s steps.
	if got := auth.TOTPCode([]byte("12345678901234567890"), 59/30); got != "287082" || auth.TOTPPeriod != 30 {
		t.Fatalf("TOTP code at T=59 is %s (period %d)", got, auth.TOTPPeriod)
	}

	// Authenticator app.
	app := env.User(t, "app@acme.example", routes.Viewer)
	setup, err := env.Svc.StartTOTP(ctx, app.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	key := mustBase32(t, setup.Secret)
	if err := only(env.Svc.ConfirmTOTP(ctx, app.ID, "", auth.TOTPCode(key, auth.TOTPStep(env.Clock.Now())))); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", "000000", "12345"} {
		_, err := env.Login(t, app.Email, code)
		if code == "" {
			apiCode(t, err, 401, "twofa_required")
		} else {
			apiCode(t, err, 400, "invalid_code")
		}
	}

	// Email code.
	em := env.User(t, "em@acme.example", routes.Viewer)
	if _, err := env.Svc.StartEmail2FA(ctx, em.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(ctx, em.ID, "", env.Mailer.LastCode())); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(2 * time.Minute)
	_, err = env.Login(t, em.Email, "")
	e, ok := apierr.As(err)
	if !ok || e.Status != 401 || e.Code != "twofa_required" || e.Extra["method"] != "email" || e.Extra["resend_after"] != 60 {
		t.Fatalf("first step = %v", err)
	}
	code := env.Mailer.LastCode()
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("code %q is not 6 digits", code)
	}
	if b := mustJSON(t, e.Body()); strings.Contains(b, code) || strings.Contains(b, "preview_code") {
		t.Fatalf("response carries the code: %s", b)
	}
	var stored string
	if err := env.DB.Reader().QueryRowContext(ctx, "SELECT code_hash FROM core_email_code WHERE user_id = ?", em.ID).Scan(&stored); err != nil || stored == code || len(stored) != 64 {
		t.Fatalf("stored code value %q, %v", stored, err)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range 4 {
		_, err = env.Login(t, em.Email, wrong)
		apiCode(t, err, 400, "wrong_code")
	}
	_, err = env.Login(t, em.Email, wrong)
	apiCode(t, err, 400, "too_many_tries") // the fifth wrong try kills the code
	_, err = env.Login(t, em.Email, code)
	apiCode(t, err, 400, "no_code")

	// Resend limits.
	env.Clock.Advance(2 * time.Minute)
	if _, err := env.Svc.ResendCode(ctx, em.Email, authtest.Password, netip.MustParseAddr("192.0.2.1"), ""); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.ResendCode(ctx, em.Email, authtest.Password, netip.MustParseAddr("192.0.2.1"), "")
	apiCode(t, err, 429, "resend_too_soon")

	// Dead email channel: 503 for every call, and still no session.
	env.Mailer.SetAvailable(false)
	for _, c := range []string{"", env.Mailer.LastCode()} {
		_, err = env.Login(t, em.Email, c)
		apiCode(t, err, 503, "twofa_email_unavailable")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions were created without a completed two-step", n)
	}
}

// INV-9: the only cookies are __Host-vedette_session (HttpOnly) and __Host-vedette_csrf, both Secure and SameSite=Strict;
// the server keeps only SHA-256 of their values.
func TestContract_INV9_Cookies(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range append(res.Session.Cookies(), auth.ClearCookies()...) {
		names[c.Name] = true
		if !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("cookie %s = %+v", c.Name, c)
		}
		if (c.Name == "__Host-vedette_session") != c.HttpOnly {
			t.Errorf("cookie %s HttpOnly = %v", c.Name, c.HttpOnly)
		}
	}
	if len(names) != 2 || !names["__Host-vedette_session"] || !names["__Host-vedette_csrf"] {
		t.Fatalf("cookie names = %v", names)
	}
	if env.Count(t, "SELECT count(*) FROM core_session WHERE instr(token_hash || csrf_hash, ?) > 0 OR instr(token_hash || csrf_hash, ?) > 0", res.Session.Token, res.Session.CSRFToken) != 0 {
		t.Fatal("a raw cookie value is stored")
	}
}

// INV-6 (TOTP key): the key is sealed in core_secret with purpose core_user_totp, never in a core_user column.
func TestContract_INV6_TOTPKeyIsSealed(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = env.DB.Reader().QueryRowContext(t.Context(),
		"SELECT count(*) FROM core_secret s JOIN core_user_totp t ON t.secret_id = s.id WHERE s.purpose = 'core_user_totp' AND t.user_id = ? AND instr(s.ciphertext, ?) = 0", u.ID, setup.Secret).Scan(&n)
	if err != nil || n != 1 {
		t.Fatalf("sealed key rows = %d, %v", n, err)
	}
}

// Issue #17: the chain head. Deleting the newest rows of a chain is detected once the head is recorded in the
// same transaction as each append, for core_audit and for the chains of other modules through the shared helper.
func TestContract_ChainHead(t *testing.T) {
	t.Parallel()
	t.Run("core_audit", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		l := audit.New(nil)
		for range 4 {
			if err := db.Write(t.Context(), func(tx *sql.Tx) error {
				return l.Append(t.Context(), tx, audit.Entry{User: "system", Action: "a.b", Target: "t"})
			}); err != nil {
				t.Fatal(err)
			}
		}
		if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || !res.OK || res.Count != 4 {
			t.Fatalf("healthy chain: %+v, %v", res, err)
		}
		err := db.Write(t.Context(), func(tx *sql.Tx) error {
			for _, q := range []string{"DROP TRIGGER core_audit_no_delete", "DELETE FROM core_audit WHERE seq > 2"} {
				if _, err := tx.ExecContext(t.Context(), q); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if res, err := audit.Verify(t.Context(), db.Reader()); err != nil || res.OK {
			t.Fatalf("chain with its newest rows deleted verified OK: %+v, %v", res, err)
		}
	})
	t.Run("other chains share the helper", func(t *testing.T) {
		t.Parallel()
		db := migrated(t)
		now := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
		hashes := []string{chain.Genesis}
		var rows []string
		for i := range 3 {
			h, err := chain.HashCanonical(hashes[i], map[string]any{"id": string(rune('a' + i))})
			if err != nil {
				t.Fatal(err)
			}
			hashes = append(hashes, h)
			rows = append(rows, h)
			if err := db.Write(t.Context(), func(tx *sql.Tx) error { return chain.AdvanceHead(t.Context(), tx, "resp_log", h, now) }); err != nil {
				t.Fatal(err)
			}
		}
		head, err := chain.LoadHead(t.Context(), db.Reader(), "resp_log")
		if err != nil || head == nil || head.Count != 3 || head.Hash != rows[2] {
			t.Fatalf("head = %+v, %v", head, err)
		}
		verify := func(n int) chain.Result {
			v := chain.NewVerifierWithHead("", head)
			for i := range n {
				v.Add(string(rune('a'+i)), hashes[i], hashes[i+1], hashes[i+1])
			}
			return v.Result()
		}
		if r := verify(3); !r.OK {
			t.Fatalf("full chain: %+v", r)
		}
		if r := verify(2); r.OK || r.BrokenAt != 3 {
			t.Fatalf("chain without its newest row: %+v", r)
		}
	})
}

// Issue #17: secrets.Value exposes only what the UI may show.
func TestContract_SecretValueLast4(t *testing.T) {
	t.Parallel()
	v := secrets.NewValue("sk-live-abcdefgh1234")
	if !v.IsSet() || v.Last4() != "1234" || secrets.NewValue("short").Last4() != "" || secrets.NewValue("").IsSet() {
		t.Fatalf("IsSet/Last4 = %v %q", v.IsSet(), v.Last4())
	}
}

func mustBase32(t *testing.T, s string) []byte {
	t.Helper()
	// The same decoding an authenticator app does.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var bits, val uint
	var out []byte
	for _, r := range s {
		i := strings.IndexRune(alphabet, r)
		if i < 0 {
			t.Fatalf("not base32: %q", s)
		}
		val = val<<5 | uint(i)
		bits += 5
		if bits >= 8 {
			out = append(out, byte((val>>(bits-8))&0xff))
			bits -= 8
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
