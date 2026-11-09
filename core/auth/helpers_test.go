package auth_test

import (
	"encoding/base32"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// ip parses a test address.
func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// only drops the renewed session of a call that returns one: most tests care about the error alone.
func only(_ auth.Issued, err error) error { return err }

// wantAPI fails unless err is an *apierr.Error with the status and code.
func wantAPI(t *testing.T, err error, status int, code string) {
	t.Helper()
	_ = apiErr(t, err, status, code)
}

// apiErr is wantAPI that also returns the error, for checks on its message and extra fields.
func apiErr(t *testing.T, err error, status int, code string) *apierr.Error {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok {
		t.Fatalf("error = %v (%T), want API error %d %s", err, err, status, code)
	}
	if e.Status != status || e.Code != code {
		t.Fatalf("error = %d %s (%s), want %d %s", e.Status, e.Code, e.Message, status, code)
	}
	return e
}

// appUser makes ann@acme.example with the authenticator-app method on and returns the key.
func appUser(t *testing.T, env *authtest.Env) []byte {
	t.Helper()
	u := env.User(t, "ann@acme.example", routes.Viewer)
	setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmTOTP(t.Context(), u.ID, "", auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())))); err != nil {
		t.Fatal(err)
	}
	return secret
}

// emailUser makes a user with the email-code method on.
func emailUser(t *testing.T, env *authtest.Env, email string) auth.User {
	t.Helper()
	u := env.User(t, email, routes.Viewer)
	if _, err := env.Svc.StartEmail2FA(t.Context(), u.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(t.Context(), u.ID, "", env.Mailer.LastCode())); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(2 * time.Minute) // clear the 60 s resend gap and use no sends of the login tests
	return u
}

func jsonOf(t *testing.T, e *apierr.Error) string {
	t.Helper()
	b, err := json.Marshal(e.Body())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
