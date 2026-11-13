package main

import (
	"database/sql"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
)

// D-473: the first Scan now needs two-step sign-in. A password account with an authenticator app counts as "app", an SSO account as
// "sso" (the identity provider owns MFA and Vedette two-step cannot be turned on for it), a password account without it as none.
func TestExposureTwoStep_RealAccounts(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	var plain, totp auth.User
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if plain, err = s.d.Auth.CreateUser(ctx, tx, "test", auth.NewUser{Name: "Plain", Email: "plain@acme.example", Role: routes.Admin, PasswordHash: "x"}); err != nil {
			return err
		}
		if totp, err = s.d.Auth.CreateUser(ctx, tx, "test", auth.NewUser{Name: "Totp", Email: "totp@acme.example", Role: routes.Admin, PasswordHash: "x"}); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE core_user SET twofa_method = 'app' WHERE id = ?`, totp.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Auth.SSOSignIn(ctx, auth.SSOIdentity{Issuer: "https://idp.example", Subject: "sub-1", Email: "sso@acme.example", Name: "Sso", Role: routes.Admin, IP: netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	var ssoID string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT id FROM core_user WHERE email = 'sso@acme.example'`).Scan(&ssoID); err != nil {
		t.Fatal(err)
	}
	check := exposureTwoStep(s.d.Auth)
	for name, c := range map[string]struct{ id, want string }{"password only": {plain.ID, ""}, "authenticator app": {totp.ID, "app"}, "sso": {ssoID, "sso"}} {
		got, err := check(ctx, c.id)
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v (want %q)", name, got, err, c.want)
		}
	}
	if _, err := check(ctx, "no-such-user"); err == nil {
		t.Error("an unknown user passed")
	}
}
