package authoidc_test

import (
	"bytes"
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/secrets"
	authoidc "github.com/knt048/vedette/modules/auth-oidc"
)

// After a backup restored without its decryption key the client secret is sealed under another master key (#812): SSO
// sign-in is refused with 409 sso_secret_lost, at the start (the browser is not sent to the identity provider for nothing)
// and at a callback of a sign-in started before, not a 500; no session. Saving the secret again makes SSO work.
func TestRestoreWithoutKeyClientSecretIsRefusedNotA500(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	state, binding := w.start()
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := w.env.DB.Write(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, "SELECT id FROM core_secret WHERE purpose = 'oidc_config.client_secret'").Scan(&id); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, id, "oidc_config.client_secret", []byte(w.idp.secret), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	_, err = w.callback(state, binding)
	wantCode(t, err, 409, "sso_secret_lost")
	_, err = w.svc.Start(ctx, origin, w.addr)
	wantCode(t, err, 409, "sso_secret_lost")
	if n := w.env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions", n)
	}
	if !w.auditHas("auth.login_failed", "SSO: client_secret") {
		t.Fatal("the refused callback is not in the audit log")
	}

	w.configure(authoidc.Save{Scopes: "openid email profile", GroupsClaim: "groups", RoleMap: []authoidc.RoleRow{{Group: "staff", Role: routes.Viewer}}}) // the administrator enters the secret again
	if _, err := w.signIn(); err != nil {
		t.Fatalf("SSO after the secret was entered again: %v", err)
	}
}
