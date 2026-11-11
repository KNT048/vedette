package auth_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func ssoIn(role routes.Role) auth.SSOIdentity {
	yes := true
	return auth.SSOIdentity{Issuer: "https://idp.example", Subject: "sub-1", Email: "Sso@Acme.Example", EmailVerified: &yes, Name: "Sso\u202eUser", Role: role, IP: netip.MustParseAddr("192.0.2.5"), UserAgent: "t"}
}

func ssoUser(t *testing.T, e *authtest.Env) auth.User {
	t.Helper()
	list, err := e.Svc.ListUsers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range list {
		if u.SSO {
			return u
		}
	}
	t.Fatal("no SSO user")
	return auth.User{}
}

// D-195 (5): an SSO account has no password, no Vedette two-step and no hand-set role: 409 sso_user. Its name never carries an
// invisible character from the IdP (the email's local part instead).
func TestSSO_AccountHasNoPasswordTwofaOrHandSetRole(t *testing.T) {
	e := authtest.New(t)
	admin := e.User(t, "admin@acme.example", routes.Admin)
	res, err := e.Login(t, "admin@acme.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Svc.SSOSignIn(t.Context(), ssoIn(routes.Operator)); err != nil {
		t.Fatal(err)
	}
	u := ssoUser(t, e)
	if u.Email != "sso@acme.example" || u.Name != "sso" || u.Role != routes.Operator {
		t.Fatalf("user = %+v", u)
	}
	_, err = e.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, res.Session.SessionID, u.ID)
	wantAPI(t, err, 409, "sso_user")
	viewer := routes.Viewer
	_, err = e.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, res.Session.SessionID, u.ID, auth.UserPatch{Role: &viewer})
	wantAPI(t, err, 409, "sso_user")
	off := true
	if _, err := e.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, res.Session.SessionID, u.ID, auth.UserPatch{Disabled: &off}); err != nil {
		t.Fatalf("disabling an SSO account: %v", err)
	}
	wantAPI(t, e.Svc.VerifyOwnPassword(t.Context(), u.ID, "", "wrong"), 409, "sso_user")
	_, err = e.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: "", IP: netip.MustParseAddr("192.0.2.1")})
	wantAPI(t, err, 400, "invalid_credentials")
}

// D-196 (3): the last-administrator rule counts only administrators who sign in with a password.
func TestSSO_LastAdminCountsPasswordAdminsOnly(t *testing.T) {
	e := authtest.New(t)
	admin := e.User(t, "admin@acme.example", routes.Admin)
	res, err := e.Login(t, "admin@acme.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Svc.SSOSignIn(t.Context(), ssoIn(routes.Admin)); err != nil {
		t.Fatal(err)
	}
	viewer := routes.Viewer
	_, err = e.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, res.Session.SessionID, admin.ID, auth.UserPatch{Role: &viewer})
	wantAPI(t, err, 400, "last_admin")
	if e, _ := apierr.As(err); !strings.Contains(e.Message, "password") {
		t.Fatalf("message = %q", e.Message)
	}
}

// SSOSignIn refuses a malformed or unverified email for a new identity, and an email of a password account.
func TestSSO_EmailRules(t *testing.T) {
	e := authtest.New(t)
	in := ssoIn(routes.Viewer)
	in.Email = "not-an-email"
	_, err := e.Svc.SSOSignIn(t.Context(), in)
	wantAPI(t, err, 403, "email_unverified")
	no := false
	in = ssoIn(routes.Viewer)
	in.EmailVerified = &no
	_, err = e.Svc.SSOSignIn(t.Context(), in)
	wantAPI(t, err, 403, "email_unverified")
	e.User(t, "sso@acme.example", routes.Viewer)
	_, err = e.Svc.SSOSignIn(t.Context(), ssoIn(routes.Viewer))
	wantAPI(t, err, 409, "email_in_use")
	if n := e.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND detail LIKE 'SSO: %'`); n != 3 {
		t.Fatalf("%d audit rows", n)
	}
}
