package auth_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// D-180: a password an administrator set (create, reset) is temporary: it signs in, the session is limited until the user changes
// it, and it ends 72 hours after it was set.

func tempUser(t *testing.T, env *authtest.Env, email string) (auth.User, string) {
	t.Helper()
	temp, hash, err := env.Svc.NewTempCredential(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var u auth.User
	err = env.DB.Write(t.Context(), func(tx *sql.Tx) (err error) {
		u, err = env.Svc.CreateUser(t.Context(), tx, "root@acme.example", auth.NewUser{Name: "Tmp", Email: email, Role: routes.Operator, PasswordHash: hash, Temporary: true})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u, temp
}

func tempLogin(env *authtest.Env, t *testing.T, email, password string) (auth.LoginResult, error) {
	t.Helper()
	return env.Svc.Login(t.Context(), auth.LoginRequest{Email: email, Password: password, IP: ip("192.0.2.7"), UserAgent: "authtest"})
}

func principalOf(t *testing.T, env *authtest.Env, res auth.LoginResult) bool {
	t.Helper()
	p, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", ""))
	if err != nil {
		t.Fatal(err)
	}
	return p.PasswordChangeRequired
}

func TestTempPassword_LimitsTheSessionUntilTheUserChangesIt(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u, temp := tempUser(t, env, "ann@acme.example")
	if !u.PasswordChangeRequired {
		t.Fatal("a created account with a temporary password is not flagged")
	}
	res, err := tempLogin(env, t, u.Email, temp)
	if err != nil {
		t.Fatalf("sign-in with the temporary password: %v", err)
	}
	if !principalOf(t, env, res) {
		t.Fatal("the session of a temporary password is not limited")
	}
	if got, _ := env.Svc.GetUser(t.Context(), u.ID); !got.PasswordChangeRequired {
		t.Fatal("GetUser does not say the password must be changed")
	}

	// The user's own accounts are not flagged: the one the library creates without Temporary, and the one that existed before the column.
	plain := env.User(t, "bob@acme.example", routes.Viewer)
	if plain.PasswordChangeRequired {
		t.Fatal("an ordinary account is flagged")
	}
	pres, err := env.Login(t, plain.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	if principalOf(t, env, pres) {
		t.Fatal("an ordinary session is limited")
	}

	// The change: the temporary password must differ (same_password), the weak policy applies, then the flag is gone for the renewed session.
	wantAPI(t, only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, res.Session.SessionID, temp, temp)), 400, "same_password")
	wantAPI(t, only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, res.Session.SessionID, temp, "short")), 400, "weak_password")
	if !principalOf(t, env, res) {
		t.Fatal("a refused change lifted the limit")
	}
	fresh, err := env.Svc.ChangeOwnPassword(t.Context(), u.ID, res.Session.SessionID, temp, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	if principalOf(t, env, auth.LoginResult{Session: fresh}) {
		t.Fatal("the renewed session is still limited after the change")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_user WHERE id = ? AND temp_password_expires_at IS NULL", u.ID); n != 1 {
		t.Fatal("the temporary-password mark is still set")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'account.password' AND target = ? AND detail = 'temporary password replaced'", u.Email); n != 1 {
		t.Fatalf("audit rows of the replacement = %d, want 1", n)
	}
	if _, err := tempLogin(env, t, u.Email, temp); err == nil {
		t.Fatal("the temporary password still signs in after the change")
	}
	next, err := tempLogin(env, t, u.Email, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	if principalOf(t, env, next) {
		t.Fatal("a sign-in with the user's own password is limited")
	}
}

func TestTempPassword_ResetFlagsAnOrdinaryAccount(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	temp, err := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tempLogin(env, t, u.Email, temp)
	if err != nil {
		t.Fatal(err)
	}
	if !principalOf(t, env, res) {
		t.Fatal("the session after a reset is not limited")
	}
}

func TestTempPassword_ExpiresAfter72Hours(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u, temp := tempUser(t, env, "ann@acme.example")
	inside, err := tempLogin(env, t, u.Email, temp)
	if err != nil {
		t.Fatal(err)
	}

	env.Clock.Advance(auth.TempPasswordLifetime - time.Minute)
	if _, err := tempLogin(env, t, u.Email, temp); err != nil {
		t.Fatalf("a temporary password inside its window was refused: %v", err)
	}
	env.Clock.Advance(2 * time.Minute) // 72 hours and a minute

	// A right password past the window: its own code, the same text as the GUI shows, and a trace for the administrator.
	_, err = tempLogin(env, t, u.Email, temp)
	e := apiErr(t, err, 400, "temp_password_expired")
	if e.Message != "This temporary password has expired. Ask an administrator for a new one." {
		t.Fatalf("message = %q", e.Message)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND target = ? AND detail = 'temporary password expired'", u.Email); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	// A wrong password is still the same invalid_credentials as for an unknown email: the expiry is not told to a guesser.
	_, err = tempLogin(env, t, u.Email, "not the password")
	wantAPI(t, err, 400, "invalid_credentials")
	// The session opened inside the window ends with it.
	if _, err := env.Svc.Sessions.Authenticate(reqWith(inside, "GET", "")); err == nil {
		t.Fatal("a session of an expired temporary password still works")
	}
	// The administrator resets again.
	admin := env.User(t, "root@acme.example", routes.Admin)
	temp2, err := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tempLogin(env, t, u.Email, temp2); err != nil {
		t.Fatalf("sign-in after a new reset: %v", err)
	}
}
