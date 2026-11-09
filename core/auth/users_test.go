package auth_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func TestCreateUser(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	hash, _ := env.Svc.HashPassword(t.Context(), authtest.Password, "")
	create := func(in auth.NewUser) error {
		in.PasswordHash = hash
		return env.DB.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := env.Svc.CreateUser(t.Context(), tx, "root@acme.example", in)
			return err
		})
	}
	if err := create(auth.NewUser{Name: "Ann", Email: " Ann@Acme.Example ", Role: routes.Operator}); err != nil {
		t.Fatal(err)
	}
	var email, role string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT email, role FROM core_user").Scan(&email, &role); err != nil || email != "ann@acme.example" || role != "operator" {
		t.Fatalf("stored %q %q, %v", email, role, err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.create' AND user = 'root@acme.example' AND target = 'ann@acme.example' AND detail = 'role operator'"); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	tests := []struct {
		name string
		in   auth.NewUser
		code string
		st   int
	}{
		{"duplicate in other case", auth.NewUser{Name: "Ann 2", Email: "ANN@acme.example", Role: routes.Viewer}, "duplicate", 409},
		{"empty name", auth.NewUser{Name: "", Email: "b@acme.example", Role: routes.Viewer}, "invalid_name", 400},
		{"name too long", auth.NewUser{Name: strings.Repeat("x", 81), Email: "b@acme.example", Role: routes.Viewer}, "invalid_name", 400},
		{"control character in name", auth.NewUser{Name: "A\x00nn", Email: "b@acme.example", Role: routes.Viewer}, "invalid_name", 400},
		{"bad email", auth.NewUser{Name: "B", Email: "not an email", Role: routes.Viewer}, "invalid_email", 400},
		{"unknown role", auth.NewUser{Name: "B", Email: "b@acme.example", Role: "root"}, "invalid_role", 400},
		{"public is not a role", auth.NewUser{Name: "B", Email: "b@acme.example", Role: routes.Public}, "invalid_role", 400},
	}
	for _, tc := range tests {
		wantAPI(t, create(tc.in), tc.st, tc.code)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_user"); n != 1 {
		t.Fatalf("%d users, want 1", n)
	}
}

func TestUpdateUserGuards(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	a1 := env.User(t, "a1@acme.example", routes.Admin)
	a2 := env.User(t, "a2@acme.example", routes.Admin)
	v := env.User(t, "v@acme.example", routes.Viewer)
	yes, no := true, false
	viewer, admin := routes.Viewer, routes.Admin
	upd := func(actor auth.User, target string, p auth.UserPatch) (auth.User, error) {
		return env.Svc.UpdateUser(t.Context(), actor.ID, actor.Email, "", target, p)
	}

	// You cannot disable yourself, even with another admin around.
	_, err := upd(a1, a1.ID, auth.UserPatch{Disabled: &yes})
	wantAPI(t, err, 400, "self_disable")
	_, err = upd(a1, "u-nope", auth.UserPatch{Disabled: &yes})
	wantAPI(t, err, 404, "not_found")
	badRole := routes.Role("god")
	_, err = upd(a1, v.ID, auth.UserPatch{Role: &badRole})
	wantAPI(t, err, 400, "invalid_role")

	// Disabling the other admin leaves a1 as the only one: the next change that would empty the set is refused.
	if _, err := upd(a1, a2.ID, auth.UserPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	_, err = upd(a1, a1.ID, auth.UserPatch{Role: &viewer}) // demoting the last active admin
	wantAPI(t, err, 400, "last_admin")
	_, err = upd(a2, a1.ID, auth.UserPatch{Disabled: &yes}) // a disabled admin may do nothing (the actor is re-checked in the write)
	wantAPI(t, err, 403, "disabled")
	if got, _ := env.Svc.GetUser(t.Context(), a1.ID); got.Role != routes.Admin || got.Disabled {
		t.Fatalf("a refused change changed the user: %+v", got)
	}
	// Promoting the viewer makes a second active admin; now a1 may step down.
	if _, err := upd(a1, v.ID, auth.UserPatch{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	if u, err := upd(a1, a1.ID, auth.UserPatch{Role: &viewer}); err != nil || u.Role != routes.Viewer {
		t.Fatalf("step down: %+v, %v", u, err)
	}
	// Re-enable.
	if u, err := upd(v, a2.ID, auth.UserPatch{Disabled: &no}); err != nil || u.Disabled {
		t.Fatalf("enable: %+v, %v", u, err)
	}
	for _, a := range []string{"user.disable", "user.enable", "user.role"} {
		if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = ?", a) == 0 {
			t.Errorf("no %s audit row", a)
		}
	}
}

func TestDisablingEndsSessions(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	_, _ = env.Login(t, u.Email, "")
	_, _ = env.Login(t, u.Email, "")
	yes := true
	if _, err := env.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, "", u.ID, auth.UserPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session WHERE user_id = ? AND revoked_at IS NULL", u.ID); n != 0 {
		t.Fatalf("%d live sessions of a disabled user", n)
	}
}

func TestResetPassword(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	s1, _ := env.Login(t, u.Email, "")
	s2, _ := env.Login(t, u.Email, "")
	adminSession, _ := env.Login(t, admin.Email, "")

	temp, err := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e := auth.ValidatePassword(temp, u.Email); e != nil {
		t.Fatalf("temporary password breaks the policy: %v", e)
	}
	// Every session of that user ended (INV-7); the admin's own did not.
	for _, r := range []auth.LoginResult{s1, s2} {
		if _, err := env.Svc.Sessions.Authenticate(reqWith(r, "GET", "")); err == nil {
			t.Fatal("a session survived the password reset")
		}
	}
	if _, err := env.Svc.Sessions.Authenticate(reqWith(adminSession, "GET", "")); err != nil {
		t.Fatalf("the admin's session ended: %v", err)
	}
	// The old password is dead; the temporary one works.
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 400, "invalid_credentials")
	if _, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: temp, IP: ip("192.0.2.9")}); err != nil {
		t.Fatalf("sign-in with the temporary password: %v", err)
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.password_reset' AND target = ? AND user = ? AND detail LIKE '%'||?||'%'", u.Email, admin.Email, temp) != 0 {
		t.Fatal("temporary password in the audit log")
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.password_reset' AND target = ?", u.Email) != 1 {
		t.Fatal("no audit row for the reset")
	}
	if strings.Contains(env.Logs.String(), temp) {
		t.Fatal("temporary password in the logs")
	}
	temp2, _ := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID)
	if temp2 == temp {
		t.Fatal("two resets gave the same password")
	}
	_, err = env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", "u-nope")
	wantAPI(t, err, 404, "not_found")
}

func TestChangeOwnPassword(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	keep, _ := env.Login(t, u.Email, "")
	other, _ := env.Login(t, u.Email, "")
	change := func(cur, next string) (auth.Issued, error) {
		return env.Svc.ChangeOwnPassword(t.Context(), u.ID, keep.Session.SessionID, cur, next)
	}

	wantAPI(t, only(change("not my password", "a brand new password")), 400, "wrong_password")
	wantAPI(t, only(change(authtest.Password, "short")), 400, "weak_password")
	wantAPI(t, only(change(authtest.Password, "ann@acme.example")), 400, "weak_password")
	wantAPI(t, only(change(authtest.Password, authtest.Password)), 400, "same_password")
	fresh, err := change(authtest.Password, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	// The current session is renewed: its old token ends, the new one works.
	if _, err := env.Svc.Sessions.Authenticate(reqWith(keep, "GET", "")); err == nil {
		t.Fatal("the old token of the current session survived a password change")
	}
	if _, err := env.Svc.Sessions.Authenticate(reqWith(auth.LoginResult{Session: fresh}, "GET", "")); err != nil {
		t.Fatalf("the renewed session does not work: %v", err)
	}
	if _, err := env.Svc.Sessions.Authenticate(reqWith(other, "GET", "")); err == nil {
		t.Fatal("another session survived a password change")
	}
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 400, "invalid_credentials")
	if _, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: "a brand new password", IP: ip("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'account.password' AND detail IS NULL") != 1 {
		t.Fatal("expected one account.password row without detail")
	}
}

func TestOwnPasswordGuessesAreRateLimited(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	for range 10 {
		wantAPI(t, only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", "guess guess guess", "a brand new password")), 400, "wrong_password")
	}
	wantAPI(t, only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", authtest.Password, "a brand new password")), 429, "rate_limited")
	wantAPI(t, only(env.Svc.DisableTwoFA(t.Context(), u.ID, "", authtest.Password)), 429, "rate_limited")
	env.Clock.Advance(31 * time.Second)
	if err := only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", authtest.Password, "a brand new password")); err != nil {
		t.Fatal(err)
	}
}

// Review of WP-04b part 2 (M1): the renewed session is the same browser (device text and address) with new
// tokens, and it lives a full lifetime from now, like a new sign-in (the user has just proved the password).
func TestRenewedSessionKeepsTheBrowserAndChangesEveryToken(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: authtest.Password, IP: ip("192.0.2.77"), UserAgent: "Firefox on a desk"})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := env.Svc.ChangeOwnPassword(t.Context(), u.ID, res.Session.SessionID, authtest.Password, "a brand new password")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.SessionID == res.Session.SessionID || fresh.Token == res.Session.Token || fresh.CSRFToken == res.Session.CSRFToken {
		t.Fatalf("the renewed session shares something with the old one: %+v / %+v", fresh, res.Session)
	}
	list, err := env.Svc.Sessions.List(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != fresh.SessionID || list[0].Device != "Firefox on a desk" || list[0].IP != "192.0.2.77" {
		t.Fatalf("sessions after the change = %+v, want only the renewed one for the same browser", list)
	}
	// No current session (a caller without one): every session ends and nothing new is made.
	none, err := env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", "a brand new password", "yet another long password")
	if err != nil || none != (auth.Issued{}) {
		t.Fatalf("with no current session: %+v, %v", none, err)
	}
}

// Review of WP-04b part 2 (L5): a wrong password typed to change the password or turn two-step on or off is
// a guess, and leaves an auth.reauth_failed row like a wrong sign-in password leaves auth.login_failed.
func TestWrongReauthPasswordIsAudited(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	wantAPI(t, only(env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", "guess guess guess", "a brand new password")), 400, "wrong_password")
	_, err := env.Svc.StartTOTP(t.Context(), u.ID, "", "guess guess guess")
	wantAPI(t, err, 400, "wrong_password")
	wantAPI(t, only(env.Svc.DisableTwoFA(t.Context(), u.ID, "", "guess guess guess")), 400, "wrong_password")
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.reauth_failed' AND target = 'ann@acme.example' AND detail = 'wrong password'"); n != 3 {
		t.Fatalf("%d auth.reauth_failed rows, want 3", n)
	}
	if env.Count(t, "SELECT count(*) FROM core_audit WHERE detail LIKE '%guess%'") != 0 {
		t.Fatal("a guessed password reached the audit log")
	}
	// The right password writes no such row.
	if _, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.reauth_failed'"); n != 3 {
		t.Fatalf("a right password wrote auth.reauth_failed (%d rows)", n)
	}
}

// Review of WP-04b part 2 (L7): names refuse invisible format characters (category Cf) as well as control
// characters: a bidirectional override makes a name read as another, a zero-width space makes one that cannot be
// typed back.
func TestNamesRefuseInvisibleFormatCharacters(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	for name, bad := range map[string]string{
		"right-to-left override": "Ann\u202Enimda", "zero width space": "Bo\u200Bb", "soft hyphen": "An\u00ADn",
		"byte order mark": "\uFEFFAnn", "word joiner": "A\u2060nn", "tag character": "Ann\U000E0041", "control": "Ann\u0007",
	} {
		if !auth.HasInvisible(bad) {
			t.Errorf("%s: HasInvisible = false", name)
		}
		if _, e := auth.ValidateUserFields(bad, "bob@acme.example", routes.Viewer); e == nil || e.Code != "invalid_name" {
			t.Errorf("%s: new user name accepted (%v)", name, e)
		}
		wantAPI(t, env.Svc.UpdateOwnName(t.Context(), u.ID, "", bad), 400, "invalid_name")
	}
	for _, ok := range []string{"Nguyễn Văn An", "Zoë O'Brien-Smith", "田中 太郎"} {
		if auth.HasInvisible(ok) {
			t.Errorf("%q refused", ok)
		}
		if _, e := auth.ValidateUserFields(ok, "bob@acme.example", routes.Viewer); e != nil {
			t.Errorf("%q: %v", ok, e)
		}
	}
}
