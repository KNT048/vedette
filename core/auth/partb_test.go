package auth_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// WP-04b1 carry-over: a dead session gets 401 from DisableTwoFA whatever else is stale (the order of
// ChangeOwnPassword): the caller is refused before the password proof is compared. An administrator's reset
// that lands while the password is being checked ends the session AND moves the password; the answer must be
// 401, not wrong_password.
func TestDisableTwoFARefusesADeadSessionBeforeTheStalePassword(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	sid := res.Session.SessionID
	if _, err := env.Svc.StartEmail2FA(t.Context(), u.ID, sid, authtest.Password); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(t.Context(), u.ID, sid, env.Mailer.LastCode())); err != nil {
		t.Fatal(err)
	}
	var armed, fired atomic.Bool
	auth.SetHashProbe(env.Svc, func(d int) {
		if d < 0 && armed.Load() && fired.CompareAndSwap(false, true) {
			if _, err := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID); err != nil {
				t.Error(err)
			}
		}
	})
	armed.Store(true)
	wantAPI(t, only(env.Svc.DisableTwoFA(t.Context(), u.ID, sid, authtest.Password)), 401, "unauthenticated")
	if !fired.Load() {
		t.Fatal("the reset did not run in the window")
	}
}

// WP-04b1 carry-over: an administrator whose session ended, who was disabled or who was demoted changes
// nothing: ResetPassword, UpdateUser and ResetTwoFA re-check the actor in the transaction that writes.
func TestAdminActionsRecheckTheActorInTheWriteTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := authtest.New(t)
	a1 := env.User(t, "a1@acme.example", routes.Admin)
	a2 := env.User(t, "a2@acme.example", routes.Admin)
	v := env.User(t, "v@acme.example", routes.Viewer)
	s1, err := env.Login(t, a1.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	live := s1.Session.SessionID
	// Turn two-step on for v so the reset has something to do.
	if _, err := env.Svc.StartEmail2FA(ctx, v.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(ctx, v.ID, "", env.Mailer.LastCode())); err != nil {
		t.Fatal(err)
	}
	yes := true

	// 1. Session ended: 401, nothing changes.
	if err := env.Svc.Sessions.Revoke(ctx, a1.Email, a1.ID, live); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.ResetPassword(ctx, a1.ID, a1.Email, live, v.ID)
	wantAPI(t, err, 401, "unauthenticated")
	_, err = env.Svc.UpdateUser(ctx, a1.ID, a1.Email, live, v.ID, auth.UserPatch{Disabled: &yes})
	wantAPI(t, err, 401, "unauthenticated")
	wantAPI(t, env.Svc.ResetTwoFA(ctx, a1.ID, a1.Email, live, v.ID), 401, "unauthenticated")
	if got, _ := env.Svc.GetUser(ctx, v.ID); got.Disabled || got.TwofaMethod == "" {
		t.Fatalf("a dead session changed the user: %+v", got)
	}

	// 2. Disabled actor: 403 disabled.
	if _, err := env.Svc.UpdateUser(ctx, a2.ID, a2.Email, "", a1.ID, auth.UserPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.ResetPassword(ctx, a1.ID, a1.Email, "", v.ID)
	wantAPI(t, err, 403, "disabled")
	wantAPI(t, env.Svc.ResetTwoFA(ctx, a1.ID, a1.Email, "", v.ID), 403, "disabled")

	// 3. Demoted actor: 403 forbidden.
	no := false
	viewer := routes.Viewer
	if _, err := env.Svc.UpdateUser(ctx, a2.ID, a2.Email, "", a1.ID, auth.UserPatch{Disabled: &no, Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.ResetPassword(ctx, a1.ID, a1.Email, "", v.ID)
	wantAPI(t, err, 403, "forbidden")
	_, err = env.Svc.UpdateUser(ctx, a1.ID, a1.Email, "", v.ID, auth.UserPatch{Disabled: &yes})
	wantAPI(t, err, 403, "forbidden")
	wantAPI(t, env.Svc.ResetTwoFA(ctx, a1.ID, a1.Email, "", v.ID), 403, "forbidden")
	if got, _ := env.Svc.GetUser(ctx, v.ID); got.Disabled || got.TwofaMethod == "" {
		t.Fatalf("a demoted actor changed the user: %+v", got)
	}
	// 4. The checked actor still can: a2 (an admin, no session claimed).
	if _, err := env.Svc.ResetPassword(ctx, a2.ID, a2.Email, "", v.ID); err != nil {
		t.Fatal(err)
	}
}

// D-76: turning two-step on needs the current password; a wrong one is refused and counted like a wrong
// sign-in password (the same account limiter as DisableTwoFA).
func TestEnablingTwoStepNeedsThePassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	_, err := env.Svc.StartTOTP(ctx, u.ID, "", "wrong password here")
	wantAPI(t, err, 400, "wrong_password")
	_, err = env.Svc.StartEmail2FA(ctx, u.ID, "", "wrong password here")
	wantAPI(t, err, 400, "wrong_password")
	if len(env.Mailer.Sent()) != 0 {
		t.Fatal("a code was mailed on a wrong password")
	}
	// Ten wrong passwords (two done) lock the account's password checks: the right one is then 429 too.
	for range 8 {
		_, err = env.Svc.StartTOTP(ctx, u.ID, "", "wrong password here")
		wantAPI(t, err, 400, "wrong_password")
	}
	_, err = env.Svc.StartTOTP(ctx, u.ID, "", authtest.Password)
	wantAPI(t, err, 429, "rate_limited")
	// A fresh account: the right password starts both methods.
	env2 := authtest.New(t)
	u2 := env2.User(t, "ann@acme.example", routes.Viewer)
	if _, err := env2.Svc.StartTOTP(ctx, u2.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if _, err := env2.Svc.StartEmail2FA(ctx, u2.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
}
