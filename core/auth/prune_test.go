package auth_test

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth/authtest"
)

// INV-30: the sign-in tables do not grow without end. Ended sessions go 30 days after they ended; keys never proved, email codes and
// code sends go once they can no longer count; a live session, a confirmed key and the current hour's sends stay.
func TestPruneDropsWhatCanNoLongerSignAnyoneIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	appUser(t, env)                       // ann: a confirmed authenticator key
	emailUser(t, env, "bob@acme.example") // two code sends and a used code
	cy := env.User(t, "cy@acme.example", routes.Viewer)
	if _, err := env.Svc.StartTOTP(ctx, cy.ID, "", authtest.Password); err != nil { // a key cy never proves
		t.Fatal(err)
	}
	if _, err := env.Login(t, "cy@acme.example", ""); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int { return env.Count(t, q) }
	if count(`SELECT count(*) FROM core_session`) != 1 || count(`SELECT count(*) FROM core_user_totp WHERE confirmed = 0`) != 1 || count(`SELECT count(*) FROM core_email_code_send`) == 0 {
		t.Fatal("setup: no session, pending key or code send")
	}

	// within the hour nothing goes
	p, err := env.Svc.Prune(ctx)
	if err != nil || p.Sessions+p.PendingTOTP+p.EmailCodes+p.EmailCodeSends != 0 {
		t.Fatalf("pruned right away: %+v %v", p, err)
	}
	// a day later: the pending key, the codes and the sends; the session ended (4 h idle) but only a day ago
	env.Clock.Advance(25 * time.Hour)
	if p, err = env.Svc.Prune(ctx); err != nil || p.PendingTOTP != 1 || p.EmailCodeSends == 0 || p.Sessions != 0 {
		t.Fatalf("after a day: %+v %v", p, err)
	}
	if count(`SELECT count(*) FROM core_user_totp WHERE confirmed = 1`) != 1 || count(`SELECT count(*) FROM core_email_code`) != 0 {
		t.Fatal("a confirmed key went, or an expired code stayed")
	}
	// 30 days after it ended, the session goes; one signed in now stays
	env.Clock.Advance(30 * 24 * time.Hour)
	if _, err := env.Login(t, "cy@acme.example", ""); err != nil {
		t.Fatal(err)
	}
	if p, err = env.Svc.Prune(ctx); err != nil || p.Sessions != 1 || count(`SELECT count(*) FROM core_session`) != 1 {
		t.Fatalf("after 31 days: %+v %v, %d sessions", p, err, count(`SELECT count(*) FROM core_session`))
	}
}
