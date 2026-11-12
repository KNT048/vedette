package auth_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// INV-30: the sign-in tables do not grow without end. Ended sessions (idle, revoked) go a day after they ended; keys never proved go
// with their sealed key; expired email codes go an hour past their 10 minutes; code sends go after a day. A live session, a
// confirmed key and a send of the last day stay.
func TestPruneDropsWhatCanNoLongerSignAnyoneIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	appUser(t, env)                       // ann: a confirmed authenticator key
	emailUser(t, env, "bob@acme.example") // bob: email codes (two sends, the used code is gone)
	cy := env.User(t, "cy@acme.example", routes.Viewer)
	if _, err := env.Svc.StartTOTP(ctx, cy.ID, "", authtest.Password); err != nil { // a key cy never proves
		t.Fatal(err)
	}
	for range 2 {
		if _, err := env.Login(t, "cy@acme.example", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE core_session SET revoked_at = started_at WHERE rowid = (SELECT min(rowid) FROM core_session)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err := env.Login(t, "bob@acme.example", "") // 401 twofa_required: a code sent and never typed
	wantAPI(t, err, 401, "twofa_required")
	count := func(q string) int { return env.Count(t, q) }
	secrets := count(`SELECT count(*) FROM core_secret`)
	if count(`SELECT count(*) FROM core_session`) != 2 || count(`SELECT count(*) FROM core_user_totp WHERE confirmed = 0`) != 1 || count(`SELECT count(*) FROM core_email_code`) != 1 {
		t.Fatal("setup: two sessions, a pending key and an unused code")
	}

	p, err := env.Svc.Prune(ctx) // nothing is old enough yet
	if err != nil || p != (auth.Pruned{}) {
		t.Fatalf("pruned right away: %+v %v", p, err)
	}
	// two hours on: the pending key (and its sealed key) and the expired code; the sessions ended (one revoked) only just
	env.Clock.Advance(2 * time.Hour)
	if p, err = env.Svc.Prune(ctx); err != nil || p.PendingTOTP != 1 || p.EmailCodes != 1 || p.Sessions != 0 || p.EmailCodeSends != 0 {
		t.Fatalf("after 2 h: %+v %v", p, err)
	}
	if count(`SELECT count(*) FROM core_secret`) != secrets-1 || count(`SELECT count(*) FROM core_user_totp WHERE confirmed = 1`) != 1 {
		t.Fatal("the pending key's sealed key stayed, or a confirmed key went")
	}
	// a send at 23 h stays at 25 h; the older sends and both ended sessions go
	env.Clock.Advance(21 * time.Hour)
	_, err = env.Login(t, "bob@acme.example", "")
	wantAPI(t, err, 401, "twofa_required")
	sends := count(`SELECT count(*) FROM core_email_code_send`)
	env.Clock.Advance(2 * time.Hour)
	if _, err := env.Login(t, "cy@acme.example", ""); err != nil { // a live session
		t.Fatal(err)
	}
	if p, err = env.Svc.Prune(ctx); err != nil || p.Sessions != 2 || p.EmailCodeSends != int64(sends-1) {
		t.Fatalf("after 25 h: %+v %v (sends before %d)", p, err, sends)
	}
	if count(`SELECT count(*) FROM core_session`) != 1 || count(`SELECT count(*) FROM core_email_code_send`) != 1 {
		t.Fatal("the live session or the last send went")
	}
}
