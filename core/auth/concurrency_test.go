package auth_test

import (
	"encoding/base32"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

// two password changes at once from two sessions of the same user, both past the password
// check (a barrier on the argon2 probe holds each request until the other has also verified and is hashing).
// Exactly one wins; the loser is refused in the transaction (its session was ended by the winner, or the
// password moved) and gets no session; the user ends with exactly one live session (the winner's new one);
// both old tokens are dead; another user's session is untouched.
func TestConcurrentPasswordChangesFromTwoSessionsHaveOneWinner(t *testing.T) {
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 4 })
	u := env.User(t, "ann@acme.example", routes.Viewer)
	env.User(t, "bob@acme.example", routes.Viewer)
	a, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := env.Login(t, "bob@acme.example", "")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	gates := []chan struct{}{make(chan struct{}), make(chan struct{})}
	auth.SetHashProbe(env.Svc, func(d int) {
		if d != 1 {
			return
		}
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		g := gates[min((n-1)/2, 1)]
		if n%2 == 0 {
			close(g)
			return
		}
		select {
		case <-g:
		case <-time.After(10 * time.Second):
			t.Error("barrier timed out")
		}
	})
	type out struct {
		fresh auth.Issued
		err   error
	}
	res := make([]out, 2)
	var wg sync.WaitGroup
	for i, sid := range []string{a.Session.SessionID, b.Session.SessionID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := []string{"first brand new long password", "second brand new long password"}[i]
			f, err := env.Svc.ChangeOwnPassword(t.Context(), u.ID, sid, authtest.Password, next)
			res[i] = out{f, err}
		}()
	}
	wg.Wait()
	wins := 0
	var winner auth.Issued
	for i, r := range res {
		if r.err == nil {
			wins++
			winner = r.fresh
			continue
		}
		e, ok := apierr.As(r.err)
		if !ok || (e.Status != 401 && e.Status != 409) {
			t.Fatalf("loser %d: %v", i, r.err)
		}
		if r.fresh.Token != "" {
			t.Fatalf("loser %d got a session", i)
		}
		t.Logf("loser %d: %v", i, r.err)
	}
	if wins != 1 {
		t.Fatalf("%d of 2 concurrent password changes won, want 1: %+v", wins, res)
	}
	live, err := env.Svc.Sessions.List(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].ID != winner.SessionID {
		t.Fatalf("live sessions after the race = %+v, want only the winner's new one %s", live, winner.SessionID)
	}
	for _, old := range []string{a.Session.Token, b.Session.Token} {
		if _, err := env.Svc.Sessions.Lookup(t.Context(), old); err == nil {
			t.Fatal("an old token still works after the race")
		}
	}
	if _, err := env.Svc.Sessions.Lookup(t.Context(), bob.Session.Token); err != nil {
		t.Fatalf("another user's session ended: %v", err)
	}
}

// two confirms of the same pending authenticator key at once, from two sessions, with the same
// valid code. Exactly one turns two-step on and gets a session; the other is refused without one.
func TestConcurrentTOTPConfirmsFromTwoSessionsHaveOneWinner(t *testing.T) {
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	a, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := env.Svc.StartTOTP(t.Context(), u.ID, a.Session.SessionID, authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := auth.TOTPCode(key, auth.TOTPStep(env.Clock.Now()))
	errs := make([]error, 2)
	fresh := make([]auth.Issued, 2)
	var wg sync.WaitGroup
	for i, sid := range []string{a.Session.SessionID, b.Session.SessionID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh[i], errs[i] = env.Svc.ConfirmTOTP(t.Context(), u.ID, sid, code)
		}()
	}
	wg.Wait()
	wins := 0
	for i := range errs {
		if errs[i] == nil {
			wins++
			continue
		}
		if fresh[i].Token != "" {
			t.Fatalf("loser %d got a session: %v", i, errs[i])
		}
		t.Logf("loser: %v", errs[i])
	}
	if wins != 1 {
		t.Fatalf("%d of 2 concurrent confirms won: %v", wins, errs)
	}
	if live, _ := env.Svc.Sessions.List(t.Context(), u.ID); len(live) != 1 {
		t.Fatalf("%d live sessions after the race, want 1", len(live))
	}
}

// The five-wrong-codes cap of a pending key holds under concurrency: the count is reserved before a code is
// judged, so ten parallel guesses get at most five judged (four "wrong_code" and the fifth, which drops the
// key, "too_many_tries"); the others find the key used up or gone (409 no_pending), never a 500; the key is
// gone afterwards.
func TestConfirmTOTPParallelGuessesJudgeAtMostFiveCodesPerKey(t *testing.T) {
	t.Parallel()
	for trial := range 8 {
		env := authtest.New(t)
		u := env.User(t, "ann@acme.example", routes.Viewer)
		setup, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password)
		if err != nil {
			t.Fatal(err)
		}
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
		if err != nil {
			t.Fatal(err)
		}
		cur := auth.TOTPStep(env.Clock.Now())
		valid := map[string]bool{}
		for d := int64(-2); d <= 2; d++ {
			valid[auth.TOTPCode(key, cur+d)] = true
		}
		var codes []string
		for i := 0; len(codes) < 10; i++ {
			if c := fmt.Sprintf("%06d", i); !valid[c] {
				codes = append(codes, c)
			}
		}
		got := make([]string, len(codes))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, c := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := env.Svc.ConfirmTOTP(t.Context(), u.ID, "", c)
				if e, ok := apierr.As(err); ok {
					got[i] = fmt.Sprintf("%d %s", e.Status, e.Code)
				} else {
					got[i] = fmt.Sprintf("other: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		wrong, tooMany := 0, 0
		for _, g := range got {
			switch g {
			case "400 wrong_code":
				wrong++
			case "400 too_many_tries":
				tooMany++
			case "409 no_pending":
			default:
				t.Fatalf("trial %d: unexpected answer %q in %v", trial, g, got)
			}
		}
		if wrong > 4 || tooMany < 1 {
			t.Fatalf("trial %d: %d wrong_code and %d too_many_tries in %v, want at most 4 judged wrong plus the one that drops the key", trial, wrong, tooMany, got)
		}
		_, err = env.Svc.ConfirmTOTP(t.Context(), u.ID, "", codes[0])
		if e, ok := apierr.As(err); !ok || e.Code != auth.CodeNoPending {
			t.Fatalf("trial %d: after the drop: %v, want no_pending", trial, err)
		}
	}
}

// Sequentially: four wrong codes, the fifth drops the key, the sixth finds none.
func TestConfirmTOTPFifthWrongCodeDropsTheKey(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	if _, err := env.Svc.StartTOTP(t.Context(), u.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		_, err := env.Svc.ConfirmTOTP(t.Context(), u.ID, "", "000000")
		wantAPI(t, err, 400, "wrong_code")
	}
	_, err := env.Svc.ConfirmTOTP(t.Context(), u.ID, "", "000000")
	wantAPI(t, err, 400, "too_many_tries")
	_, err = env.Svc.ConfirmTOTP(t.Context(), u.ID, "", "000000")
	wantAPI(t, err, 409, "no_pending")
}
