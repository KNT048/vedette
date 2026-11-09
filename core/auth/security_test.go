package auth_test

// Tests of the fixes of the independent security review (WP-04b part 1): one test per finding, named
// after what must hold.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store/coredb"
)

// parallel runs fn(i) for i in 0..n-1 at once (released together) and waits for all.
func parallel(n int, fn func(i int)) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			fn(i)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

func decodeBase32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loginAs(env *authtest.Env, email, password, code string, addr netip.Addr) error {
	_, err := env.Svc.Login(context.Background(), auth.LoginRequest{Email: email, Password: password, Code: code, IP: addr, UserAgent: "test"})
	return err
}

// ---- H1: argon2 concurrency cap ----------------------------------------------------------------

func TestH1ArgonRunsNeverExceedTheCap(t *testing.T) {
	t.Parallel()
	const limit = 2
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = limit; c.HashWait = 10 * time.Second })
	var cur, peak atomic.Int32
	auth.SetHashProbe(env.Svc, func(d int) {
		n := cur.Add(int32(d)) //nolint:gosec // d is +1 or -1
		if d > 0 {
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			for range 500 {
				runtime.Gosched() // give the other requests the chance to overlap with this run
			}
		}
	})
	parallel(60, func(i int) {
		err := loginAs(env, fmt.Sprintf("nobody%d@acme.example", i), "wrong password here", "", ip("192.0.2.1"))
		if e, _ := apierr.As(err); e == nil || (e.Code != "invalid_credentials" && e.Code != "server_busy") {
			t.Errorf("login %d: %v", i, err)
		}
	})
	if p := peak.Load(); p < 1 || p > limit {
		t.Fatalf("peak concurrent argon2 runs = %d, want 1..%d", p, limit)
	}
}

func TestH1FullQueueIsRefusedAtOnce(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 1; c.HashWait = 30 * time.Second })
	hold, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	auth.SetHashProbe(env.Svc, func(d int) {
		if d > 0 {
			once.Do(func() { close(entered); <-hold })
		}
	})
	first := make(chan error, 1)
	go func() { first <- loginAs(env, "first@acme.example", "wrong password here", "", ip("192.0.2.1")) }()
	<-entered // the only slot is taken and will stay taken

	// The queue holds 4 per slot: of 20 more requests, 4 wait and 16 are refused without waiting.
	results := make(chan error, 20)
	for i := range 20 {
		go func() {
			results <- loginAs(env, fmt.Sprintf("other%d@acme.example", i), "wrong password here", "", ip("192.0.2.2"))
		}()
	}
	for range 16 {
		select {
		case err := <-results:
			wantAPI(t, err, 503, "server_busy")
		case <-time.After(5 * time.Second):
			close(hold)
			t.Fatal("a request beyond the queue was not refused at once")
		}
	}
	close(hold)
	for range 4 + 1 {
		select {
		case err := <-results:
			wantAPI(t, err, 400, "invalid_credentials")
		case err := <-first:
			wantAPI(t, err, 400, "invalid_credentials")
		case <-time.After(10 * time.Second):
			t.Fatal("queued requests never finished")
		}
	}
}

func TestH1BusyIs503WithRetryAfterAndDoesNotCountAsAGuess(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 1; c.HashWait = 20 * time.Millisecond })
	u := env.User(t, "ann@acme.example", routes.Viewer)
	hold, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var blocking atomic.Bool
	auth.SetHashProbe(env.Svc, func(d int) {
		if d > 0 && blocking.Load() {
			once.Do(func() { close(entered); <-hold })
		}
	})
	blocking.Store(true)
	first := make(chan error, 1)
	go func() { first <- loginAs(env, u.Email, authtest.Password, "", ip("192.0.2.5")) }()
	<-entered // the only slot is taken

	for range 12 { // more than the limit of 10: busy refusals must not count
		e := apiErr(t, loginAs(env, u.Email, authtest.Password, "", ip("192.0.2.6")), 503, "server_busy")
		if e.Extra["retry_after"] != 3 {
			t.Fatalf("retry_after = %v", e.Extra["retry_after"])
		}
	}
	// The same applies to the other callers of argon2.
	wantAPI(t, func() error { _, err := env.Svc.HashPassword(t.Context(), "a long enough password", ""); return err }(), 503, "server_busy")
	wantAPI(t, env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", authtest.Password, "another long password"), 503, "server_busy")
	_, err := env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, ip("192.0.2.6"))
	wantAPI(t, err, 503, "server_busy")

	blocking.Store(false)
	close(hold)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := loginAs(env, u.Email, authtest.Password, "", ip("192.0.2.6")); err != nil {
		t.Fatalf("sign-in after the burst: %v (busy refusals were counted as failed guesses)", err)
	}
}

func TestH1CancelledWhileWaitingReturnsTheContextError(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 1; c.HashWait = 10 * time.Second })
	hold, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	auth.SetHashProbe(env.Svc, func(d int) {
		if d > 0 {
			once.Do(func() { close(entered); <-hold })
		}
	})
	go func() { _ = loginAs(env, "a@acme.example", "wrong password here", "", ip("192.0.2.1")) }()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := env.Svc.Login(ctx, auth.LoginRequest{Email: "b@acme.example", Password: "x", IP: ip("192.0.2.2")})
	close(hold)
	if err == nil || strings.Contains(err.Error(), "server_busy") {
		t.Fatalf("err = %v, want a context error", err)
	}
}

// ---- M1: parallel guesses ------------------------------------------------------------------------

func TestM1ParallelWrongGuessesAreCappedAtTheLimit(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 8; c.HashWait = 10 * time.Second })
	u := env.User(t, "ann@acme.example", routes.Viewer)
	var limited, invalid atomic.Int32
	parallel(24, func(int) {
		switch e, _ := apierr.As(loginAs(env, u.Email, "wrong password here", "", ip("192.0.2.1"))); {
		case e != nil && e.Code == "rate_limited":
			limited.Add(1)
		case e != nil && e.Code == "invalid_credentials":
			invalid.Add(1)
		default:
			t.Error("unexpected result")
		}
	})
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed' AND detail = 'wrong password'"); n > 10 {
		t.Fatalf("%d guesses reached the password check, the limit is 10", n)
	}
	if invalid.Load() > 10 || limited.Load() < 14 {
		t.Fatalf("invalid_credentials=%d rate_limited=%d, want at most 10 and at least 14", invalid.Load(), limited.Load())
	}
}

func TestM1ParallelGuessesAtTheOwnPasswordAreCappedToo(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 8; c.HashWait = 10 * time.Second })
	u := env.User(t, "ann@acme.example", routes.Viewer)
	var wrong, limited atomic.Int32
	parallel(24, func(int) {
		switch e, _ := apierr.As(env.Svc.ChangeOwnPassword(t.Context(), u.ID, "", "wrong password here", "a brand new password")); {
		case e != nil && e.Code == "wrong_password":
			wrong.Add(1)
		case e != nil && e.Code == "rate_limited":
			limited.Add(1)
		default:
			t.Error("unexpected result")
		}
	})
	if wrong.Load() > 10 || limited.Load() < 14 {
		t.Fatalf("wrong_password=%d rate_limited=%d", wrong.Load(), limited.Load())
	}
}

// ---- M2: client address --------------------------------------------------------------------------

func TestM2ZeroAddressIsRefusedNotPooled(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	_, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: authtest.Password})
	if err == nil {
		t.Fatal("a login without a client address succeeded")
	}
	if _, ok := apierr.As(err); ok {
		t.Fatalf("a missing address is a programming error, not a client error: %v", err)
	}
	if _, err := env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, netip.Addr{}); err == nil {
		t.Fatal("resend-code without an address succeeded")
	}
}

func TestM2ClientsFromAHostPortAreSeparate(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	addr := func(hostport string) netip.Addr { return netip.MustParseAddrPort(hostport).Addr() }
	attacker, victim := addr("192.0.2.66:51234"), addr("192.0.2.77:40001")
	for range 10 {
		wantAPI(t, loginAs(env, u.Email, "wrong password here", "", attacker), 400, "invalid_credentials")
	}
	wantAPI(t, loginAs(env, u.Email, authtest.Password, "", attacker), 429, "rate_limited")
	res, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: authtest.Password, IP: victim, UserAgent: "x"})
	if err != nil {
		t.Fatalf("another client was locked out by the attacker: %v", err)
	}
	var stored string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT ip FROM core_session WHERE id = ?", res.Session.SessionID).Scan(&stored); err != nil || stored != "192.0.2.77" {
		t.Fatalf("session ip = %q, %v; want the real client address", stored, err)
	}
	// An IPv6 client's row keeps its full address, not the /64 used for the limit.
	res6, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: authtest.Password, IP: ip("2001:db8:0:5::1234"), UserAgent: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT ip FROM core_session WHERE id = ?", res6.Session.SessionID).Scan(&stored); err != nil || stored != "2001:db8:0:5::1234" {
		t.Fatalf("session ip = %q, %v", stored, err)
	}
}

// ---- M3: two-step guesses from rotating addresses -------------------------------------------------

func wrongTOTP(t *testing.T, env *authtest.Env, secret []byte) string {
	t.Helper()
	cur := auth.TOTPStep(env.Clock.Now())
	good := map[string]bool{}
	for d := int64(-2); d <= 2; d++ {
		good[auth.TOTPCode(secret, cur+d)] = true
	}
	for i := range 1_000_000 {
		if c := fmt.Sprintf("%06d", i); !good[c] {
			return c
		}
	}
	panic("unreachable")
}

func TestM3RotatingIPv6AddressesInOnePrefixShareTheLimit(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	wrong := wrongTOTP(t, env, secret)
	var judged, limited int
	for i := range 60 {
		switch e, _ := apierr.As(loginAs(env, "ann@acme.example", authtest.Password, wrong, ip(fmt.Sprintf("2001:db8:0:1::%x", i+1)))); {
		case e != nil && e.Code == "invalid_code":
			judged++
		case e != nil && e.Code == "rate_limited":
			limited++
		default:
			t.Fatalf("attempt %d: %v", i, e)
		}
	}
	if judged > 10 || limited < 50 {
		t.Fatalf("judged=%d limited=%d: 60 addresses of one /64 must be one client", judged, limited)
	}
}

func TestM3PasswordGuessesFromOneIPv6PrefixShareTheLimitButOtherPrefixesDoNot(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	var judged, limited int
	for i := range 60 {
		switch e, _ := apierr.As(loginAs(env, u.Email, "wrong password here", "", ip(fmt.Sprintf("2001:db8:0:1::%x", i+1)))); {
		case e != nil && e.Code == "invalid_credentials":
			judged++
		case e != nil && e.Code == "rate_limited":
			limited++
		default:
			t.Fatalf("attempt %d: %v", i, e)
		}
	}
	if judged != 10 || limited != 50 {
		t.Fatalf("one /64: judged=%d limited=%d, want 10 and 50", judged, limited)
	}
	// Another prefix, and an IPv4 address, are other clients.
	wantAPI(t, loginAs(env, u.Email, "wrong password here", "", ip("2001:db8:0:2::1")), 400, "invalid_credentials")
	wantAPI(t, loginAs(env, u.Email, "wrong password here", "", ip("192.0.2.1")), 400, "invalid_credentials")
	// An IPv4-mapped IPv6 address is the IPv4 client.
	for range 9 {
		wantAPI(t, loginAs(env, u.Email, "wrong password here", "", ip("::ffff:192.0.2.1")), 400, "invalid_credentials")
	}
	wantAPI(t, loginAs(env, u.Email, "wrong password here", "", ip("192.0.2.1")), 429, "rate_limited")
}

func TestM3RotatingPrefixesStillHitThePerAccountLimit(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	wrong := wrongTOTP(t, env, secret)
	var judged, limited int
	for i := range 60 {
		switch e, _ := apierr.As(loginAs(env, "ann@acme.example", authtest.Password, wrong, ip(fmt.Sprintf("2001:db8:%x::1", i+1)))); {
		case e != nil && e.Code == "invalid_code":
			judged++
		case e != nil && e.Code == "rate_limited":
			limited++
		default:
			t.Fatalf("attempt %d: %v", i, e)
		}
	}
	if judged > 10 || limited < 50 {
		t.Fatalf("judged=%d limited=%d: 60 different /64s must meet the account's two-step limit", judged, limited)
	}
	good := auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now()))
	wantAPI(t, loginAs(env, "ann@acme.example", authtest.Password, good, ip("2001:db8:ffff::1")), 429, "rate_limited")
	env.Clock.Advance(16 * time.Minute)
	good = auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now()))
	if err := loginAs(env, "ann@acme.example", authtest.Password, good, ip("2001:db8:ffff::1")); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
}

func TestM3ParallelTwoStepGuessesAreCounted(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 8; c.HashWait = 10 * time.Second })
	secret := appUser(t, env)
	wrong := wrongTOTP(t, env, secret)
	var judged atomic.Int32
	parallel(30, func(i int) {
		if e, _ := apierr.As(loginAs(env, "ann@acme.example", authtest.Password, wrong, ip(fmt.Sprintf("2001:db8:%x::1", i+1)))); e != nil && e.Code == "invalid_code" {
			judged.Add(1)
		}
	})
	if judged.Load() > 10 {
		t.Fatalf("%d two-step guesses were judged, the limit is 10", judged.Load())
	}
}

// ---- M4: sessions end with two-step changes -------------------------------------------------------

func sessionAlive(env *authtest.Env, r auth.LoginResult) bool {
	_, err := env.Svc.Sessions.Authenticate(reqWith(r, "GET", ""))
	return err == nil
}

func TestM4EnablingDisablingAndResettingTwoStepEndSessions(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	s1, _ := env.Login(t, u.Email, "")
	s2, _ := env.Login(t, u.Email, "")

	// Turning two-step on by email: the current session stays, the other ends.
	if _, err := env.Svc.StartEmail2FA(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := env.Svc.ConfirmEmail2FA(ctx, u.ID, s1.Session.SessionID, env.Mailer.LastCode()); err != nil {
		t.Fatal(err)
	}
	if !sessionAlive(env, s1) || sessionAlive(env, s2) {
		t.Fatalf("after enabling: s1=%v s2=%v, want true false", sessionAlive(env, s1), sessionAlive(env, s2))
	}

	// Turning it off by the user: the other sessions end, the current one stays.
	env.Clock.Advance(2 * time.Minute)
	_, _ = env.Login(t, u.Email, "")
	s3, err := env.Login(t, u.Email, env.Mailer.LastCode())
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Svc.DisableTwoFA(ctx, u.ID, s1.Session.SessionID, authtest.Password); err != nil {
		t.Fatal(err)
	}
	if !sessionAlive(env, s1) || sessionAlive(env, s3) {
		t.Fatalf("after disabling: s1=%v s3=%v, want true false", sessionAlive(env, s1), sessionAlive(env, s3))
	}

	// Reset by an administrator ends every session of that user, the current one of the user included.
	secret := func() []byte { // app method this time
		setup, err := env.Svc.StartTOTP(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		k := decodeBase32(t, setup.Secret)
		if err := env.Svc.ConfirmTOTP(ctx, u.ID, s1.Session.SessionID, auth.TOTPCode(k, auth.TOTPStep(env.Clock.Now()))); err != nil {
			t.Fatal(err)
		}
		return k
	}()
	s4, err := env.Login(t, u.Email, auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())+1))
	if err != nil {
		t.Fatal(err)
	}
	if !sessionAlive(env, s1) || !sessionAlive(env, s4) {
		t.Fatal("setup of the reset case failed")
	}
	if err := env.Svc.ResetTwoFA(ctx, admin.ID, admin.Email, u.ID); err != nil {
		t.Fatal(err)
	}
	if sessionAlive(env, s1) || sessionAlive(env, s4) {
		t.Fatalf("after the reset: s1=%v s4=%v, want both ended", sessionAlive(env, s1), sessionAlive(env, s4))
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'user.2fa_reset' AND detail LIKE '%2 sessions ended'"); n != 1 {
		t.Fatalf("the reset audit row does not say how many sessions ended (%d rows)", n)
	}
	// Other users are untouched.
	o := env.User(t, "bob@acme.example", routes.Viewer)
	os1, _ := env.Login(t, o.Email, "")
	if !sessionAlive(env, os1) {
		t.Fatal("another user's session ended")
	}
}

// ---- M5: a login racing a reset ----------------------------------------------------------------

func TestM5LoginRacingAPasswordResetNeitherSignsInNorOverwritesTheNewHash(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 4 })
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	// An outdated hash makes the login want to rehash, the write that used to overwrite the reset.
	old, err := auth.Params{Memory: 32, Time: 1, Threads: 1}.Hash(authtest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := coredb.New(tx).UpdateUserPassword(t.Context(), coredb.UpdateUserPasswordParams{PasswordHash: old, ID: u.ID})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var temp string
	var fired atomic.Bool
	var armed atomic.Bool
	auth.SetHashProbe(env.Svc, func(d int) {
		// At the end of the login's password check, before its write transaction: an administrator resets
		// the password (this runs on the login's goroutine; the reset's own hashing is not intercepted).
		if d < 0 && armed.Load() && fired.CompareAndSwap(false, true) {
			var err error
			if temp, err = env.Svc.ResetPassword(t.Context(), admin.Email, u.ID); err != nil {
				t.Error(err)
			}
		}
	})
	armed.Store(true)
	_, err = env.Login(t, u.Email, "")
	armed.Store(false)
	wantAPI(t, err, 400, "invalid_credentials")
	if !fired.Load() || temp == "" {
		t.Fatal("the reset did not run between the check and the write")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_session WHERE user_id = ? AND revoked_at IS NULL", u.ID); n != 0 {
		t.Fatalf("the racing login left %d live sessions", n)
	}
	if _, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: temp, IP: ip("192.0.2.9")}); err != nil {
		t.Fatalf("the new password does not work: the rehash overwrote it (%v)", err)
	}
	wantAPI(t, loginAs(env, u.Email, authtest.Password, "", ip("192.0.2.9")), 400, "invalid_credentials")
}

func TestM5LoginRacingADisableDoesNotSignIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t, func(c *auth.Config) { c.MaxHashing = 4 })
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	var fired, armed atomic.Bool
	auth.SetHashProbe(env.Svc, func(d int) {
		if d < 0 && armed.Load() && fired.CompareAndSwap(false, true) {
			yes := true
			if _, err := env.Svc.UpdateUser(t.Context(), admin.ID, admin.Email, u.ID, auth.UserPatch{Disabled: &yes}); err != nil {
				t.Error(err)
			}
		}
	})
	armed.Store(true)
	_, err := env.Login(t, u.Email, "")
	armed.Store(false)
	wantAPI(t, err, 403, "disabled")
	if n := env.Count(t, "SELECT count(*) FROM core_session WHERE user_id = ? AND revoked_at IS NULL", u.ID); n != 0 {
		t.Fatalf("a disabled account got a session (%d)", n)
	}
}

// ---- L1: same work for known and unknown emails -----------------------------------------------

func TestL1KnownAndUnknownEmailsDoTheSameWork(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	env.User(t, "ann@acme.example", routes.Viewer)
	var runs atomic.Int32
	auth.SetHashProbe(env.Svc, func(d int) {
		if d > 0 {
			runs.Add(1)
		}
	})
	chain := func() int { return env.Count(t, "SELECT count FROM core_chain_head WHERE chain = 'core_audit'") }
	failedRows := func() int { return env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.login_failed'") }

	measure := func(email string) (argon, audit, chainSteps int) {
		r0, a0, c0 := int(runs.Load()), failedRows(), chain()
		wantAPI(t, loginAs(env, email, "wrong password here", "", ip("192.0.2.1")), 400, "invalid_credentials")
		return int(runs.Load()) - r0, failedRows() - a0, chain() - c0
	}
	ka, kf, kc := measure("ann@acme.example")
	ua, uf, uc := measure("nobody@acme.example")
	if ka != 1 || ua != 1 || kf != 1 || uf != 1 || kc != uc {
		t.Fatalf("known: argon2=%d audit=%d chain=%d; unknown: argon2=%d audit=%d chain=%d; want one argon2 run and one audit row each", ka, kf, kc, ua, uf, uc)
	}
	// The stranger's text is not stored: a hash stands for it, and the same address gives the same text.
	var target string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT target FROM core_audit WHERE action = 'auth.login_failed' AND detail = 'unknown email'").Scan(&target); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(target, "nobody") || !strings.HasPrefix(target, "unknown email ") {
		t.Fatalf("target = %q", target)
	}
	// The long and the empty password take the same path.
	r0 := runs.Load()
	wantAPI(t, loginAs(env, "nobody@acme.example", strings.Repeat("x", 100_000), "", ip("192.0.2.2")), 400, "invalid_credentials")
	if runs.Load()-r0 != 1 {
		t.Fatal("an over-long password skipped the argon2 run")
	}
}

// ---- L2: control characters in emails ----------------------------------------------------------

func TestL2EmailsWithControlCharactersAreRefused(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	hash, err := env.Svc.HashPassword(t.Context(), authtest.Password, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"a\x01b@acme.example", "ann\x7f@acme.example", "ann@acme\x00.example", "ann@acme.example\x1b[0m", "a\u0085b@acme.example", "ann\u0000@acme.example"} {
		err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := env.Svc.CreateUser(t.Context(), tx, "system", auth.NewUser{Name: "Ann", Email: email, Role: routes.Viewer, PasswordHash: hash})
			return err
		})
		wantAPI(t, err, 400, "invalid_email")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_user"); n != 0 {
		t.Fatalf("%d users were created", n)
	}
}

// ---- L3: two-step enabling races ---------------------------------------------------------------

func TestL3ConfirmingBothMethodsAtOnceTurnsOneOn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	ctx := t.Context()
	for i := range 15 {
		u := env.User(t, fmt.Sprintf("user%d@acme.example", i), routes.Viewer)
		setup, err := env.Svc.StartTOTP(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		secret := decodeBase32(t, setup.Secret)
		if _, err := env.Svc.StartEmail2FA(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		mailed, totp := env.Mailer.LastCode(), auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now()))
		errs := make([]error, 2)
		parallel(2, func(k int) {
			if k == 0 {
				errs[0] = env.Svc.ConfirmTOTP(ctx, u.ID, "", totp)
			} else {
				errs[1] = env.Svc.ConfirmEmail2FA(ctx, u.ID, "", mailed)
			}
		})
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else {
				wantAPI(t, err, 409, "already_on")
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d confirmations succeeded, want exactly 1 (%v)", i, ok, errs)
		}
		got, _ := env.Svc.GetUser(ctx, u.ID)
		confirmedKey := env.Count(t, "SELECT count(*) FROM core_user_totp WHERE user_id = ? AND confirmed = 1", u.ID)
		if (got.TwofaMethod == "app") != (confirmedKey == 1) {
			t.Fatalf("round %d: method %q with %d confirmed keys", i, got.TwofaMethod, confirmedKey)
		}
	}
}

func TestL3StartingWhileAnotherMethodIsAlreadyOnIsRefused(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	appUser(t, env)
	u := userByEmail(t, env, "ann@acme.example")
	wantAPI(t, func() error { _, err := env.Svc.StartTOTP(t.Context(), u.ID); return err }(), 409, "already_on")
	if n := env.Count(t, "SELECT count(*) FROM core_user_totp WHERE user_id = ? AND confirmed = 1", u.ID); n != 1 {
		t.Fatalf("confirmed key lost: %d", n)
	}
}

// ---- L4: concurrent duplicate users ------------------------------------------------------------

func TestL4ConcurrentCreatesOfOneEmailGiveOneAccountAndDuplicates(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	hash, err := env.Svc.HashPassword(t.Context(), authtest.Password, "")
	if err != nil {
		t.Fatal(err)
	}
	var created, dup atomic.Int32
	parallel(12, func(int) {
		err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := env.Svc.CreateUser(t.Context(), tx, "system", auth.NewUser{Name: "Ann", Email: "ann@acme.example", Role: routes.Viewer, PasswordHash: hash})
			return err
		})
		switch e, _ := apierr.As(err); {
		case err == nil:
			created.Add(1)
		case e != nil && e.Status == 409 && e.Code == "duplicate":
			dup.Add(1)
		default:
			t.Errorf("unexpected error: %v", err)
		}
	})
	if created.Load() != 1 || dup.Load() != 11 {
		t.Fatalf("created=%d duplicate=%d", created.Load(), dup.Load())
	}
}

// ---- L6: last_seen never queues requests behind the writer ----------------------------------

func TestL6BusyWriterDoesNotStallAuthentication(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	res, err := env.Login(t, u.Email, "")
	if err != nil {
		t.Fatal(err)
	}
	start := lastSeen(t, env, res.Session.SessionID)
	env.Clock.Advance(2 * time.Minute) // the refresh is due

	held, release := make(chan struct{}), make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- env.DB.Write(t.Context(), func(*sql.Tx) error { close(held); <-release; return nil })
	}()
	<-held
	done := make(chan error, 1)
	go func() { _, err := env.Svc.Sessions.Authenticate(reqWith(res, "GET", "")); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("authenticate with a busy writer: %v", err)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("Authenticate is stuck behind the writer")
	}
	if got := lastSeen(t, env, res.Session.SessionID); got != start {
		t.Fatalf("last_seen changed while the writer was held")
	}
	close(release)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	// The refresh was not lost: it finishes once the writer is free.
	deadline := time.Now().Add(3 * time.Second)
	for lastSeen(t, env, res.Session.SessionID) == start {
		if time.Now().After(deadline) {
			t.Fatal("last_seen was never refreshed after the writer became free")
		}
		<-time.After(10 * time.Millisecond)
	}
}

// ---- INFO: HMAC email codes, temp password alphabet --------------------------------------------

func TestEmailCodesAreStoredAsAKeyedHash(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	if _, err := env.Login(t, u.Email, ""); err == nil { // sends a code
		t.Fatal("expected twofa_required")
	}
	code := env.Mailer.LastCode()
	var stored string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT code_hash FROM core_email_code WHERE user_id = ?", u.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	plain := sha256.Sum256([]byte(code))
	if stored == hex.EncodeToString(plain[:]) {
		t.Fatal("the stored code hash is a plain SHA-256: a leaked database gives the code back by table lookup")
	}
	var id string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT id FROM core_secret WHERE purpose = 'core_email_code.hmac_key'").Scan(&id); err != nil {
		t.Fatalf("no key in core_secret: %v", err)
	}
	key, err := env.Secrets.Open(t.Context(), env.DB.Reader(), id, "core_email_code.hmac_key")
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(u.ID + "\x00" + code))
	if want := hex.EncodeToString(m.Sum(nil)); stored != want {
		t.Fatalf("code_hash = %s, want HMAC-SHA-256(key, user id, code) = %s", stored, want)
	}
	// A second service on the same database (a restart) uses the same key and accepts the code.
	svc2, err := auth.New(auth.Config{DB: env.DB, Secrets: env.Secrets, Audit: env.Audit, Mailer: env.Mailer, Clock: env.Clock.Now, Log: slog.New(slog.DiscardHandler), Argon2: authtest.Cheap})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.Codes.Verify(t.Context(), u.ID, code); err != nil {
		t.Fatalf("a restarted service rejects the code: %v", err)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_secret WHERE purpose = 'core_email_code.hmac_key'"); n != 1 {
		t.Fatalf("%d keys", n)
	}
}

func TestTempPasswordAlphabet(t *testing.T) {
	t.Parallel()
	if len(auth.TempAlphabet) != 55 {
		t.Fatalf("alphabet has %d characters; the comment in password.go says 55", len(auth.TempAlphabet))
	}
	seen := map[rune]bool{}
	for _, r := range auth.TempAlphabet {
		if seen[r] || strings.ContainsRune("01OIloi", r) || !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			t.Fatalf("bad or repeated character %q", r)
		}
		seen[r] = true
	}
	p, err := auth.NewTempPassword()
	if err != nil || len(p) != 20 || strings.Trim(p, auth.TempAlphabet) != "" {
		t.Fatalf("password %q, %v", p, err)
	}
}
