package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

func loginWith(env *authtest.Env, email, password, device string, addr string) (auth.LoginResult, error) {
	return env.Svc.Login(context.Background(), auth.LoginRequest{Email: email, Password: password, IP: ip(addr), UserAgent: "test", DeviceCookie: device})
}

// signInForCookie signs ann in once and returns her device cookie value.
func signInForCookie(t *testing.T, env *authtest.Env, email string) string {
	t.Helper()
	res, err := loginWith(env, email, authtest.Password, "", "2001:db8:0:1::1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Device == "" {
		t.Fatal("no device cookie after a successful sign-in")
	}
	return res.Device
}

// D-77: the cookie is HttpOnly, Secure, SameSite=Strict, scoped to the sign-in endpoints, and ninety days long.
func TestDeviceCookieAttributes(t *testing.T) {
	t.Parallel()
	c := auth.DeviceCookie("v")
	if c.Name != "__Secure-vedette_device" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/v1/auth/" || c.Domain != "" {
		t.Fatalf("device cookie = %+v", c)
	}
	if time.Duration(c.MaxAge)*time.Second != auth.DeviceLifetime {
		t.Fatalf("MaxAge = %d", c.MaxAge)
	}
}

// D-77: an insider in the same /64 who guesses 100 times blocks the /64 key of admin@ for everyone without a
// cookie, but not the real owner, who presents a device cookie from an earlier sign-in.
func TestDeviceCookieHolderIsNotLockedOutByTheInsiderOfTheSame64(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "admin@acme.example", routes.Admin)
	cookie := signInForCookie(t, env, u.Email)

	for i := range 100 { // the insider rotates addresses inside the /64
		wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", "", fmt.Sprintf("2001:db8:0:1::%x", i+0x100))), 400, "invalid_credentials")
	}
	// The /64 is blocked for a sign-in without the cookie, even with the right password.
	wantAPI(t, mustErr(loginWith(env, u.Email, authtest.Password, "", "2001:db8:0:1::2")), 429, "rate_limited")
	// The owner, with the cookie, signs in from the very same /64, and gets the cookie again.
	res, err := loginWith(env, u.Email, authtest.Password, cookie, "2001:db8:0:1::2")
	if err != nil {
		t.Fatalf("the owner with a device cookie was locked out: %v", err)
	}
	if res.Device == "" {
		t.Fatal("no cookie re-issued")
	}
	// And the insider's failures did not grow on the owner's behalf: a wrong password with the cookie is
	// counted on the cookie, not on the /64 (which stays where the insider left it).
	wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, "2001:db8:0:1::2")), 400, "invalid_credentials")
}

func mustErr(_ auth.LoginResult, err error) error { return err }

// D-77: a stolen cookie brute-forces from anywhere, but only ten tries per window per cookie; the address
// does not matter (a new address gives no new budget) and the address counters stay untouched.
func TestStolenDeviceCookieBruteForceIsStillLimited(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "admin@acme.example", routes.Admin)
	cookie := signInForCookie(t, env, u.Email)
	for i := range 10 {
		wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, fmt.Sprintf("198.51.100.%d", i+1))), 400, "invalid_credentials")
	}
	// The 11th try from yet another address is refused before any password work, and so is the right password.
	e := apiErr(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, "203.0.113.9")), 429, "rate_limited")
	if e.Extra["retry_after"] == nil {
		t.Fatal("no retry_after")
	}
	wantAPI(t, mustErr(loginWith(env, u.Email, authtest.Password, cookie, "203.0.113.10")), 429, "rate_limited")
	// The thief's addresses were never counted: without the cookie they are clean clients.
	if _, err := loginWith(env, u.Email, authtest.Password, "", "198.51.100.1"); err != nil {
		t.Fatalf("the address counters moved for cookie attempts: %v", err)
	}
	// After the wait the cookie works again.
	env.Clock.Advance(11 * time.Minute)
	if _, err := loginWith(env, u.Email, authtest.Password, cookie, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
}

// D-77: a missing, malformed, tampered, expired or other-user cookie is no exemption: the address limit applies.
func TestInvalidDeviceCookiesGetNoExemption(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "admin@acme.example", routes.Admin)
	other := env.User(t, "bob@acme.example", routes.Viewer)
	good := signInForCookie(t, env, u.Email)
	bobs := signInForCookie(t, env, other.Email)
	val, mac, _ := strings.Cut(good, ".")
	tampered := val + "." + strings.Repeat("A", len(mac))
	flipped := val[:len(val)-1] + string(rune('A'+(val[len(val)-1]-'A'+1)%26)) + "." + mac

	for name, cookie := range map[string]string{"empty": "", "garbage": "not-a-cookie", "no dot": val, "tampered mac": tampered, "tampered payload": flipped, "another user's": bobs} {
		t.Run(name, func(t *testing.T) {
			addr := fmt.Sprintf("192.0.2.%d", 10+len(name)) // a fresh IPv4 client per case
			for range 10 {
				wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, addr)), 400, "invalid_credentials")
			}
			wantAPI(t, mustErr(loginWith(env, u.Email, authtest.Password, cookie, addr)), 429, "rate_limited")
		})
	}
	t.Run("expired", func(t *testing.T) {
		env.Clock.Advance(auth.DeviceLifetime + time.Hour)
		for range 10 {
			wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", good, "192.0.2.99")), 400, "invalid_credentials")
		}
		wantAPI(t, mustErr(loginWith(env, u.Email, authtest.Password, good, "192.0.2.99")), 429, "rate_limited")
	})
}

// D-77: a password change or reset kills every device cookie of the account (cred_version is in the signed value).
func TestDeviceCookieDiesWithThePassword(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	admin := env.User(t, "root@acme.example", routes.Admin)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	cookie := signInForCookie(t, env, u.Email)
	if _, err := env.Svc.ResetPassword(t.Context(), admin.ID, admin.Email, "", u.ID); err != nil {
		t.Fatal(err)
	}
	addr := "192.0.2.77"
	for range 10 {
		wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, addr)), 400, "invalid_credentials")
	}
	wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", cookie, addr)), 429, "rate_limited")
}

// D-77: a cookie of the account is presented to the resend-code endpoint the same way.
func TestResendCodeHonoursTheDeviceCookie(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	// Sign in to get a cookie: email two-step needs the code.
	_, err := loginWith(env, u.Email, authtest.Password, "", "2001:db8:0:1::1")
	wantAPI(t, err, 401, "twofa_required")
	res, err := env.Svc.Login(t.Context(), auth.LoginRequest{Email: u.Email, Password: authtest.Password, Code: env.Mailer.LastCode(), IP: ip("2001:db8:0:1::1")})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", "", fmt.Sprintf("2001:db8:0:1::%x", i+0x100))), 400, "invalid_credentials")
	}
	// Without the cookie the /64 limiter refuses before anything else; with it the request gets past it.
	_, err = env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, ip("2001:db8:0:1::2"), "")
	wantAPI(t, err, 429, "rate_limited")
	if _, err := env.Svc.ResendCode(t.Context(), u.Email, authtest.Password, ip("2001:db8:0:1::2"), res.Device); err != nil {
		t.Fatalf("resend with the device cookie: %v", err)
	}
}

// D-75 (amended after the security review of WP-04b part 2): wrong setup codes are counted per client
// address like a sign-in, so one guesser cannot keep setup closed for the owner at another address; a right
// code gives its count back.
func TestSetupAttemptsAreBoundedPerClient(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	attacker, owner := ip("198.51.100.66"), ip("192.0.2.5")
	for range 10 {
		if _, err := env.Svc.BeginSetupAttempt(attacker); err != nil {
			t.Fatal(err)
		}
	}
	_, err := env.Svc.BeginSetupAttempt(attacker)
	wantAPI(t, err, 429, "rate_limited")
	if _, err := env.Svc.BeginSetupAttempt(owner); err != nil {
		t.Fatalf("a guesser at another address locked the owner out: %v", err)
	}

	env2 := authtest.New(t)
	for range 9 {
		if _, err := env2.Svc.BeginSetupAttempt(owner); err != nil {
			t.Fatal(err)
		}
	}
	refund, err := env2.Svc.BeginSetupAttempt(owner)
	if err != nil {
		t.Fatal(err)
	}
	refund() // the tenth was right
	if _, err := env2.Svc.BeginSetupAttempt(owner); err != nil {
		t.Fatalf("a refunded attempt still counted: %v", err)
	}
}

// D-75: an IPv6 client is counted per address and per /64 (the same keys as sign-in), so rotating inside
// a /64 does not give a fresh budget forever.
func TestSetupAttemptsOfOneIPv6PrefixShareABudget(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	for i := range 100 {
		if _, err := env.Svc.BeginSetupAttempt(ip(fmt.Sprintf("2001:db8:0:1::%x", i+1))); err != nil {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	_, err := env.Svc.BeginSetupAttempt(ip("2001:db8:0:1::ffff"))
	wantAPI(t, err, 429, "rate_limited")
	if _, err := env.Svc.BeginSetupAttempt(ip("2001:db8:0:2::1")); err != nil {
		t.Fatalf("another /64 was refused: %v", err)
	}
}

// D-75 (amended after review 2): there is no box-wide ceiling on setup guesses, because it is itself the
// lever that locks the owner out. One stranger with ten IPv6 /64s (a hundred fresh addresses in each: no
// address reaches its own limit of 10, each /64 reaches exactly 100) and 1000 IPv4 addresses never stops
// the owner, from an address never seen before, at any time.
func TestSetupAttemptsHaveNoBoxWideCeiling(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	for n := range 10 {
		for host := range 100 {
			a := ip(fmt.Sprintf("2001:db8:0:%x::%x", 0x100+n, host+1))
			if _, err := env.Svc.BeginSetupAttempt(a); err != nil {
				t.Fatalf("stranger guess %d from %s: %v", n*100+host, a, err)
			}
		}
	}
	for i := range 1100 {
		a := ip(fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256))
		if _, err := env.Svc.BeginSetupAttempt(a); err != nil {
			t.Fatalf("IPv4 stranger guess %d: %v", i, err)
		}
	}
	if _, err := env.Svc.BeginSetupAttempt(ip("192.0.2.50")); err != nil { // the owner, never seen before
		t.Fatalf("the owner after 2100 stranger guesses: %v", err)
	}
	if _, err := env.Svc.BeginSetupAttempt(netip.Addr{}); err == nil {
		t.Fatal("an invalid address was accepted")
	}
}

// An IPv4-mapped IPv6 peer shares the bucket of its IPv4 address.
func TestSetupMappedAddressSharesTheIPv4Bucket(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	for range 10 {
		if _, err := env.Svc.BeginSetupAttempt(ip("::ffff:192.0.2.9")); err != nil {
			t.Fatal(err)
		}
	}
	_, err := env.Svc.BeginSetupAttempt(ip("192.0.2.9"))
	wantAPI(t, err, 429, "rate_limited")
}

// OWASP's device-cookie scheme issues a new cookie on every successful sign-in. Re-signing the presented
// cookie with its own nonce (what the box did before) let a copy stolen once share the owner's counter for as
// long as it lived: the thief could keep the owner's trusted browser at 429 even after the owner had signed
// in again since the theft.
func TestDeviceCookieNonceIsNewOnEverySignIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "admin@acme.example", routes.Admin)
	stolen := signInForCookie(t, env, u.Email) // the thief copies this one

	// The owner signs in again with that cookie and gets a new one.
	res, err := loginWith(env, u.Email, authtest.Password, stolen, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	current := res.Device
	if current == stolen {
		t.Fatal("the cookie was re-issued unchanged")
	}

	// The thief burns the stolen copy's budget from anywhere.
	for i := range 10 {
		wantAPI(t, mustErr(loginWith(env, u.Email, "wrong password here", stolen, fmt.Sprintf("198.51.100.%d", i+1))), 400, "invalid_credentials")
	}
	// The owner's current cookie is not locked by the stale copy.
	if _, err := loginWith(env, u.Email, authtest.Password, current, "192.0.2.10"); err != nil {
		t.Fatalf("the owner's re-issued device cookie is locked by a copy stolen before the re-sign-in: %v", err)
	}
}
