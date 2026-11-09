package auth_test

import (
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
)

const purpose = "response.approve"

func nextCode(env *authtest.Env, secret []byte, ahead int64) string {
	return auth.TOTPCode(secret, auth.TOTPStep(env.Clock.Now())+ahead)
}

// wrongCode is a code that is not valid at any step the check accepts now.
func wrongCode(env *authtest.Env, secret []byte) string {
	for n := 0; ; n++ {
		c := strings.Repeat(string(rune('0'+n%10)), 6)
		if c != nextCode(env, secret, -1) && c != nextCode(env, secret, 0) && c != nextCode(env, secret, 1) {
			return c
		}
	}
}

func TestStepUpTOTPRefusesTheCodeThatSignedIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	u, err := env.Svc.GetUser(t.Context(), annID(t, env))
	if err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(auth.TOTPPeriod * time.Second)
	signIn := nextCode(env, secret, 0)
	if _, err := env.Login(t, u.Email, signIn); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, signIn, purpose)
	wantAPI(t, err, 400, "invalid_code")

	// A code of the next step is accepted, once.
	next := nextCode(env, secret, 1)
	su, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, next, purpose)
	if err != nil || su.Method != "app" {
		t.Fatalf("next-step code: %+v, %v", su, err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, next, purpose)
	wantAPI(t, err, 400, "invalid_code")
	// The step is shared with sign-in: the used step-up code cannot sign in either.
	_, err = env.Login(t, u.Email, next)
	wantAPI(t, err, 400, "invalid_code")
}

// annID is the id of ann@acme.example, the user of appUser.
func annID(t *testing.T, env *authtest.Env) string {
	t.Helper()
	var id string
	if err := env.DB.Reader().QueryRowContext(t.Context(), "SELECT id FROM core_user WHERE email = 'ann@acme.example'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStepUpTOTPSameCodeTwiceAndNoCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	// No code: 400 code_required with the method, nothing counted.
	su, err := env.Svc.VerifyTwoStep(t.Context(), id, "", purpose)
	e := apiErr(t, err, 400, "code_required")
	if e.Extra["method"] != "app" || su.Method != "app" {
		t.Fatalf("extra = %v, result = %+v", e.Extra, su)
	}
	c := nextCode(env, secret, 1)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, " "+c[:3]+" "+c[3:], purpose); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, c, purpose)
	wantAPI(t, err, 400, "invalid_code")
	// An earlier step than the accepted one is refused too.
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 0), purpose)
	wantAPI(t, err, 400, "invalid_code")
}

func TestStepUpConcurrentUseOfOneTOTPCodePassesOnce(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	code := nextCode(env, secret, 1)
	var mu sync.Mutex
	ok := 0
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if _, err := env.Svc.VerifyTwoStep(t.Context(), id, code, purpose); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent step-ups with one code passed, want 1", ok)
	}
}

func TestStepUpWithoutTwoStepIsTwofaRequired(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := env.User(t, "ann@acme.example", routes.Viewer)
	for _, code := range []string{"", "123456"} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose)
		wantAPI(t, err, 403, "twofa_required")
	}
}

func TestStepUpDisabledAndUnknownUsersLookLikeAWrongCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	_, errWrong := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose)
	wantAPI(t, errWrong, 400, "invalid_code")

	if err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_user SET disabled = 1 WHERE id = ?", id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, errOff := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose) // a right code
	_, errUnknown := env.Svc.VerifyTwoStep(t.Context(), "no-such-user", nextCode(env, secret, 1), purpose)
	for _, err := range []error{errOff, errUnknown} {
		e := apiErr(t, err, 400, "invalid_code")
		if e.Message != apiErr(t, errWrong, 400, "invalid_code").Message {
			t.Fatalf("message %q differs from a wrong code's", e.Message)
		}
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup'"); n != 0 {
		t.Fatalf("%d auth.stepup rows for refused calls", n)
	}
}

func TestStepUpRefusesAnInvalidPurpose(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	for _, p := range []string{"", "Response", "1abc", "a b", "a;b", "x'--", "response/approve", "é", strings.Repeat("a", 65), "a\n"} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), p)
		wantAPI(t, err, 400, "invalid")
	}
	// Nothing was used up: the code still passes with a good purpose.
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestStepUpEmail(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	before := len(env.Mailer.Sent())

	su, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose)
	e := apiErr(t, err, 400, "code_required")
	if su.Method != "email" || su.SentTo != "a•••@acme.example" || su.ResendAfter != 60 || e.Extra["sent_to"] != su.SentTo || e.Extra["resend_after"] != 60 {
		t.Fatalf("result = %+v, extra = %v", su, e.Extra)
	}
	if len(env.Mailer.Sent()) != before+1 {
		t.Fatalf("%d mails, want exactly one", len(env.Mailer.Sent())-before)
	}
	code := env.Mailer.LastCode()
	if contains(jsonOf(t, e), code) {
		t.Fatalf("the code reached the error: %s", jsonOf(t, e))
	}

	// Asking again before resend_after is refused like at sign-in, and mails nothing.
	env.Clock.Advance(20 * time.Second)
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose)
	if e := apiErr(t, err, 429, "resend_too_soon"); e.Extra["retry_after"] != 40 {
		t.Fatalf("extra = %v", e.Extra)
	}
	if len(env.Mailer.Sent()) != before+1 {
		t.Fatal("a second mail was sent inside the resend gap")
	}

	// A code for another purpose is refused; the right one passes once.
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, "response.other")
	wantAPI(t, err, 400, "wrong_code")
	su, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose)
	if err != nil || su.Method != "email" {
		t.Fatalf("right code: %+v, %v", su, err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose)
	wantAPI(t, err, 400, "no_code")
}

func TestStepUpEmailCodeAndSignInCodeAreNotInterchangeable(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")

	// A step-up code does not sign in, and the failed sign-in does not use it up.
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose)
	wantAPI(t, err, 400, "code_required")
	stepCode := env.Mailer.LastCode()
	_, err = env.Login(t, u.Email, stepCode)
	wantAPI(t, err, 400, "wrong_code")
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions from a step-up code", n)
	}
	if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, stepCode, purpose); err != nil {
		t.Fatalf("step-up code after a failed sign-in: %v", err)
	}

	// A sign-in code does not pass step-up, and the failed step-up does not use it up.
	env.Clock.Advance(2 * time.Minute)
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	loginCode := env.Mailer.LastCode()
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, loginCode, purpose)
	wantAPI(t, err, 400, "wrong_code")
	if _, err := env.Login(t, u.Email, loginCode); err != nil {
		t.Fatalf("sign-in code after a failed step-up: %v", err)
	}
}

func TestStepUpEmailUnavailable(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	env.Mailer.SetAvailable(false)
	for _, code := range []string{"", "123456"} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose)
		wantAPI(t, err, 503, "twofa_email_unavailable")
	}
	env.Mailer.SetAvailable(true)
	env.Mailer.FailSend(true)
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose)
	wantAPI(t, err, 503, "twofa_email_unavailable")
	// The failed send did not use up the resend gap.
	env.Mailer.FailSend(false)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose); err == nil {
		t.Fatal("want code_required")
	}
	if got := len(env.Mailer.Sent()); got != 2 { // the enrolment code and this one
		t.Fatalf("%d mails", got)
	}
}

func TestStepUpMissingMailerIsUnavailable(t *testing.T) {
	t.Parallel()
	// A box whose mailer was never wired (nil Mailer).
	env := authtest.New(t, func(c *auth.Config) { c.Mailer = nil })
	u := env.User(t, "ann@acme.example", routes.Viewer)
	if err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_user SET twofa_method = 'email' WHERE id = ?", u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose)
	wantAPI(t, err, 503, "twofa_email_unavailable")
}

func TestStepUpWrongGuessesShareTheSignInLimiter(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	for range 10 {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose)
		wantAPI(t, err, 400, "invalid_code")
	}
	_, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose) // even a right code
	if e := apiErr(t, err, 429, "rate_limited"); e.Extra["retry_after"] == nil {
		t.Fatalf("extra = %v", e.Extra)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, "", purpose)
	wantAPI(t, err, 429, "rate_limited")
	// Sign-in is blocked by the same counter.
	_, err = env.Login(t, "ann@acme.example", nextCode(env, secret, 1))
	wantAPI(t, err, 429, "rate_limited")
}

func TestStepUpParallelWrongGuessesAreBoundedByTheLimiter(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	const n = 60
	var mu sync.Mutex
	judged, limited := 0, 0
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose)
			mu.Lock()
			defer mu.Unlock()
			if e, ok := apierr.As(err); ok && e.Code == "invalid_code" {
				judged++
			} else if ok && e.Code == "rate_limited" {
				limited++
			}
		})
	}
	wg.Wait()
	if judged != 10 || limited != n-10 {
		t.Fatalf("judged = %d, limited = %d of %d parallel guesses, want 10 and %d", judged, limited, n, n-10)
	}
}

func TestStepUpAuditCarriesPurposeAndNoCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	good, bad := nextCode(env, secret, 1), wrongCode(env, secret)
	_, _ = env.Svc.VerifyTwoStep(t.Context(), id, bad, purpose)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, good, purpose); err != nil {
		t.Fatal(err)
	}
	bob := emailUser(t, env, "bob@acme.example")
	_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, "", "response.approve")
	mailed := env.Mailer.LastCode()
	_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, "000000", "response.approve")
	if mailed != "000000" {
		_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, mailed, "response.approve")
	}

	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup' AND detail LIKE 'purpose=response.approve method=app%'"); n != 1 {
		t.Fatalf("%d auth.stepup rows for the app user, want 1", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup' AND detail LIKE 'purpose=response.approve method=email%'"); n != 1 {
		t.Fatalf("%d auth.stepup rows for the email user, want 1", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup_failed' AND detail LIKE 'purpose=response.approve method=%'"); n != 2 {
		t.Fatalf("%d auth.stepup_failed rows, want 2", n)
	}
	rows, err := env.DB.Reader().QueryContext(t.Context(), "SELECT user || '|' || action || '|' || target || '|' || coalesce(detail, '') FROM core_audit")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	banned := []string{good, bad, mailed, auth.SecretBase32(secret), string(secret)}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(line, b) && !strings.Contains(line, "auth.login") { // a code could appear by chance in a hash, never in a step-up row
				t.Fatalf("audit row %q contains %q", line, b)
			}
		}
	}
	if logs := env.Logs.String(); contains(logs, good) || contains(logs, mailed) || contains(logs, bad) {
		t.Fatalf("a code reached the log: %s", logs)
	}
}

func TestStepUpHasNoSudoWindow(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose); err != nil {
		t.Fatal(err)
	}
	// Right after a pass an empty code asks again, and so does another purpose.
	_, err := env.Svc.VerifyTwoStep(t.Context(), id, "", purpose)
	wantAPI(t, err, 400, "code_required")
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, "", "response.other")
	wantAPI(t, err, 400, "code_required")
}
