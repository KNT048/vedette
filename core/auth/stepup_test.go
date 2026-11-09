package auth_test

import (
	"context"
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

const (
	purpose = "response.approve"
	summary = "Approve: Block 203.0.113.5 on Firewall A (high risk, AI request)"
)

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
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, signIn, purpose, summary)
	wantAPI(t, err, 400, "invalid_code")

	// A code of the next step is accepted, once.
	next := nextCode(env, secret, 1)
	su, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, next, purpose, summary)
	if err != nil || su.Method != "app" {
		t.Fatalf("next-step code: %+v, %v", su, err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, next, purpose, summary)
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
	su, err := env.Svc.VerifyTwoStep(t.Context(), id, "", purpose, summary)
	e := apiErr(t, err, 400, "code_required")
	if e.Extra["method"] != "app" || su.Method != "app" {
		t.Fatalf("extra = %v, result = %+v", e.Extra, su)
	}
	c := nextCode(env, secret, 1)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, " "+c[:3]+" "+c[3:], purpose, summary); err != nil {
		t.Fatal(err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, c, purpose, summary)
	wantAPI(t, err, 400, "invalid_code")
	// An earlier step than the accepted one is refused too.
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 0), purpose, summary)
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
			if _, err := env.Svc.VerifyTwoStep(t.Context(), id, code, purpose, summary); err == nil {
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
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
		wantAPI(t, err, 403, "twofa_required")
	}
}

func TestStepUpDisabledAndUnknownUsersLookLikeAWrongCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	_, errWrong := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose, summary)
	wantAPI(t, errWrong, 400, "invalid_code")

	if err := env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_user SET disabled = 1 WHERE id = ?", id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, errOff := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose, summary) // a right code
	_, errUnknown := env.Svc.VerifyTwoStep(t.Context(), "no-such-user", nextCode(env, secret, 1), purpose, summary)
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
	for _, p := range []string{"", "Response", "1abc", "a b", "a;b", "x'--", "response/approve", "é", strings.Repeat("a", 129), "a\n", "-a", "A-b"} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), p, summary)
		wantAPI(t, err, 400, "invalid")
	}
	// Nothing was used up: the code still passes with a good purpose.
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), "r-"+strings.Repeat("a", 126), summary); err != nil {
		t.Fatal(err)
	}
}

func TestStepUpEmail(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	before := len(env.Mailer.Sent())

	su, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
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
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	if e := apiErr(t, err, 429, "resend_too_soon"); e.Extra["retry_after"] != 40 {
		t.Fatalf("extra = %v", e.Extra)
	}
	if len(env.Mailer.Sent()) != before+1 {
		t.Fatal("a second mail was sent inside the resend gap")
	}

	// A code for another purpose is refused; the right one passes once.
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, "response.other", summary)
	wantAPI(t, err, 400, "wrong_code")
	su, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
	if err != nil || su.Method != "email" {
		t.Fatalf("right code: %+v, %v", su, err)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
	wantAPI(t, err, 400, "no_code")
}

func TestStepUpEmailCodeAndSignInCodeAreNotInterchangeable(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")

	// A step-up code does not sign in, and the failed sign-in does not use it up.
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 400, "code_required")
	stepCode := env.Mailer.LastCode()
	_, err = env.Login(t, u.Email, stepCode)
	wantAPI(t, err, 400, "wrong_code")
	if n := env.Count(t, "SELECT count(*) FROM core_session"); n != 0 {
		t.Fatalf("%d sessions from a step-up code", n)
	}
	if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, stepCode, purpose, summary); err != nil {
		t.Fatalf("step-up code after a failed sign-in: %v", err)
	}

	// A sign-in code does not pass step-up, and the failed step-up does not use it up.
	env.Clock.Advance(2 * time.Minute)
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	loginCode := env.Mailer.LastCode()
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, loginCode, purpose, summary)
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
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
		wantAPI(t, err, 503, "twofa_email_unavailable")
	}
	env.Mailer.SetAvailable(true)
	env.Mailer.FailSend(true)
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 503, "twofa_email_unavailable")
	// The failed send did not use up the resend gap.
	env.Mailer.FailSend(false)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary); err == nil {
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
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 503, "twofa_email_unavailable")
}

func TestStepUpWrongGuessesShareTheSignInLimiter(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	for range 10 {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose, summary)
		wantAPI(t, err, 400, "invalid_code")
	}
	_, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose, summary) // even a right code
	if e := apiErr(t, err, 429, "rate_limited"); e.Extra["retry_after"] == nil {
		t.Fatalf("extra = %v", e.Extra)
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, "", purpose, summary)
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
			_, err := env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose, summary)
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
	_, _ = env.Svc.VerifyTwoStep(t.Context(), id, bad, purpose, summary)
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, good, purpose, summary); err != nil {
		t.Fatal(err)
	}
	bob := emailUser(t, env, "bob@acme.example")
	_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, "", "response.approve", summary)
	mailed := env.Mailer.LastCode()
	_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, "000000", "response.approve", summary)
	if mailed != "000000" {
		_, _ = env.Svc.VerifyTwoStep(t.Context(), bob.ID, mailed, "response.approve", summary)
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
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose, summary); err != nil {
		t.Fatal(err)
	}
	// Right after a pass an empty code asks again, and so does another purpose.
	_, err := env.Svc.VerifyTwoStep(t.Context(), id, "", purpose, summary)
	wantAPI(t, err, 400, "code_required")
	_, err = env.Svc.VerifyTwoStep(t.Context(), id, "", "response.other", summary)
	wantAPI(t, err, 400, "code_required")
}

// hookMailer is the fake mailer with a hook that runs once inside Available: VerifyTwoStep's email path asks
// Available after it read the user and before the code is judged, which is where a concurrent admin write
// can land in production (the reader query is done, the verify transaction waits for the single writer).
type hookMailer struct {
	*authtest.Mailer
	mu   sync.Mutex
	hook func()
}

func (h *hookMailer) Available(ctx context.Context) bool {
	h.mu.Lock()
	f := h.hook
	h.hook = nil
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.Mailer.Available(ctx)
}

func (h *hookMailer) arm(f func()) { h.mu.Lock(); h.hook = f; h.mu.Unlock() }

// emailUserWith enrols an email-method user through the given mailer (emailUser reads env.Mailer).
func emailUserWith(t *testing.T, env *authtest.Env, m *authtest.Mailer, email string) auth.User {
	t.Helper()
	u := env.User(t, email, routes.Operator)
	if _, err := env.Svc.StartEmail2FA(t.Context(), u.ID, "", authtest.Password); err != nil {
		t.Fatal(err)
	}
	if err := only(env.Svc.ConfirmEmail2FA(t.Context(), u.ID, "", m.LastCode())); err != nil {
		t.Fatal(err)
	}
	env.Clock.Advance(2 * time.Minute)
	return u
}

func exec(t *testing.T, env *authtest.Env, q string, args ...any) {
	t.Helper()
	if err := env.DB.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		t.Error(err)
	}
}

// M1: the email path re-reads the user in the transaction that writes auth.stepup. A disable (or an admin password
// reset) that commits after VerifyTwoStep read the user but before the code is judged does not win: the
// step-up passes, auth.stepup is written for a disabled account, and the caller (response 13b-9) gets nil
// and approves. The app path re-reads the user in the AdvanceTotpStep transaction and refuses
// ("account changed"); the email path should do the same inside the verify transaction.
func TestStepUpEmailRefusesAUserDisabledOrResetDuringTheCheck(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, change string }{
		{"disabled", "UPDATE core_user SET disabled = 1 WHERE id = ?"},
		{"password reset by an admin", "UPDATE core_user SET cred_version = cred_version + 1 WHERE id = ?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &authtest.Mailer{}
			m.SetAvailable(true)
			hm := &hookMailer{Mailer: m}
			env := authtest.New(t, func(c *auth.Config) { c.Mailer = hm })
			u := emailUserWith(t, env, m, "ann@acme.example")
			_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
			wantAPI(t, err, 400, "code_required")
			code := m.LastCode()

			hm.arm(func() { exec(t, env, tc.change, u.ID) })
			_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
			if err == nil {
				t.Fatalf("step-up passed although the account changed (%s) before the code was judged", tc.name)
			}
			if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup'"); n != 0 {
				t.Fatalf("%d auth.stepup rows for an account changed mid-check", n)
			}
		})
	}
}

// DEFECT (Medium): step-up sends share the per-user budget of 5 mailed codes an hour with sign-in. Anyone
// holding a session of an email-method user (the very threat a step-up exists for) can keep that budget
// full with "approve, no code" calls, five an hour, and the owner can then not get a sign-in code at all
// (429 too_many_codes), so cannot sign in elsewhere to end the stolen session. Before 13b-3 only someone who
// knew the password could spend the budget (ResendCode). A step-up send should not consume sign-in sends.
func TestStepUpEmailSendsDoNotUseUpTheSignInBudget(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	env.Clock.Advance(time.Hour) // the enrolment send is out of the hour
	for i := range auth.MaxSendsPerHour {
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
		if e, ok := apierr.As(err); !ok || e.Code != "code_required" {
			t.Fatalf("step-up send %d: %v", i+1, err)
		}
		env.Clock.Advance(61 * time.Second)
	}
	_, err := env.Login(t, u.Email, "")
	if e, ok := apierr.As(err); !ok || e.Code != "twofa_required" {
		t.Fatalf("after %d step-up sends the owner's sign-in got %v, want 401 twofa_required with a fresh code", auth.MaxSendsPerHour, err)
	}
}

// L4 (documentation of what happens): a disabled email-method user gets the generic 400 invalid_code, not the
// wrong_code of a live user. That is no oracle: userID comes from the caller's own session.
func TestStepUpDisabledEmailUserIsInvalidCodeNotWrongCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 400, "code_required")
	wrong := "000000"
	if env.Mailer.LastCode() == wrong {
		wrong = "111111"
	}
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, wrong, purpose, summary)
	wantAPI(t, err, 400, "wrong_code")

	exec(t, env, "UPDATE core_user SET disabled = 1 WHERE id = ?", u.ID)
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, wrong, purpose, summary)
	wantAPI(t, err, 400, "invalid_code")
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 400, "invalid_code")
	if n := env.Count(t, "SELECT count(*) FROM core_email_code_send WHERE kind = 'stepup'"); n != 1 {
		t.Fatalf("%d step-up sends, a disabled user must not get a mail", n)
	}
}

// one bound for two-step guesses across sign-in and step-up together, under concurrency.
func TestStepUpParallelSignInAndStepUpGuessesShareOneBound(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	const n = 30
	var mu sync.Mutex
	judged := 0
	var wg sync.WaitGroup
	for i := range 2 * n {
		wg.Go(func() {
			var err error
			if i%2 == 0 {
				_, err = env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose, summary)
			} else {
				_, err = env.Login(t, "ann@acme.example", wrong)
			}
			if e, ok := apierr.As(err); ok && e.Code == "invalid_code" {
				mu.Lock()
				judged++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	t.Logf("judged %d of %d", judged, 2*n)
	if judged == 0 || judged > 10 {
		t.Fatalf("%d wrong two-step codes judged across sign-in and step-up, want at most 10", judged)
	}
}

// one TOTP code raced between a sign-in and a step-up is accepted at most once.
func TestStepUpOneTOTPCodeRacedBetweenSignInAndStepUpPassesOnce(t *testing.T) {
	t.Parallel()
	for range 5 {
		env := authtest.New(t)
		secret := appUser(t, env)
		id := annID(t, env)
		code := nextCode(env, secret, 1)
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := range 6 {
			wg.Go(func() {
				var err error
				if i%2 == 0 {
					_, err = env.Svc.VerifyTwoStep(t.Context(), id, code, purpose, summary)
				} else {
					_, err = env.Login(t, "ann@acme.example", code)
				}
				if err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d of 6 raced uses of one TOTP code passed, want 1", ok)
		}
	}
}

// one emailed step-up code used in parallel passes once, and never for another purpose.
func TestStepUpEmailCodeRacedPassesOnce(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 400, "code_required")
	code := env.Mailer.LastCode()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 8 {
		wg.Go(func() {
			p := purpose
			if i%2 == 1 {
				p = "response.other"
			}
			if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, p, summary); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok > 1 {
		t.Fatalf("%d parallel uses of one email step-up code passed, want at most 1", ok)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup' AND detail NOT LIKE 'purpose=response.approve %'"); n != 0 {
		t.Fatalf("a code issued for %s passed for another purpose", purpose)
	}
}

// a pending sign-in code never passes step-up even when the sign-in code was mailed while a step-up
// code was pending (the row is replaced, the domain is the sign-in one).
func TestStepUpSignInSendReplacingAStepUpCodeDoesNotLetItApprove(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 400, "code_required")
	env.Clock.Advance(61 * time.Second)
	_, err = env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
	signIn := env.Mailer.LastCode()
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, signIn, purpose, summary)
	if err == nil {
		t.Fatal("a sign-in code passed step-up")
	}
}

// M2 (continued): each kind has its own five an hour, the sixth is 429 too_many_codes with retry_after, and
// every step-up send leaves an auth.stepup_code_sent row without the code.
func TestStepUpEmailSendBudgetIsItsOwn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	env.Clock.Advance(time.Hour)
	var codes []string
	for range auth.MaxSendsPerHour {
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
		wantAPI(t, err, 400, "code_required")
		codes = append(codes, env.Mailer.LastCode())
		env.Clock.Advance(61 * time.Second)
	}
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	e := apiErr(t, err, 429, "too_many_codes")
	ra, ok := e.Extra["retry_after"].(int)
	if !ok || ra < 1 || ra > 3600 {
		t.Fatalf("retry_after = %v", e.Extra["retry_after"])
	}
	// Sign-in sends have their own five.
	for range auth.MaxSendsPerHour - 1 { // one was spent at enrolment, an hour ago: out of the window
		_, err = env.Login(t, u.Email, "")
		if e, ok := apierr.As(err); !ok || e.Code != "twofa_required" {
			t.Fatalf("sign-in send: %v", err)
		}
		env.Clock.Advance(61 * time.Second)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup_code_sent' AND detail = 'purpose=response.approve method=email: sent to a•••@acme.example'"); n != auth.MaxSendsPerHour {
		t.Fatalf("%d auth.stepup_code_sent rows, want %d", n, auth.MaxSendsPerHour)
	}
	for _, c := range codes {
		if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE detail LIKE ? OR target LIKE ?", "%"+c+"%", "%"+c+"%"); n != 0 {
			t.Fatalf("a code reached the audit")
		}
	}
}

// L7: the sign-in 429 too_many_codes carries retry_after too.
func TestSignInTooManyCodesHasRetryAfter(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	env.Clock.Advance(time.Hour)
	for range auth.MaxSendsPerHour {
		_, err := env.Login(t, u.Email, "")
		wantAPI(t, err, 401, "twofa_required")
		env.Clock.Advance(61 * time.Second)
	}
	_, err := env.Login(t, u.Email, "")
	if e, ok := apierr.As(err); ok && e.Code == "twofa_required" {
		// reuseFresh does not apply (the last code is older than 60 s): the sixth is refused
		t.Fatalf("sixth sign-in send went through")
	}
	e := apiErr(t, err, 429, "too_many_codes")
	if ra, ok := e.Extra["retry_after"].(int); !ok || ra < 1 || ra > 3600 {
		t.Fatalf("retry_after = %v", e.Extra["retry_after"])
	}
}

// M3: the summary reaches the step-up mailer verbatim, the code is not in it, and a sign-in code mail has none.
func TestStepUpEmailMailsTheSummaryWithTheCode(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	before := len(env.Mailer.Sent())
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, "  "+summary+" \n")
	wantAPI(t, err, 400, "code_required")
	sent := env.Mailer.Sent()
	if len(sent) != before+1 {
		t.Fatalf("%d mails", len(sent)-before)
	}
	m := sent[before]
	if !m.StepUp || m.To != u.Email || m.Summary != summary || strings.Contains(m.Summary, m.Code) {
		t.Fatalf("mail = %+v", m)
	}
	if sent[0].StepUp || sent[0].Summary != "" {
		t.Fatalf("the enrolment mail looks like a step-up mail: %+v", sent[0])
	}
	// The summary never goes into the audit.
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE detail LIKE '%Firewall%' OR target LIKE '%Firewall%'"); n != 0 {
		t.Fatalf("%d audit rows hold the summary", n)
	}
}

// codeMailerOnly hides every method but the two of auth.CodeMailer: a mailer from before step-up existed.
type codeMailerOnly struct{ auth.CodeMailer }

func TestStepUpEmailNeedsAMailerThatKnowsStepUp(t *testing.T) {
	t.Parallel()
	m := &authtest.Mailer{}
	m.SetAvailable(true)
	env := authtest.New(t, func(c *auth.Config) { c.Mailer = codeMailerOnly{m} })
	u := emailUserWith(t, env, m, "ann@acme.example")
	for _, code := range []string{"", "123456"} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, purpose, summary)
		wantAPI(t, err, 503, "twofa_email_unavailable")
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup_failed' AND detail = 'purpose=response.approve method=email: mailer'"); n != 2 {
		t.Fatalf("%d audit rows with reason mailer, want 2", n)
	}
	for _, mm := range m.Sent() {
		if mm.StepUp {
			t.Fatal("a step-up code was mailed through SendCode")
		}
	}
	// Sign-in mail is unchanged.
	_, err := env.Login(t, u.Email, "")
	wantAPI(t, err, 401, "twofa_required")
}

func TestStepUpFailedSendIsAuditedWithReasonSend(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	env.Mailer.FailSend(true)
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", purpose, summary)
	wantAPI(t, err, 503, "twofa_email_unavailable")
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup_failed' AND detail = 'purpose=response.approve method=email: send'"); n != 1 {
		t.Fatalf("%d audit rows with reason send, want 1", n)
	}
	if n := env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'auth.stepup_code_sent'"); n != 0 {
		t.Fatalf("%d code_sent rows for a mail that was not sent", n)
	}
}

func TestStepUpRefusesAnInvalidSummary(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	bad := []string{"", "   ", "a\nb", "a\rb", "a\tb", "a\x00b", "a\u202eb", "a\u2028b", "a\x7fb", strings.Repeat("x", 201), "a\xffb"}
	for _, sm := range bad {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose, sm)
		wantAPI(t, err, 400, "invalid")
	}
	// 200 characters (of two bytes each) is fine and nothing above was used up.
	if _, err := env.Svc.VerifyTwoStep(t.Context(), id, nextCode(env, secret, 1), purpose, strings.Repeat("é", 200)); err != nil {
		t.Fatal(err)
	}
}

// L5: a code mailed for one request does not pass for another with the same prefix.
func TestStepUpEmailCodeIsBoundToTheRequest(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	u := emailUser(t, env, "ann@acme.example")
	_, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, "", "response.approve.req-a", summary)
	wantAPI(t, err, 400, "code_required")
	code := env.Mailer.LastCode()
	_, err = env.Svc.VerifyTwoStep(t.Context(), u.ID, code, "response.approve.req-b", summary)
	wantAPI(t, err, 400, "wrong_code")
	if _, err := env.Svc.VerifyTwoStep(t.Context(), u.ID, code, "response.approve.req-a", summary); err != nil {
		t.Fatal(err)
	}
}

// L7: the limiter's 429 on step-up does not talk about signing in.
func TestStepUpRateLimitedMessageDoesNotMentionSignIn(t *testing.T) {
	t.Parallel()
	env := authtest.New(t)
	secret := appUser(t, env)
	id := annID(t, env)
	wrong := wrongCode(env, secret)
	for range 10 {
		_, _ = env.Svc.VerifyTwoStep(t.Context(), id, wrong, purpose, summary)
	}
	for _, code := range []string{wrong, ""} {
		_, err := env.Svc.VerifyTwoStep(t.Context(), id, code, purpose, summary)
		e := apiErr(t, err, 429, "rate_limited")
		if strings.Contains(strings.ToLower(e.Message), "sign") || e.Extra["retry_after"] == nil {
			t.Fatalf("message = %q, extra = %v", e.Message, e.Extra)
		}
	}
}
