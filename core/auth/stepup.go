package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store/coredb"
)

// CodeRequired is the 400 code of a step-up that still needs its code (API_CONVENTIONS 3.3).
const CodeRequired = "code_required"

// StepUp describes the outcome of VerifyTwoStep. A nil error means the code was right and used up; then only
// Method is set. Without a code the call fails with 400 code_required and StepUp says where the code went:
// for the email method SentTo (masked address) and ResendAfter (seconds), as at sign-in.
type StepUp struct {
	Method      string // "app" or "email"
	SentTo      string
	ResendAfter int
}

var purposeRE = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// VerifyTwoStep asks a signed-in user for a fresh two-step code before one sensitive act (D-98, core INV-22):
// purpose names the act (for example "response.approve"), is validated and goes into the audit. There is no
// sudo window: every call needs its own code and nothing is remembered.
//
//   - app method: the code must be one step after the last accepted one, so the code that just signed the
//     user in, and a code already used here, are refused (RFC 6238 5.2). The step is stored in the same
//     transaction as auth.stepup.
//   - email method: an empty code mails one (same generator, HMAC storage, lifetime and resend spacing as
//     sign-in) and fails with 400 code_required plus the StepUp; the code is bound to purpose, so a sign-in
//     code never passes here and a step-up code never signs in. Mail that cannot be sent is 503
//     twofa_email_unavailable.
//   - a user without two-step is 403 twofa_required; a disabled or unknown user gets the same 400
//     invalid_code as a wrong code.
//   - wrong codes count on the account's two-step limiter shared with sign-in: a blocked account is 429
//     rate_limited with retry_after.
//
// The error is the only way to tell "passed" from "not passed": only nil means the user proved the code.
// auth.stepup and auth.stepup_failed carry the purpose and method, never the code.
func (s *Service) VerifyTwoStep(ctx context.Context, userID, code, purpose string) (StepUp, error) {
	if !purposeRE.MatchString(purpose) {
		return StepUp{}, apierr.Invalid("The purpose must be a short identifier such as response.approve.")
	}
	row, err := coredb.New(s.db.Reader()).GetUserByID(ctx, userID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return StepUp{}, s.stepUpFailed(ctx, "unknown", "unknown user", "unknown user", purpose, "", wrongAppCode())
	case err != nil:
		return StepUp{}, fmt.Errorf("auth: look up user: %w", err)
	case row.Disabled != 0:
		return StepUp{}, s.stepUpFailed(ctx, row.Email, row.Email, "account disabled", purpose, "", wrongAppCode())
	case row.TwofaMethod == nil:
		return StepUp{}, s.stepUpFailed(ctx, row.Email, row.Email, "two-step sign-in is off", purpose, "",
			apierr.New(403, CodeTwofaRequired, "Turn on two-step sign-in for your account first (My account), then try again."))
	}
	method := *row.TwofaMethod
	code = strings.Join(strings.Fields(code), "")
	switch method {
	case "email":
		return s.stepUpEmail(ctx, row, code, purpose)
	case "app":
		return s.stepUpTOTP(ctx, row, code, purpose)
	}
	return StepUp{}, fmt.Errorf("auth: user %s has unknown twofa_method %q", row.ID, method)
}

// stepUpFailed writes auth.stepup_failed (a reason, never the code) and returns refusal.
func (s *Service) stepUpFailed(ctx context.Context, user, target, why, purpose, method string, refusal *apierr.Error) error {
	if err := s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: user, Action: "auth.stepup_failed", Target: target, Detail: stepUpDetail(purpose, method, why)})
	}); err != nil {
		return err
	}
	return refusal
}

func stepUpDetail(purpose, method, why string) string {
	d := "purpose=" + purpose
	if method != "" {
		d += " method=" + method
	}
	if why != "" {
		d += ": " + why
	}
	return d
}

func (s *Service) stepUpEmail(ctx context.Context, row coredb.CoreUser, code, purpose string) (StepUp, error) {
	domain := "stepup:" + purpose
	fail := func(why string, refusal *apierr.Error) error {
		return s.stepUpFailed(ctx, row.Email, row.Email, why, purpose, "email", refusal)
	}
	if !s.Codes.Available(ctx) {
		return StepUp{}, fail("email channel unavailable for two-step code", errEmailUnavailable())
	}
	if code == "" {
		if e := s.limit.check(twofaKey, row.Email); e != nil {
			return StepUp{}, e
		}
		sent, err := s.Codes.send(ctx, row.ID, row.Email, domain, false)
		if err != nil {
			return StepUp{}, err
		}
		su := StepUp{Method: "email", SentTo: sent.SentTo, ResendAfter: sent.ResendAfter}
		return su, apierr.New(400, CodeRequired, "We sent a 6-digit code to your sign-in email. Enter it to continue.").
			With("method", "email").With("sent_to", sent.SentTo).With("resend_after", sent.ResendAfter)
	}
	guess, e := s.limit.begin(twofaKey, row.Email) // counted before judging: parallel guesses cannot all pass
	if e != nil {
		return StepUp{}, e
	}
	if err := s.Codes.verify(ctx, row.ID, domain, code); err != nil {
		if !isCodeVerdict(err) {
			guess.refund() // never judged
			return StepUp{}, err
		}
		return StepUp{}, fail("wrong two-step code", asAPI(err))
	}
	guess.refund()
	if err := s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.stepup", Target: row.Email, Detail: stepUpDetail(purpose, "email", "")})
	}); err != nil {
		return StepUp{}, err
	}
	return StepUp{Method: "email"}, nil
}

func asAPI(err error) *apierr.Error {
	e, _ := apierr.As(err)
	return e
}

func (s *Service) stepUpTOTP(ctx context.Context, row coredb.CoreUser, code, purpose string) (StepUp, error) {
	fail := func(why string) error {
		return s.stepUpFailed(ctx, row.Email, row.Email, why, purpose, "app", wrongAppCode())
	}
	if code == "" {
		if e := s.limit.check(twofaKey, row.Email); e != nil {
			return StepUp{}, e
		}
		return StepUp{Method: "app"}, apierr.New(400, CodeRequired, "Enter the 6-digit code from your authenticator app to continue.").With("method", "app")
	}
	guess, e := s.limit.begin(twofaKey, row.Email)
	if e != nil {
		return StepUp{}, e
	}
	step, ok, err := s.checkTOTP(ctx, row.ID, code)
	if err != nil {
		guess.refund()
		return StepUp{}, err
	}
	if !ok {
		return StepUp{}, fail("wrong two-step code")
	}
	used, err := write(ctx, s.db, func(tx *sql.Tx) (bool, *apierr.Error, error) {
		q := coredb.New(tx)
		cur, err := q.GetUserByID(ctx, row.ID)
		if err != nil {
			return false, nil, fmt.Errorf("auth: re-read user: %w", err)
		}
		// A disable or two-step change that committed since the check wins.
		if cur.Disabled != 0 || cur.CredVersion != row.CredVersion || !sameMethod(cur.TwofaMethod, row.TwofaMethod) {
			return false, wrongAppCode(), s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.stepup_failed", Target: row.Email, Detail: stepUpDetail(purpose, "app", "account changed")})
		}
		st := step
		n, err := q.AdvanceTotpStep(ctx, coredb.AdvanceTotpStepParams{LastStep: &st, UserID: row.ID, LastStep_2: &st})
		if err != nil {
			return false, nil, fmt.Errorf("auth: store totp step: %w", err)
		}
		if n == 0 { // another request used this code (or a later one) since the check
			return true, nil, nil
		}
		return false, nil, s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.stepup", Target: row.Email, Detail: stepUpDetail(purpose, "app", "")})
	})
	if err != nil {
		if _, isAPI := apierr.As(err); !isAPI {
			guess.refund()
		}
		return StepUp{}, err
	}
	if used {
		return StepUp{}, fail("two-step code already used")
	}
	guess.refund()
	return StepUp{Method: "app"}, nil
}
