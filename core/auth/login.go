package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// maxPasswordBytes bounds what Login hashes: a longer value cannot be a valid password (the policy allows
// 256 characters), so it is refused after the usual dummy hash without reaching argon2 with the real input.
const maxPasswordBytes = 4 * MaxPasswordLen

// LoginRequest is POST /auth/login after the handler decoded it. IP is the client address and UserAgent the
// header; neither is trusted for anything but display and the rate limit.
type LoginRequest struct {
	Email     string
	Password  string
	Code      string // the two-step code, empty on the first call
	IP        string
	UserAgent string
}

// LoginResult is a successful sign-in: the handler sets Session.Cookies() and answers 200.
type LoginResult struct {
	Session Issued
	User    User
}

func invalidCredentials() *apierr.Error {
	return apierr.New(400, CodeInvalidCredentials, "Wrong email or password.")
}

// checkPassword runs exactly one argon2 verification whether or not the account exists (against a dummy
// hash when it does not), so response time does not reveal which emails have accounts. It records a failure
// on the rate limiter and, for a real account, a core_audit row. It returns the account row and whether its
// hash should be recomputed with the current parameters.
func (s *Service) checkPassword(ctx context.Context, email, password, ip string) (coredb.CoreUser, bool, error) {
	row, err := coredb.New(s.db.Reader()).GetUserByEmail(ctx, email)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return coredb.CoreUser{}, false, fmt.Errorf("auth: look up user: %w", err)
	}
	hash := s.dummy
	if found {
		hash = row.PasswordHash
	}
	tooLong := len(password) > maxPasswordBytes
	if tooLong {
		password = ""
	}
	ok, rehash, verr := s.params.Verify(hash, password)
	if verr != nil {
		s.log.ErrorContext(ctx, "stored password hash is malformed", "user_id", row.ID)
		ok = false
	}
	if !found || !ok || tooLong {
		s.limit.fail(ip, email)
		if found {
			if err := s.auditFailure(ctx, row.Email, "wrong password"); err != nil {
				return coredb.CoreUser{}, false, err
			}
		}
		return coredb.CoreUser{}, false, invalidCredentials()
	}
	return row, rehash, nil
}

func (s *Service) auditFailure(ctx context.Context, email, why string) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: email, Action: "auth.login_failed", Target: email, Detail: why})
	})
}

func disabledError() *apierr.Error {
	return apierr.New(403, CodeDisabled, "This account has been disabled.")
}

// Login runs the sign-in flow of core INV-8:
//
//  1. the (IP, email) rate limit: 429 rate_limited while blocked;
//  2. the password (always one argon2 run): 400 invalid_credentials, identical for an unknown email and a
//     wrong password; a disabled account that gave the right password is 403 disabled;
//  3. two-step sign-in, when the account has it: without Code, 401 twofa_required with method app, or
//     method email plus sent_to and resend_after (the code was just mailed); with a bad Code, no session:
//     invalid_code (app) or the email-code errors of EmailCodes.Verify. An email-method account whose
//     channel cannot send is 503 twofa_email_unavailable, never password-only;
//  4. on success one transaction creates the session, sets last_login, stores the TOTP step (a code is
//     accepted once), upgrades an outdated password hash, and writes auth.login.
//
// Failures that name a real account write auth.login_failed (a reason, never the password or code).
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	email, ip := normalizeEmail(req.Email), normalizeIP(req.IP)
	if e := s.limit.check(ip, email); e != nil {
		return LoginResult{}, e
	}
	row, rehash, err := s.checkPassword(ctx, email, req.Password, ip)
	if err != nil {
		return LoginResult{}, err
	}
	if row.Disabled != 0 {
		if err := s.auditFailure(ctx, row.Email, "account disabled"); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, disabledError()
	}

	code := strings.Join(strings.Fields(req.Code), "")
	var totpStep int64
	if row.TwofaMethod != nil {
		switch *row.TwofaMethod {
		case "email":
			if err := s.loginEmailCode(ctx, row, code, ip); err != nil {
				return LoginResult{}, err
			}
		case "app":
			var err error
			if totpStep, err = s.loginTOTP(ctx, row, code, ip); err != nil {
				return LoginResult{}, err
			}
		default:
			return LoginResult{}, fmt.Errorf("auth: user %s has unknown twofa_method %q", row.ID, *row.TwofaMethod)
		}
	}

	newHash := ""
	if rehash {
		if newHash, err = s.params.Hash(req.Password); err != nil {
			return LoginResult{}, err
		}
	}
	res, err := write(ctx, s.db, func(tx *sql.Tx) (LoginResult, *apierr.Error, error) {
		q := coredb.New(tx)
		if row.TwofaMethod != nil && *row.TwofaMethod == "app" {
			step := totpStep
			n, err := q.AdvanceTotpStep(ctx, coredb.AdvanceTotpStepParams{LastStep: &step, UserID: row.ID, LastStep_2: &step})
			if err != nil {
				return LoginResult{}, nil, fmt.Errorf("auth: store totp step: %w", err)
			}
			if n == 0 { // another request used this code (or a later one) between our check and now
				s.limit.fail(ip, email)
				if err := s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.login_failed", Target: row.Email, Detail: "two-step code already used"}); err != nil {
					return LoginResult{}, nil, err
				}
				return LoginResult{}, wrongAppCode(), nil
			}
		}
		now := store.FormatTS(s.now())
		if err := q.UpdateUserLastLogin(ctx, coredb.UpdateUserLastLoginParams{LastLogin: &now, ID: row.ID}); err != nil {
			return LoginResult{}, nil, fmt.Errorf("auth: set last_login: %w", err)
		}
		if newHash != "" {
			if _, err := q.UpdateUserPassword(ctx, coredb.UpdateUserPasswordParams{PasswordHash: newHash, ID: row.ID}); err != nil {
				return LoginResult{}, nil, fmt.Errorf("auth: rehash password: %w", err)
			}
		}
		sess, err := s.Sessions.Create(ctx, tx, row.ID, req.UserAgent, ip)
		if err != nil {
			return LoginResult{}, nil, err
		}
		if err := s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.login", Target: row.Email}); err != nil {
			return LoginResult{}, nil, err
		}
		u := userFrom(row)
		t := s.now()
		u.LastLogin = &t
		return LoginResult{Session: sess, User: u}, nil, nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	s.limit.reset(ip, email)
	return res, nil
}

func wrongAppCode() *apierr.Error {
	return apierr.New(400, CodeInvalidCode, "Wrong code. Check the time on your phone and enter a new code.")
}

// loginEmailCode is step 3 for the email method. It returns nil only when a correct code was used up.
func (s *Service) loginEmailCode(ctx context.Context, row coredb.CoreUser, code, ip string) error {
	if !s.Codes.Available(ctx) {
		// INV-8: never fall back to the password alone.
		if err := s.auditFailure(ctx, row.Email, "email channel unavailable for two-step code"); err != nil {
			return err
		}
		return errEmailUnavailable()
	}
	if code == "" {
		sent, err := s.Codes.Send(ctx, row.ID, row.Email, true)
		if err != nil {
			return err
		}
		return apierr.New(401, CodeTwofaRequired, "We sent a 6-digit code to your sign-in email. Enter it to finish signing in.").
			With("method", "email").With("sent_to", sent.SentTo).With("resend_after", sent.ResendAfter)
	}
	if err := s.Codes.Verify(ctx, row.ID, code); err != nil {
		if _, ok := apierr.As(err); ok {
			s.limit.fail(ip, row.Email)
			if aerr := s.auditFailure(ctx, row.Email, "wrong two-step code"); aerr != nil {
				return aerr
			}
		}
		return err
	}
	return nil
}

// loginTOTP is step 3 for the authenticator-app method. It returns the accepted time step; the caller stores
// it in the sign-in transaction.
func (s *Service) loginTOTP(ctx context.Context, row coredb.CoreUser, code, ip string) (int64, error) {
	if code == "" {
		return 0, apierr.New(401, CodeTwofaRequired, "This account has two-step sign-in on. Enter the 6-digit code from your authenticator app.").With("method", "app")
	}
	t, err := coredb.New(s.db.Reader()).GetTotp(ctx, row.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("auth: read totp: %w", err)
	}
	var step int64
	ok := false
	if err == nil && t.Confirmed == 1 {
		secret, oerr := s.secrets.Open(ctx, s.db.Reader(), t.SecretID, totpPurpose)
		if oerr != nil {
			return 0, fmt.Errorf("auth: open totp secret: %w", oerr)
		}
		last := NoStep
		if t.LastStep != nil {
			last = *t.LastStep
		}
		step, ok = VerifyTOTP(secret, code, s.now(), last)
	} else {
		s.log.ErrorContext(ctx, "user has two-step app method but no confirmed key", "user_id", row.ID)
	}
	if !ok {
		s.limit.fail(ip, row.Email)
		if aerr := s.auditFailure(ctx, row.Email, "wrong two-step code"); aerr != nil {
			return 0, aerr
		}
		return 0, wrongAppCode()
	}
	return step, nil
}

// totpPurpose is the core_secret purpose of TOTP keys (DATA_MODEL 5.4).
const totpPurpose = "core_user_totp"

// ResendCode is POST /auth/login/resend-code: it needs the password again, so a stranger cannot make the
// box mail codes to someone else's mailbox. Errors: the rate limit, invalid_credentials, 403 disabled,
// 409 not_email_method, 503 twofa_email_unavailable, and the send limits of EmailCodes.Send.
func (s *Service) ResendCode(ctx context.Context, email, password, ip string) (Sent, error) {
	email, ip = normalizeEmail(email), normalizeIP(ip)
	if e := s.limit.check(ip, email); e != nil {
		return Sent{}, e
	}
	row, _, err := s.checkPassword(ctx, email, password, ip)
	if err != nil {
		return Sent{}, err
	}
	if row.Disabled != 0 {
		return Sent{}, disabledError()
	}
	if row.TwofaMethod == nil || *row.TwofaMethod != "email" {
		return Sent{}, apierr.New(409, CodeNotEmailMethod, "This account does not use email codes.")
	}
	sent, err := s.Codes.Send(ctx, row.ID, row.Email, false)
	if err != nil {
		return Sent{}, err
	}
	return sent, s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: row.Email, Action: "auth.code_resend", Target: row.Email})
	})
}
