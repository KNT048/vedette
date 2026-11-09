package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// maxPasswordBytes bounds what Login hashes: a longer value cannot be a valid password (the policy allows
// 256 characters), so it is refused after the usual dummy hash without reaching argon2 with the real input.
const maxPasswordBytes = 4 * MaxPasswordLen

// LoginRequest is POST /auth/login after the handler decoded it. IP is the client address (the handler
// parses r.RemoteAddr with netip.ParseAddrPort and refuses the request when that fails) and UserAgent the
// header; neither is trusted for anything but display and the rate limit. A zero IP is refused: there is no
// shared fallback key an attacker could fill to lock everyone out.
type LoginRequest struct {
	Email     string
	Password  string
	Code      string // the two-step code, empty on the first call
	IP        netip.Addr
	UserAgent string
	// DeviceCookie is the value of the __Secure-vedette_device cookie the browser sent, "" when it sent none (D-77).
	DeviceCookie string
}

// LoginResult is a successful sign-in: the handler sets Session.Cookies() and answers 200.
type LoginResult struct {
	Session Issued
	User    User
	// Device is the value of the device cookie to set with DeviceCookie (D-77); "" when none could be made.
	Device string
}

func invalidCredentials() *apierr.Error {
	return apierr.New(400, CodeInvalidCredentials, "Wrong email or password.")
}

// checkPassword counts the attempt on the rate limiter (limitIP is ipLimitKey of the client; a blocked pair
// is refused with 429 before any password work), then runs exactly one argon2 verification whether or not
// the account exists (against a dummy hash when it does not), so response time does not reveal which emails
// have accounts. A failure writes one auth.login_failed row for a real account and for an unknown email
// alike (the same writer work on both paths); the count stays. A right password gives the count back. It
// returns the account row and whether its hash should be recomputed with the current parameters.
func (s *Service) checkPassword(ctx context.Context, email, password string, lims []string) (coredb.CoreUser, bool, error) {
	tries, e := s.limit.beginAll(email, lims)
	if e != nil {
		return coredb.CoreUser{}, false, e
	}
	row, err := coredb.New(s.db.Reader()).GetUserByEmail(ctx, email)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		refundAll(tries)
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
	ok, rehash, verr := s.verifyPassword(ctx, hash, password)
	if verr != nil {
		if !errors.Is(verr, ErrBadHash) { // busy or cancelled: nothing was judged
			refundAll(tries)
			return coredb.CoreUser{}, false, verr
		}
		s.log.ErrorContext(ctx, "stored password hash is malformed", "user_id", row.ID)
		ok = false
	}
	if !found || !ok || tooLong {
		user, target, why := row.Email, row.Email, "wrong password"
		if !found {
			ref, err := s.unknownEmailRef(ctx, email)
			if err != nil {
				return coredb.CoreUser{}, false, err
			}
			user, target, why = "unknown", ref, "unknown email"
		}
		if err := s.auditFailure(ctx, user, target, why); err != nil {
			return coredb.CoreUser{}, false, err
		}
		return coredb.CoreUser{}, false, invalidCredentials()
	}
	refundAll(tries)
	return row, rehash, nil
}

// auditKeyPurpose is the core_secret purpose of the key of unknownEmailRef (DATA_MODEL 5.4).
const auditKeyPurpose = "core_audit.unknown_email_key"

// unknownEmailRef names an email that has no account in core_audit without storing the address a stranger
// typed (people paste passwords into the email field, and the audit chain cannot be pruned): a keyed hash,
// HMAC-SHA-256 under a key of the box, cut to 16 hex characters. It is enough to see that one address is
// being tried again and again, and no table of guesses can undo it without the key.
func (s *Service) unknownEmailRef(ctx context.Context, email string) (string, error) {
	s.auditKeyMu.Lock()
	defer s.auditKeyMu.Unlock()
	if s.auditKey == nil {
		k, err := s.secrets.OpenOrCreate(ctx, s.db, auditKeyPurpose, 32)
		if err != nil {
			return "", fmt.Errorf("auth: audit key: %w", err)
		}
		s.auditKey = k
	}
	m := hmac.New(sha256.New, s.auditKey)
	m.Write([]byte(email))
	return "unknown email " + hex.EncodeToString(m.Sum(nil)[:8]), nil
}

func (s *Service) auditFailure(ctx context.Context, user, target, why string) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: user, Action: "auth.login_failed", Target: target, Detail: why})
	})
}

func disabledError() *apierr.Error {
	return apierr.New(403, CodeDisabled, "This account has been disabled.")
}

// Login runs the sign-in flow of core INV-8:
//
//  1. the (IP, email) rate limit (IPv6 by /64): the attempt is counted up front, 429 rate_limited while
//     blocked, before any password work. A valid device cookie of that account (D-77, device.go) swaps the
//     address keys for its own counter;
//  2. the password (always one argon2 run, under the concurrency cap: 503 server_busy when the box is
//     swamped): 400 invalid_credentials, identical for an unknown email and a wrong password; a disabled
//     account that gave the right password is 403 disabled;
//  3. two-step sign-in, when the account has it: the account's own limiter of two-step guesses first (no
//     IP, 429 rate_limited); without Code, 401 twofa_required with method app, or method email plus sent_to
//     and resend_after (the code was just mailed); with a bad Code, no session: invalid_code (app) or the
//     email-code errors of EmailCodes.Verify. An email-method account whose channel cannot send is 503
//     twofa_email_unavailable, never password-only;
//  4. on success one transaction first re-reads the account and refuses when its password, disabled flag or
//     two-step method changed since step 2 (a reset or disable that committed meanwhile wins), then creates
//     the session, sets last_login, stores the TOTP step (a code is accepted once), upgrades an outdated
//     password hash (only if it is still the one that was checked), and writes auth.login.
//
// Failures write auth.login_failed (a reason, never the password or code); an unknown email is written too,
// as a hash, so both paths do the same work.
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	if !req.IP.IsValid() {
		return LoginResult{}, errNoIP()
	}
	email := normalizeEmail(req.Email)
	lims, err := s.limitKeys(ctx, email, req.IP, req.DeviceCookie)
	if err != nil {
		return LoginResult{}, err
	}
	row, rehash, err := s.checkPassword(ctx, email, req.Password, lims)
	if err != nil {
		return LoginResult{}, err
	}
	if row.Disabled != 0 {
		if err := s.auditFailure(ctx, row.Email, row.Email, "account disabled"); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, disabledError()
	}

	code := strings.Join(strings.Fields(req.Code), "")
	var totpStep int64
	if row.TwofaMethod != nil {
		// A code is a guess: count it before checking so parallel guesses cannot all pass. Asking for the
		// prompt (no code) only needs the account not to be blocked.
		var guess attempt
		if code == "" {
			if e := s.limit.check(twofaKey, row.Email); e != nil {
				return LoginResult{}, e
			}
		} else {
			var e *apierr.Error
			if guess, e = s.limit.begin(twofaKey, row.Email); e != nil {
				return LoginResult{}, e
			}
		}
		var err error
		switch *row.TwofaMethod {
		case "email":
			err = s.loginEmailCode(ctx, row, code, lims)
		case "app":
			totpStep, err = s.loginTOTP(ctx, row, code, lims)
		default:
			err = fmt.Errorf("auth: user %s has unknown twofa_method %q", row.ID, *row.TwofaMethod)
		}
		if code != "" && (err == nil || !isCodeVerdict(err)) {
			guess.refund() // right, or never judged (channel down, internal error)
		}
		if err != nil {
			return LoginResult{}, err
		}
	}

	newHash := ""
	if rehash {
		switch h, err := s.hashPassword(ctx, req.Password); {
		case err == nil:
			newHash = h
		case isBusy(err): // upgrading the hash can wait for the next sign-in
		default:
			return LoginResult{}, err
		}
	}
	res, err := write(ctx, s.db, func(tx *sql.Tx) (LoginResult, *apierr.Error, error) {
		q := coredb.New(tx)
		// The checks above ran outside this transaction. The single writer serialises us with a reset,
		// disable or two-step change, so what we read here is what we commit against.
		cur, err := q.GetUserByID(ctx, row.ID)
		if errors.Is(err, sql.ErrNoRows) {
			return LoginResult{}, invalidCredentials(), nil
		}
		if err != nil {
			return LoginResult{}, nil, fmt.Errorf("auth: re-read user: %w", err)
		}
		if cur.Disabled != 0 {
			return LoginResult{}, disabledError(), nil
		}
		// cred_version, not the hash: a concurrent sign-in that only upgraded the hash must not make this
		// one fail with the right password (and burn its email code).
		if cur.CredVersion != row.CredVersion || !sameMethod(cur.TwofaMethod, row.TwofaMethod) {
			return LoginResult{}, invalidCredentials(), nil
		}
		if row.TwofaMethod != nil && *row.TwofaMethod == "app" {
			step := totpStep
			n, err := q.AdvanceTotpStep(ctx, coredb.AdvanceTotpStepParams{LastStep: &step, UserID: row.ID, LastStep_2: &step})
			if err != nil {
				return LoginResult{}, nil, fmt.Errorf("auth: store totp step: %w", err)
			}
			if n == 0 { // another request used this code (or a later one) between our check and now
				s.limit.failAll(email, lims)
				s.limit.fail(twofaKey, row.Email)
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
			if _, err := q.RehashUserPassword(ctx, coredb.RehashUserPasswordParams{PasswordHash: newHash, ID: row.ID, CredVersion: row.CredVersion}); err != nil {
				return LoginResult{}, nil, fmt.Errorf("auth: rehash password: %w", err)
			}
		}
		sess, err := s.Sessions.Create(ctx, tx, row.ID, req.UserAgent, req.IP)
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
	s.limit.resetAll(email, lims)
	s.limit.reset(twofaKey, row.Email)
	res.Device = s.deviceFor(ctx, row.ID, row.CredVersion)
	return res, nil
}

func sameMethod(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func isBusy(err error) bool {
	e, ok := apierr.As(err)
	return ok && e.Code == CodeBusy
}

// isCodeVerdict reports whether err says the two-step code itself was judged (wrong, malformed, expired,
// used up, none pending): those attempts stay counted.
func isCodeVerdict(err error) bool {
	e, ok := apierr.As(err)
	if !ok {
		return false
	}
	switch e.Code {
	case CodeInvalidCode, CodeWrongCode, CodeTooManyTries, CodeCodeExpired, CodeNoCode:
		return true
	}
	return false
}

func wrongAppCode() *apierr.Error {
	return apierr.New(400, CodeInvalidCode, "Wrong code. Check the time on your phone and enter a new code.")
}

// loginEmailCode is step 3 for the email method. It returns nil only when a correct code was used up.
func (s *Service) loginEmailCode(ctx context.Context, row coredb.CoreUser, code string, lims []string) error {
	if !s.Codes.Available(ctx) {
		// INV-8: never fall back to the password alone.
		if err := s.auditFailure(ctx, row.Email, row.Email, "email channel unavailable for two-step code"); err != nil {
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
			s.limit.failAll(row.Email, lims)
			if aerr := s.auditFailure(ctx, row.Email, row.Email, "wrong two-step code"); aerr != nil {
				return aerr
			}
		}
		return err
	}
	return nil
}

// loginTOTP is step 3 for the authenticator-app method. It returns the accepted time step; the caller stores
// it in the sign-in transaction.
func (s *Service) loginTOTP(ctx context.Context, row coredb.CoreUser, code string, lims []string) (int64, error) {
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
		s.limit.failAll(row.Email, lims)
		if aerr := s.auditFailure(ctx, row.Email, row.Email, "wrong two-step code"); aerr != nil {
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
func (s *Service) ResendCode(ctx context.Context, email, password string, ip netip.Addr, deviceCookie string) (Sent, error) {
	if !ip.IsValid() {
		return Sent{}, errNoIP()
	}
	email = normalizeEmail(email)
	lims, err := s.limitKeys(ctx, email, ip, deviceCookie)
	if err != nil {
		return Sent{}, err
	}
	row, _, err := s.checkPassword(ctx, email, password, lims)
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
