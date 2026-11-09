package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// pendingTOTPTTL is how long a key shown by StartTOTP can be confirmed (DATA_MODEL: unconfirmed row expires
// after 10 minutes). The age is core_user_totp.created_at.
const pendingTOTPTTL = 10 * time.Minute

func alreadyOn() *apierr.Error {
	return apierr.New(409, CodeAlreadyOn, "Two-step sign-in is already on. Turn it off first to set up the other method.")
}

func noPending() *apierr.Error {
	return apierr.New(409, CodeNoPending, `No key is waiting for confirmation. Click "Turn on two-factor authentication" to create one.`)
}

func emailNotReady() *apierr.Error {
	return apierr.New(409, CodeEmailNotReady, "Email codes need the email alert channel. An administrator has to set it up and turn it on first.")
}

// TOTPSetup is what the SPA shows when someone turns on the authenticator-app method: the key to type in
// and the otpauth:// URI it draws as a QR code. The key is shown once, here.
type TOTPSetup struct {
	Secret string
	URI    string
}

func (s *Service) user(ctx context.Context, id string) (coredb.CoreUser, error) {
	t, err := coredb.New(s.db.Reader()).GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return coredb.CoreUser{}, apierr.Unauthenticated()
	}
	if err != nil {
		return coredb.CoreUser{}, fmt.Errorf("auth: read user: %w", err)
	}
	return t, nil
}

// enableWrongPassword is the message of a wrong password when two-step sign-in is being turned on (D-76).
const enableWrongPassword = "Wrong password. The password is needed to turn on two-factor authentication."

// StartTOTP creates a new unconfirmed key for the user (replacing an earlier unconfirmed one) and returns it.
// Turning two-step on needs the current password, like turning it off (D-76): 400 wrong_password, counted by
// the same account limiter as a wrong sign-in password. 409 already_on when two-step sign-in is already on.
// Nothing changes for sign-in until ConfirmTOTP. keepSessionID is the caller's session: when it has ended
// by the time the key is written, nothing is written (401).
func (s *Service) StartTOTP(ctx context.Context, userID, keepSessionID, password string) (TOTPSetup, error) {
	t, err := s.user(ctx, userID)
	if err != nil {
		return TOTPSetup{}, err
	}
	if err := s.checkOwnPassword(ctx, t, password, enableWrongPassword); err != nil {
		return TOTPSetup{}, err
	}
	if t.TwofaMethod != nil {
		return TOTPSetup{}, alreadyOn()
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return TOTPSetup{}, err
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		q := coredb.New(tx)
		if refusal, err := s.callerRefusal(ctx, q, t.ID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		if cur, err := q.GetUserByID(ctx, t.ID); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		} else if cur.CredVersion != t.CredVersion { // the password proof is stale
			return struct{}{}, passwordMoved(), nil
		} else if cur.TwofaMethod != nil { // turned on by another request since the check above
			return struct{}{}, alreadyOn(), nil
		}
		old, err := q.GetTotp(ctx, t.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return struct{}{}, nil, fmt.Errorf("auth: read totp: %w", err)
		}
		id, _, err := s.secrets.Seal(ctx, tx, totpPurpose, secret, false)
		if err != nil {
			return struct{}{}, nil, err
		}
		if err := q.UpsertTotp(ctx, coredb.UpsertTotpParams{UserID: t.ID, SecretID: id, CreatedAt: store.FormatTS(s.now())}); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: store totp: %w", err)
		}
		if old.SecretID != "" {
			s.pendingTries.forget(old.SecretID)
			if err := s.secrets.Delete(ctx, tx, old.SecretID); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				return struct{}{}, nil, err
			}
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_start", Target: t.Email, Detail: "authenticator app"})
	})
	if err != nil {
		return TOTPSetup{}, err
	}
	return TOTPSetup{Secret: SecretBase32(secret), URI: OTPAuthURI(t.Email, secret)}, nil
}

// maxPendingTOTPTries is how many wrong codes a pending authenticator key takes before it is dropped (the
// same count as an emailed code, MaxCodeTries): the owner starts again with the password.
const maxPendingTOTPTries = MaxCodeTries

// ConfirmTOTP turns two-step sign-in on with the authenticator app once the user proves they hold the key:
// 409 no_pending (no key, or it is over 10 minutes old), 400 invalid_code (not 6 digits), 400 wrong_code,
// 409 already_on. The confirming code's step is recorded, so it cannot sign in a second time. Every code is
// a guess: it is counted on the account's two-step limiter before it is checked (429 rate_limited; given
// back when the code is right, like a sign-in code), and the pending key is dropped after 5 wrong codes
// (400 too_many_tries): without the limits a holder of any session of the account could try every code
// while the key is pending. Turning two-step on ends every session of the user and returns a new one for
// the current browser (Sessions.Replace, INV-7), empty when currentSessionID is.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, currentSessionID, code string) (Issued, error) {
	t, err := s.user(ctx, userID)
	if err != nil {
		return Issued{}, err
	}
	if t.TwofaMethod != nil {
		return Issued{}, alreadyOn()
	}
	p, err := coredb.New(s.db.Reader()).GetTotp(ctx, t.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return Issued{}, noPending()
	}
	if err != nil {
		return Issued{}, fmt.Errorf("auth: read totp: %w", err)
	}
	if p.Confirmed == 1 || s.now().Sub(parseTS(p.CreatedAt)) > pendingTOTPTTL {
		return Issued{}, noPending()
	}
	code = strings.Join(strings.Fields(code), "")
	if !isSixDigits(code) {
		return Issued{}, apierr.New(400, CodeInvalidCode, "The code is 6 digits from your authenticator app.")
	}
	guess, e := s.limit.begin(twofaKey, t.Email)
	if e != nil {
		return Issued{}, e
	}
	secret, err := s.secrets.Open(ctx, s.db.Reader(), p.SecretID, totpPurpose)
	if err != nil {
		guess.refund() // not a wrong guess
		return Issued{}, fmt.Errorf("auth: open totp secret: %w", err)
	}
	step, ok := VerifyTOTP(secret, code, s.now(), NoStep)
	if !ok {
		if s.pendingTries.wrong(p.SecretID) >= maxPendingTOTPTries {
			if err := s.dropPendingTOTP(ctx, t.ID, p.SecretID); err != nil {
				return Issued{}, err
			}
			return Issued{}, apierr.New(400, CodeTooManyTries, "Too many wrong codes. Turn on two-factor authentication again to get a new key.")
		}
		return Issued{}, apierr.New(400, CodeWrongCode, "Wrong code. Check the time on your phone and enter a new code.")
	}
	guess.refund()
	s.pendingTries.forget(p.SecretID)
	return write(ctx, s.db, func(tx *sql.Tx) (Issued, *apierr.Error, error) {
		q := coredb.New(tx)
		// Checked again here, before anything is written: the single writer serialises us with a racing
		// confirm of the other method (a refusal after a write would commit that write), and the caller
		// must still be allowed to act (account not disabled, session not ended).
		if refusal, err := s.callerRefusal(ctx, q, t.ID, currentSessionID); refusal != nil || err != nil {
			return Issued{}, refusal, err
		}
		if cur, err := q.GetUserByID(ctx, t.ID); err != nil {
			return Issued{}, nil, fmt.Errorf("auth: read user: %w", err)
		} else if cur.TwofaMethod != nil {
			return Issued{}, alreadyOn(), nil
		}
		if n, err := q.ConfirmTotp(ctx, coredb.ConfirmTotpParams{LastStep: &step, UserID: t.ID}); err != nil {
			return Issued{}, nil, fmt.Errorf("auth: confirm totp: %w", err)
		} else if n == 0 {
			return Issued{}, noPending(), nil
		}
		fresh, err := s.enableMethod(ctx, tx, t.ID, "app", currentSessionID)
		if err != nil {
			return Issued{}, nil, err
		}
		return fresh, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_on", Target: t.Email, Detail: "authenticator app"})
	})
}

// dropPendingTOTP deletes the unconfirmed key secretID of a user (too many wrong codes), unless it was
// replaced or confirmed meanwhile.
func (s *Service) dropPendingTOTP(ctx context.Context, userID, secretID string) error {
	s.pendingTries.forget(secretID)
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		p, err := q.GetTotp(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (p.SecretID != secretID || p.Confirmed == 1)) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("auth: read totp: %w", err)
		}
		if err := q.DeleteTotp(ctx, userID); err != nil {
			return fmt.Errorf("auth: delete totp: %w", err)
		}
		if err := s.secrets.Delete(ctx, tx, secretID); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
		return nil
	})
}

// pendingTries counts the wrong codes of each pending authenticator key (by its secret id), in memory.
// ponytail: counts reset on restart (the account's two-step limiter does too); upgrade path: a tries column
// on core_user_totp like core_email_code.tries.
type pendingTries struct {
	mu sync.Mutex
	m  map[string]int
}

// wrong counts one wrong code for the key and returns how many it has had.
func (p *pendingTries) wrong(secretID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]int{}
	}
	p.m[secretID]++
	return p.m[secretID]
}

func (p *pendingTries) forget(secretID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, secretID)
}

// StartEmail2FA mails a code to the user's address so they can prove the mailbox works before email-code
// sign-in turns on. It needs the current password (D-76: 400 wrong_password, counted like a wrong sign-in
// password). 409 already_on; 409 email_channel_not_ready when the email channel cannot send; the send
// limits of EmailCodes.Send (resend_too_soon, too_many_codes). A caller whose account or session is gone
// (keepSessionID) gets nothing sent.
func (s *Service) StartEmail2FA(ctx context.Context, userID, keepSessionID, password string) (Sent, error) {
	t, err := s.user(ctx, userID)
	if err != nil {
		return Sent{}, err
	}
	if err := s.checkOwnPassword(ctx, t, password, enableWrongPassword); err != nil {
		return Sent{}, err
	}
	if refusal, err := s.callerRefusal(ctx, coredb.New(s.db.Reader()), t.ID, keepSessionID); refusal != nil || err != nil {
		if refusal != nil {
			return Sent{}, refusal
		}
		return Sent{}, err
	}
	if t.TwofaMethod != nil {
		return Sent{}, alreadyOn()
	}
	if !s.Codes.Available(ctx) {
		return Sent{}, emailNotReady()
	}
	sent, err := s.Codes.Send(ctx, t.ID, t.Email, false)
	if err != nil {
		return Sent{}, err
	}
	return sent, s.db.Write(ctx, func(tx *sql.Tx) error {
		return s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_start", Target: t.Email, Detail: "email code"})
	})
}

// ConfirmEmail2FA turns on email-code sign-in once the mailed code is right (the code errors of
// EmailCodes.Verify; 409 already_on; 409 email_channel_not_ready). Like ConfirmTOTP it ends every session of
// the user and returns a new one for the current browser.
func (s *Service) ConfirmEmail2FA(ctx context.Context, userID, currentSessionID, code string) (Issued, error) {
	t, err := s.user(ctx, userID)
	if err != nil {
		return Issued{}, err
	}
	if t.TwofaMethod != nil {
		return Issued{}, alreadyOn()
	}
	if !s.Codes.Available(ctx) {
		return Issued{}, emailNotReady()
	}
	if err := s.Codes.Verify(ctx, t.ID, code); err != nil {
		return Issued{}, err
	}
	return write(ctx, s.db, func(tx *sql.Tx) (Issued, *apierr.Error, error) {
		if refusal, err := s.callerRefusal(ctx, coredb.New(tx), t.ID, currentSessionID); refusal != nil || err != nil {
			return Issued{}, refusal, err
		}
		if cur, err := coredb.New(tx).GetUserByID(ctx, t.ID); err != nil {
			return Issued{}, nil, fmt.Errorf("auth: read user: %w", err)
		} else if cur.TwofaMethod != nil {
			return Issued{}, alreadyOn(), nil
		}
		fresh, err := s.enableMethod(ctx, tx, t.ID, "email", currentSessionID)
		if err != nil {
			return Issued{}, nil, err
		}
		return fresh, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_on", Target: t.Email, Detail: "email code"})
	})
}

// DisableTwoFA turns two-step sign-in off for the signed-in user (POST /core/account/2fa/disable): the
// password must be right (400 wrong_password); 409 not_on. The key or pending code is deleted and every
// session of the user ends, with a new one returned for the current browser: INV-7.
func (s *Service) DisableTwoFA(ctx context.Context, userID, currentSessionID, password string) (Issued, error) {
	t, err := s.user(ctx, userID)
	if err != nil {
		return Issued{}, err
	}
	if err := s.checkOwnPassword(ctx, t, password, "Wrong password. The password is needed to turn off two-factor authentication."); err != nil {
		return Issued{}, err
	}
	return write(ctx, s.db, func(tx *sql.Tx) (Issued, *apierr.Error, error) {
		cur, err := coredb.New(tx).GetUserByID(ctx, t.ID)
		if err != nil {
			return Issued{}, nil, fmt.Errorf("auth: read user: %w", err)
		}
		// A caller whose account or session is gone is refused first (the same order as ChangeOwnPassword: a
		// dead session is 401 whatever else is stale). The password was checked outside this transaction:
		// when it has been changed or reset since, that proof is stale.
		if refusal, err := s.callerRefusal(ctx, coredb.New(tx), t.ID, currentSessionID); refusal != nil || err != nil {
			return Issued{}, refusal, err
		}
		if cur.CredVersion != t.CredVersion {
			return Issued{}, passwordMoved(), nil
		}
		if cur.TwofaMethod == nil {
			return Issued{}, apierr.New(409, CodeNotOn, "Two-step sign-in is already off."), nil
		}
		if err := s.clearTwoFA(ctx, tx, t.ID); err != nil {
			return Issued{}, nil, err
		}
		fresh, err := s.Sessions.Replace(ctx, tx, t.ID, currentSessionID)
		if err != nil {
			return Issued{}, nil, err
		}
		return fresh, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_off", Target: t.Email})
	})
}

// ResetTwoFA is POST /core/users/{id}/2fa/reset (admin): it turns another user's two-step sign-in off, for
// someone who lost their phone. An administrator cannot reset their own (400 self_reset: use DisableTwoFA,
// which asks for the password); 404 not_found; 409 not_on. Every session of that user ends in the same
// transaction (INV-7): whoever held the lost phone, or the stolen password, is signed out with it.
func (s *Service) ResetTwoFA(ctx context.Context, actorID, actorEmail, actorSessionID, targetID string) error {
	if targetID == actorID {
		return apierr.New(400, CodeSelfReset, "You cannot reset your own two-step sign-in here. Use My account instead.")
	}
	_, err := write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		if refusal, err := s.adminRefusal(ctx, coredb.New(tx), actorID, actorSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		t, err := coredb.New(tx).GetUserByID(ctx, targetID)
		if errors.Is(err, sql.ErrNoRows) {
			return struct{}{}, notFound(), nil
		}
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		}
		if t.TwofaMethod == nil {
			return struct{}{}, apierr.New(409, CodeNotOn, "Two-step sign-in is already off for this user."), nil
		}
		was := "authenticator app"
		if *t.TwofaMethod == "email" {
			was = "email code"
		}
		if err := s.clearTwoFA(ctx, tx, t.ID); err != nil {
			return struct{}{}, nil, err
		}
		n, err := s.Sessions.RevokeAllForUser(ctx, tx, t.ID)
		if err != nil {
			return struct{}{}, nil, err
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: "user.2fa_reset", Target: t.Email, Detail: fmt.Sprintf("was %s; %d sessions ended", was, n)})
	})
	return err
}

// enableMethod turns a method on for a user who has none, and replaces their sessions (Sessions.Replace). The
// update is conditional; the callers read the user in the same transaction first, so zero rows is a bug,
// not a race.
func (s *Service) enableMethod(ctx context.Context, tx *sql.Tx, userID, method, currentSessionID string) (Issued, error) {
	n, err := coredb.New(tx).EnableUserTwofaMethod(ctx, coredb.EnableUserTwofaMethodParams{TwofaMethod: &method, ID: userID})
	if err != nil {
		return Issued{}, fmt.Errorf("auth: set twofa_method: %w", err)
	}
	if n == 0 {
		return Issued{}, fmt.Errorf("auth: user %s already had a two-step method inside the transaction", userID)
	}
	return s.Sessions.Replace(ctx, tx, userID, currentSessionID)
}

func (s *Service) setMethod(ctx context.Context, tx *sql.Tx, userID, method string) error {
	m := &method
	if method == "" {
		m = nil
	}
	if _, err := coredb.New(tx).UpdateUserTwofaMethod(ctx, coredb.UpdateUserTwofaMethodParams{TwofaMethod: m, ID: userID}); err != nil {
		return fmt.Errorf("auth: set twofa_method: %w", err)
	}
	return nil
}

// clearTwoFA removes every trace of two-step sign-in of a user inside tx: the TOTP row and its sealed key
// (no orphan core_secret), a pending email code, and the method.
func (s *Service) clearTwoFA(ctx context.Context, tx *sql.Tx, userID string) error {
	q := coredb.New(tx)
	p, err := q.GetTotp(ctx, userID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("auth: read totp: %w", err)
	default:
		if err := q.DeleteTotp(ctx, userID); err != nil {
			return fmt.Errorf("auth: delete totp: %w", err)
		}
		if err := s.secrets.Delete(ctx, tx, p.SecretID); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return err
		}
	}
	if err := s.Codes.Discard(ctx, tx, userID); err != nil {
		return err
	}
	return s.setMethod(ctx, tx, userID, "")
}
