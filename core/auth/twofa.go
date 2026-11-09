package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// ConfirmTOTP turns two-step sign-in on with the authenticator app once the user proves they hold the key:
// 409 no_pending (no key, or it is over 10 minutes old), 400 invalid_code (not 6 digits), 400 wrong_code,
// 409 already_on. The confirming code's step is recorded, so it cannot sign in a second time. Turning
// two-step on ends the user's other sessions (keepSessionID, the current one, stays): INV-7.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, keepSessionID, code string) error {
	t, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	if t.TwofaMethod != nil {
		return alreadyOn()
	}
	p, err := coredb.New(s.db.Reader()).GetTotp(ctx, t.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return noPending()
	}
	if err != nil {
		return fmt.Errorf("auth: read totp: %w", err)
	}
	if p.Confirmed == 1 || s.now().Sub(parseTS(p.CreatedAt)) > pendingTOTPTTL {
		return noPending()
	}
	code = strings.Join(strings.Fields(code), "")
	if !isSixDigits(code) {
		return apierr.New(400, CodeInvalidCode, "The code is 6 digits from your authenticator app.")
	}
	secret, err := s.secrets.Open(ctx, s.db.Reader(), p.SecretID, totpPurpose)
	if err != nil {
		return fmt.Errorf("auth: open totp secret: %w", err)
	}
	step, ok := VerifyTOTP(secret, code, s.now(), NoStep)
	if !ok {
		return apierr.New(400, CodeWrongCode, "Wrong code. Check the time on your phone and enter a new code.")
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		q := coredb.New(tx)
		// Checked again here, before anything is written: the single writer serialises us with a racing
		// confirm of the other method (a refusal after a write would commit that write), and the caller
		// must still be allowed to act (account not disabled, session not ended).
		if refusal, err := s.callerRefusal(ctx, q, t.ID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		if cur, err := q.GetUserByID(ctx, t.ID); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		} else if cur.TwofaMethod != nil {
			return struct{}{}, alreadyOn(), nil
		}
		if n, err := q.ConfirmTotp(ctx, coredb.ConfirmTotpParams{LastStep: &step, UserID: t.ID}); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: confirm totp: %w", err)
		} else if n == 0 {
			return struct{}{}, noPending(), nil
		}
		if err := s.enableMethod(ctx, tx, t.ID, "app", keepSessionID); err != nil {
			return struct{}{}, nil, err
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_on", Target: t.Email, Detail: "authenticator app"})
	})
	return err
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
// EmailCodes.Verify; 409 already_on; 409 email_channel_not_ready). Like ConfirmTOTP it ends the user's
// other sessions.
func (s *Service) ConfirmEmail2FA(ctx context.Context, userID, keepSessionID, code string) error {
	t, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	if t.TwofaMethod != nil {
		return alreadyOn()
	}
	if !s.Codes.Available(ctx) {
		return emailNotReady()
	}
	if err := s.Codes.Verify(ctx, t.ID, code); err != nil {
		return err
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		if refusal, err := s.callerRefusal(ctx, coredb.New(tx), t.ID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		if cur, err := coredb.New(tx).GetUserByID(ctx, t.ID); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		} else if cur.TwofaMethod != nil {
			return struct{}{}, alreadyOn(), nil
		}
		if err := s.enableMethod(ctx, tx, t.ID, "email", keepSessionID); err != nil {
			return struct{}{}, nil, err
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_on", Target: t.Email, Detail: "email code"})
	})
	return err
}

// DisableTwoFA turns two-step sign-in off for the signed-in user (POST /core/account/2fa/disable): the
// password must be right (400 wrong_password); 409 not_on. The key or pending code is deleted and the
// user's other sessions end (keepSessionID, the current one, stays): INV-7.
func (s *Service) DisableTwoFA(ctx context.Context, userID, keepSessionID, password string) error {
	t, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.checkOwnPassword(ctx, t, password, "Wrong password. The password is needed to turn off two-factor authentication."); err != nil {
		return err
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		cur, err := coredb.New(tx).GetUserByID(ctx, t.ID)
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		}
		// A caller whose account or session is gone is refused first (the same order as ChangeOwnPassword: a
		// dead session is 401 whatever else is stale). The password was checked outside this transaction:
		// when it has been changed or reset since, that proof is stale.
		if refusal, err := s.callerRefusal(ctx, coredb.New(tx), t.ID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		if cur.CredVersion != t.CredVersion {
			return struct{}{}, passwordMoved(), nil
		}
		if cur.TwofaMethod == nil {
			return struct{}{}, apierr.New(409, CodeNotOn, "Two-step sign-in is already off."), nil
		}
		if err := s.clearTwoFA(ctx, tx, t.ID); err != nil {
			return struct{}{}, nil, err
		}
		if err := s.revokeOthers(ctx, tx, t.ID, keepSessionID); err != nil {
			return struct{}{}, nil, err
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.2fa_off", Target: t.Email})
	})
	return err
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

// enableMethod turns a method on for a user who has none, and ends their other sessions. The update is
// conditional; the callers read the user in the same transaction first, so zero rows is a bug, not a race.
func (s *Service) enableMethod(ctx context.Context, tx *sql.Tx, userID, method, keepSessionID string) error {
	n, err := coredb.New(tx).EnableUserTwofaMethod(ctx, coredb.EnableUserTwofaMethodParams{TwofaMethod: &method, ID: userID})
	if err != nil {
		return fmt.Errorf("auth: set twofa_method: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("auth: user %s already had a two-step method inside the transaction", userID)
	}
	return s.revokeOthers(ctx, tx, userID, keepSessionID)
}

func (s *Service) revokeOthers(ctx context.Context, tx *sql.Tx, userID, keepSessionID string) error {
	if _, err := coredb.New(tx).RevokeOtherSessions(ctx, coredb.RevokeOtherSessionsParams{RevokedAt: ptr(store.FormatTS(s.now())), UserID: userID, ID: keepSessionID}); err != nil {
		return fmt.Errorf("auth: revoke other sessions: %w", err)
	}
	return nil
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
