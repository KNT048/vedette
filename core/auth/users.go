package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

var emailRE = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validRole(r routes.Role) bool {
	return r == routes.Viewer || r == routes.Operator || r == routes.Admin
}

func notFound() *apierr.Error { return apierr.New(404, apierr.CodeNotFound, "No such user.") }

// NewUser is a account to create. PasswordHash comes from Service.HashPassword (which applies the policy),
// computed before the transaction starts.
type NewUser struct {
	Name         string
	Email        string
	Role         routes.Role
	PasswordHash string
}

// CreateUser inserts an account inside the caller's transaction and writes user.create. Refusals are
// *apierr.Error: invalid_name (1 to 80 characters), invalid_email, invalid_role, 409 duplicate.
// The caller (the admin handler, or first-run setup) owns the transaction; the actor is "system" during setup.
func (s *Service) CreateUser(ctx context.Context, tx *sql.Tx, actor string, in NewUser) (User, error) {
	name := in.Name
	if n := utf8.RuneCountInString(name); n < 1 || n > 80 || !utf8.ValidString(name) || hasControl(name) {
		return User{}, apierr.New(400, CodeInvalidName, "Enter the user's name (at most 80 characters).")
	}
	email := normalizeEmail(in.Email)
	if !emailRE.MatchString(email) || len(email) > 320 || hasControl(email) {
		return User{}, apierr.New(400, CodeInvalidEmail, "The email is not valid, for example name@company.com.")
	}
	if !validRole(in.Role) {
		return User{}, apierr.New(400, CodeInvalidRole, "Choose a role: view only, operator or administrator.")
	}
	q := coredb.New(tx)
	if _, err := q.GetUserByEmail(ctx, email); err == nil {
		return User{}, apierr.New(409, CodeDuplicate, "This email already has an account.")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("auth: check duplicate: %w", err)
	}
	id := store.NewID("u")
	now := s.now()
	err := q.InsertUser(ctx, coredb.InsertUserParams{ID: id, Name: name, Email: email, Role: string(in.Role), PasswordHash: in.PasswordHash, CreatedAt: store.FormatTS(now)})
	if store.IsUniqueViolation(err) { // two creates of one email raced past the check above
		return User{}, apierr.New(409, CodeDuplicate, "This email already has an account.")
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: insert user: %w", err)
	}
	if err := s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "user.create", Target: email, Detail: "role " + string(in.Role)}); err != nil {
		return User{}, err
	}
	return User{ID: id, Name: name, Email: email, Role: in.Role, CreatedAt: now}, nil
}

// hasControl reports whether s has a control character (C0, DEL, C1): none belongs in a name or an email.
func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// UserPatch is PATCH /core/users/{id}: nil fields stay as they are.
type UserPatch struct {
	Role     *routes.Role
	Disabled *bool
}

// UpdateUser changes a role and/or disables or enables an account (INV-7). actorID is the signed-in admin.
// An administrator cannot disable themselves (400 self_disable), and the change may not leave the box without
// an active administrator (400 last_admin) - checked on the state after the change, so demoting or
// disabling the last one is refused. Disabling ends all of the account's sessions. 404 not_found for an
// unknown id; 400 invalid_role.
func (s *Service) UpdateUser(ctx context.Context, actorID, actorEmail, targetID string, p UserPatch) (User, error) {
	if p.Role != nil && !validRole(*p.Role) {
		return User{}, apierr.New(400, CodeInvalidRole, "Choose a role: view only, operator or administrator.")
	}
	return write(ctx, s.db, func(tx *sql.Tx) (User, *apierr.Error, error) {
		q := coredb.New(tx)
		t, err := q.GetUserByID(ctx, targetID)
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, notFound(), nil
		}
		if err != nil {
			return User{}, nil, fmt.Errorf("auth: read user: %w", err)
		}
		role, disabled := routes.Role(t.Role), t.Disabled != 0
		if p.Role != nil {
			role = *p.Role
		}
		if p.Disabled != nil {
			if *p.Disabled && t.ID == actorID {
				return User{}, apierr.New(400, CodeSelfDisable, "You cannot disable the account you are using. Ask another administrator."), nil
			}
			disabled = *p.Disabled
		}
		others, err := q.CountOtherActiveAdmins(ctx, t.ID)
		if err != nil {
			return User{}, nil, fmt.Errorf("auth: count admins: %w", err)
		}
		stays := int64(0)
		if role == routes.Admin && !disabled {
			stays = 1
		}
		if others+stays < 1 {
			return User{}, apierr.New(400, CodeLastAdmin, "At least one active administrator must remain. Add another administrator first."), nil
		}
		if role != routes.Role(t.Role) {
			if _, err := q.UpdateUserRole(ctx, coredb.UpdateUserRoleParams{Role: string(role), ID: t.ID}); err != nil {
				return User{}, nil, fmt.Errorf("auth: set role: %w", err)
			}
			if err := s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: "user.role", Target: t.Email, Detail: t.Role + " to " + string(role)}); err != nil {
				return User{}, nil, err
			}
		}
		if disabled != (t.Disabled != 0) {
			flag := int64(0)
			action := "user.enable"
			if disabled {
				flag, action = 1, "user.disable"
			}
			if _, err := q.UpdateUserDisabled(ctx, coredb.UpdateUserDisabledParams{Disabled: flag, ID: t.ID}); err != nil {
				return User{}, nil, fmt.Errorf("auth: set disabled: %w", err)
			}
			if disabled {
				if _, err := s.Sessions.RevokeAllForUser(ctx, tx, t.ID); err != nil {
					return User{}, nil, err
				}
			}
			if err := s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: action, Target: t.Email}); err != nil {
				return User{}, nil, err
			}
		}
		after, err := q.GetUserByID(ctx, t.ID)
		if err != nil {
			return User{}, nil, fmt.Errorf("auth: re-read user: %w", err)
		}
		return userFrom(after), nil, nil
	})
}

// ResetPassword is POST /core/users/{id}/reset-password (admin): it sets a new random temporary password,
// ends every session of that user (INV-7) and returns the password. It is returned this once and never
// stored in the clear: the handler passes it on in the response and nowhere else.
func (s *Service) ResetPassword(ctx context.Context, actorEmail, targetID string) (string, error) {
	t, err := coredb.New(s.db.Reader()).GetUserByID(ctx, targetID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", notFound()
	}
	if err != nil {
		return "", fmt.Errorf("auth: read user: %w", err)
	}
	temp, err := NewTempPassword()
	if err != nil {
		return "", err
	}
	hash, err := s.hashPassword(ctx, temp)
	if err != nil {
		return "", err
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		if n, err := coredb.New(tx).UpdateUserPassword(ctx, coredb.UpdateUserPasswordParams{PasswordHash: hash, ID: t.ID}); err != nil || n == 0 {
			if err == nil {
				return struct{}{}, notFound(), nil
			}
			return struct{}{}, nil, fmt.Errorf("auth: set password: %w", err)
		}
		n, err := s.Sessions.RevokeAllForUser(ctx, tx, t.ID)
		if err != nil {
			return struct{}{}, nil, err
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: "user.password_reset", Target: t.Email, Detail: fmt.Sprintf("%d sessions ended", n)})
	})
	if err != nil {
		return "", err
	}
	return temp, nil
}

// ChangeOwnPassword is POST /core/account/password: the current password must be right (400 wrong_password,
// counted by the same rate limit as sign-in), the new one must pass the policy (weak_password) and differ
// (same_password). The user's other sessions end; keepSessionID (the current one) stays.
func (s *Service) ChangeOwnPassword(ctx context.Context, userID, keepSessionID, current, next string) error {
	t, err := coredb.New(s.db.Reader()).GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.Unauthenticated()
	}
	if err != nil {
		return fmt.Errorf("auth: read user: %w", err)
	}
	if err := s.checkOwnPassword(ctx, t, current, "The current password is wrong."); err != nil {
		return err
	}
	if e := ValidatePassword(next, t.Email); e != nil {
		return e
	}
	if next == current {
		return apierr.New(400, CodeSamePassword, "The new password must differ from the current one.")
	}
	hash, err := s.hashPassword(ctx, next)
	if err != nil {
		return err
	}
	_, err = write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		q := coredb.New(tx)
		// The password was checked and the new one hashed outside this transaction: an administrator's
		// reset (or this user's other request) may have changed it since. Then this request is stale and
		// must not overwrite the newer password. The caller must also still be who they were: not
		// disabled, and the session they act from not ended.
		if refusal, err := s.callerRefusal(ctx, q, t.ID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		n, err := q.ChangeUserPassword(ctx, coredb.ChangeUserPasswordParams{PasswordHash: hash, ID: t.ID, CredVersion: t.CredVersion})
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: set password: %w", err)
		}
		if n == 0 {
			return struct{}{}, passwordMoved(), nil
		}
		if _, err := q.RevokeOtherSessions(ctx, coredb.RevokeOtherSessionsParams{RevokedAt: ptr(store.FormatTS(s.now())), UserID: t.ID, ID: keepSessionID}); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: revoke other sessions: %w", err)
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.password", Target: t.Email})
	})
	return err
}

// passwordMoved is the refusal when the password changed between the check and the write. wrong_password
// (API_CONVENTIONS 3.3) is the honest code: the password the caller proved is no longer the current one.
func passwordMoved() *apierr.Error {
	return apierr.New(400, CodeWrongPassword, "Your password was changed while this request was running. Enter your current password again.")
}

// callerRefusal is checked inside the write transaction of every operation done for a signed-in user: the
// account must not be disabled (403 disabled) and, when keepSessionID is given, that session must still be
// live (401 unauthenticated): a revoked or expired session, or a disabled account, must not finish a
// request it started before. Nothing has been written when it returns a refusal.
func (s *Service) callerRefusal(ctx context.Context, q *coredb.Queries, userID, keepSessionID string) (*apierr.Error, error) {
	cur, err := q.GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.Unauthenticated(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read user: %w", err)
	}
	if cur.Disabled != 0 {
		return disabledError(), nil
	}
	if keepSessionID == "" {
		return nil, nil
	}
	now := s.now()
	_, err = q.GetLiveSession(ctx, coredb.GetLiveSessionParams{ID: keepSessionID, UserID: userID, ExpiresAt: store.FormatTS(now), LastSeen: store.FormatTS(now.Add(-IdleTimeout))})
	if errors.Is(err, sql.ErrNoRows) {
		return apierr.Unauthenticated(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read session: %w", err)
	}
	return nil, nil
}

// checkOwnPassword verifies the password of a signed-in user for a sensitive change. Wrong guesses share the
// sign-in rate limit (keyed by account, since a signed-in caller's IP is not the point); a guess is counted
// before it is checked so parallel guesses cannot all pass, and the count goes away on the right password.
func (s *Service) checkOwnPassword(ctx context.Context, t coredb.CoreUser, password, wrongMsg string) error {
	try, e := s.limit.begin(accountKey, t.Email)
	if e != nil {
		return e
	}
	ok, _, err := s.verifyPassword(ctx, t.PasswordHash, password[:min(len(password), maxPasswordBytes)])
	if err != nil {
		try.refund() // busy, cancelled or a broken stored hash: not a wrong guess
		if errors.Is(err, ErrBadHash) {
			return fmt.Errorf("auth: stored password hash: %w", err)
		}
		return err
	}
	if !ok || len(password) > maxPasswordBytes {
		return apierr.New(400, CodeWrongPassword, wrongMsg)
	}
	s.limit.reset(accountKey, t.Email)
	return nil
}
