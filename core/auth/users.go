package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	// Temporary: an administrator chose the password (D-180): it works for TempPasswordLifetime and the user must replace it.
	Temporary bool
}

// CreateUser inserts an account inside the caller's transaction and writes user.create. Refusals are
// *apierr.Error: invalid_name (1 to 80 characters), invalid_email, invalid_role, 409 duplicate.
// The caller (the admin handler, or first-run setup) owns the transaction; the actor is "system" during setup.
func (s *Service) CreateUser(ctx context.Context, tx *sql.Tx, actor string, in NewUser) (User, error) {
	email, verr := ValidateUserFields(in.Name, in.Email, in.Role)
	if verr != nil {
		return User{}, verr
	}
	name := in.Name
	q := coredb.New(tx)
	if _, err := q.GetUserByEmail(ctx, email); err == nil {
		return User{}, apierr.New(409, CodeDuplicate, "This email already has an account.")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("auth: check duplicate: %w", err)
	}
	id := store.NewID("u")
	now := s.now()
	var temp *string
	if in.Temporary {
		temp = s.tempExpiry()
	}
	err := q.InsertUser(ctx, coredb.InsertUserParams{ID: id, Name: name, Email: email, Role: string(in.Role), PasswordHash: in.PasswordHash, TempPasswordExpiresAt: temp, CreatedAt: store.FormatTS(now)})
	if store.IsUniqueViolation(err) { // two creates of one email raced past the check above
		return User{}, apierr.New(409, CodeDuplicate, "This email already has an account.")
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: insert user: %w", err)
	}
	if err := s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "user.create", Target: email, Detail: "role " + string(in.Role)}); err != nil {
		return User{}, err
	}
	return User{ID: id, Name: name, Email: email, Role: in.Role, CreatedAt: now, PasswordChangeRequired: in.Temporary}, nil
}

// ValidateUserFields applies the rules of a new account's name, email and role and returns the email as it
// is stored (trimmed, lowercase). Handlers that must refuse in a fixed order call it before the work
// (hashing) that CreateUser would otherwise follow.
func ValidateUserFields(name, rawEmail string, role routes.Role) (string, *apierr.Error) {
	if n := utf8.RuneCountInString(name); n < 1 || n > 80 || !utf8.ValidString(name) || HasInvisible(name) {
		return "", apierr.New(400, CodeInvalidName, "Enter the user's name (at most 80 characters).")
	}
	email := normalizeEmail(rawEmail)
	if !emailRE.MatchString(email) || len(email) > 320 || HasInvisible(email) {
		return "", apierr.New(400, CodeInvalidEmail, "The email is not valid, for example name@company.com.")
	}
	if !validRole(role) {
		return "", apierr.New(400, CodeInvalidRole, "Choose a role: view only, operator or administrator.")
	}
	return email, nil
}

// HasInvisible reports whether s has a control character (category Cc: C0, DEL, C1), an invisible format
// character (category Cf: bidirectional overrides and isolates, zero-width space and joiners, soft hyphen,
// byte order mark, tag characters), a Unicode Default_Ignorable_Code_Point (hangul fillers, combining
// grapheme joiner, variation selectors and others, many of them letters or marks, not Cf) or the braille
// blank U+2800. None belongs in a name or an email: they let a name read as another (an
// administrator-looking one) or make a name that cannot be typed back exactly. Used for the names of
// accounts and the organization. One exception: ZERO WIDTH NON-JOINER (U+200C) and ZERO WIDTH JOINER
// (U+200D) between two letters, which Persian, Indic and other scripts need to spell a name correctly.
func HasInvisible(s string) bool {
	rs := []rune(s)
	for i, r := range rs {
		if (r == 0x200C || r == 0x200D) && i > 0 && i+1 < len(rs) && unicode.IsLetter(rs[i-1]) && unicode.IsLetter(rs[i+1]) {
			continue
		}
		if r == 0x2800 || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(defaultIgnorable, r) {
			return true
		}
	}
	return false
}

// defaultIgnorable is the Unicode property Default_Ignorable_Code_Point (Unicode 16.0, DerivedCoreProperties.txt,
// https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt). Go's unicode package has no
// table for it. ponytail: written out by hand, so a later Unicode version that adds a code point is not
// covered until the table is updated; upgrade path: generate it from DerivedCoreProperties.txt.
var defaultIgnorable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00AD, Hi: 0x00AD, Stride: 1},
		{Lo: 0x034F, Hi: 0x034F, Stride: 1},
		{Lo: 0x061C, Hi: 0x061C, Stride: 1},
		{Lo: 0x115F, Hi: 0x1160, Stride: 1},
		{Lo: 0x17B4, Hi: 0x17B5, Stride: 1},
		{Lo: 0x180B, Hi: 0x180F, Stride: 1},
		{Lo: 0x200B, Hi: 0x200F, Stride: 1},
		{Lo: 0x202A, Hi: 0x202E, Stride: 1},
		{Lo: 0x2060, Hi: 0x206F, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1},
		{Lo: 0xFEFF, Hi: 0xFEFF, Stride: 1},
		{Lo: 0xFFA0, Hi: 0xFFA0, Stride: 1},
		{Lo: 0xFFF0, Hi: 0xFFF8, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1BCA0, Hi: 0x1BCA3, Stride: 1},
		{Lo: 0x1D173, Hi: 0x1D17A, Stride: 1},
		{Lo: 0xE0000, Hi: 0xE0FFF, Stride: 1},
	},
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
func (s *Service) UpdateUser(ctx context.Context, actorID, actorEmail, actorSessionID, targetID string, p UserPatch) (User, error) {
	if p.Role != nil && !validRole(*p.Role) {
		return User{}, apierr.New(400, CodeInvalidRole, "Choose a role: view only, operator or administrator.")
	}
	return write(ctx, s.db, func(tx *sql.Tx) (User, *apierr.Error, error) {
		q := coredb.New(tx)
		if refusal, err := s.adminRefusal(ctx, q, actorID, actorSessionID); refusal != nil || err != nil {
			return User{}, refusal, err
		}
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

// ResetPassword is POST /core/users/{id}/reset-password (admin): it sets a new random temporary password
// (TempPasswordLifetime, replaced by the user at the next sign-in, D-180), ends every session of that user
// (INV-7) and returns the password. It is returned this once and never
// stored in the clear: the handler passes it on in the response and nowhere else.
func (s *Service) ResetPassword(ctx context.Context, actorID, actorEmail, actorSessionID, targetID string) (string, error) {
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
		// The acting administrator is checked here, in the transaction that writes: a demoted or disabled
		// administrator, or one whose session ended while the hash was computed, changes nothing.
		if refusal, err := s.adminRefusal(ctx, coredb.New(tx), actorID, actorSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		if n, err := coredb.New(tx).UpdateUserPassword(ctx, coredb.UpdateUserPasswordParams{PasswordHash: hash, TempPasswordExpiresAt: s.tempExpiry(), ID: t.ID}); err != nil || n == 0 {
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
// (same_password). Every session of the user ends, the current one (currentSessionID) included, and a new
// session for the same browser is returned for the handler to set as cookies (Sessions.Replace): the user
// stays signed in, a copy of the old cookie does not. It also ends the limit of a temporary password
// (D-180): the statement that stores the hash clears core_user.temp_password_expires_at.
func (s *Service) ChangeOwnPassword(ctx context.Context, userID, currentSessionID, current, next string) (Issued, error) {
	t, err := coredb.New(s.db.Reader()).GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return Issued{}, apierr.Unauthenticated()
	}
	if err != nil {
		return Issued{}, fmt.Errorf("auth: read user: %w", err)
	}
	if err := s.checkOwnPassword(ctx, t, current, "The current password is wrong."); err != nil {
		return Issued{}, err
	}
	if e := ValidatePassword(next, t.Email); e != nil {
		return Issued{}, e
	}
	if next == current {
		return Issued{}, apierr.New(400, CodeSamePassword, "The new password must differ from the current one.")
	}
	hash, err := s.hashPassword(ctx, next)
	if err != nil {
		return Issued{}, err
	}
	return write(ctx, s.db, func(tx *sql.Tx) (Issued, *apierr.Error, error) {
		q := coredb.New(tx)
		// The password was checked and the new one hashed outside this transaction: an administrator's
		// reset (or this user's other request) may have changed it since. Then this request is stale and
		// must not overwrite the newer password. The caller must also still be who they were: not
		// disabled, and the session they act from not ended.
		if refusal, err := s.callerRefusal(ctx, q, t.ID, currentSessionID); refusal != nil || err != nil {
			return Issued{}, refusal, err
		}
		n, err := q.ChangeUserPassword(ctx, coredb.ChangeUserPasswordParams{PasswordHash: hash, ID: t.ID, CredVersion: t.CredVersion})
		if err != nil {
			return Issued{}, nil, fmt.Errorf("auth: set password: %w", err)
		}
		if n == 0 {
			return Issued{}, passwordMoved(), nil
		}
		fresh, err := s.Sessions.Replace(ctx, tx, t.ID, currentSessionID)
		if err != nil {
			return Issued{}, nil, err
		}
		detail := ""
		if t.TempPasswordExpiresAt != nil {
			detail = "temporary password replaced"
		}
		return fresh, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.password", Target: t.Email, Detail: detail})
	})
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

// adminRefusal is callerRefusal for an administrator's action on someone else's account: besides the
// account not being disabled and the session being alive, the actor must still be an administrator (a role
// change that committed meanwhile wins). Nothing has been written when it returns a refusal.
func (s *Service) adminRefusal(ctx context.Context, q *coredb.Queries, actorID, actorSessionID string) (*apierr.Error, error) {
	if refusal, err := s.callerRefusal(ctx, q, actorID, actorSessionID); refusal != nil || err != nil {
		return refusal, err
	}
	cur, err := q.GetUserByID(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("auth: read user: %w", err)
	}
	if routes.Role(cur.Role) != routes.Admin {
		return apierr.Forbidden(), nil
	}
	return nil, nil
}

// CheckAdmin is adminRefusal inside the caller's transaction, for the operations that write through
// their own transaction (creating a user): it returns the refusal as an error, nil when the actor may go on.
func (s *Service) CheckAdmin(ctx context.Context, tx *sql.Tx, actorID, actorSessionID string) error {
	refusal, err := s.adminRefusal(ctx, coredb.New(tx), actorID, actorSessionID)
	if err != nil {
		return err
	}
	if refusal != nil {
		return refusal
	}
	return nil
}

// checkOwnPassword verifies the password of a signed-in user for a sensitive change (turning two-step on or
// off, changing the password). Wrong guesses have their own per-account limiter (accountKey, with the
// sign-in limits and wait; a signed-in caller's IP is not the point and it is not the sign-in counter of
// the account); a guess is counted before it is checked so parallel guesses cannot all pass, and the count
// goes away on the right password. A wrong password writes auth.reauth_failed, so a stolen session that
// guesses the password leaves a trace for the administrator like a wrong sign-in does.
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
		if aerr := s.db.Write(ctx, func(tx *sql.Tx) error {
			return s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "auth.reauth_failed", Target: t.Email, Detail: "wrong password"})
		}); aerr != nil {
			return aerr
		}
		return apierr.New(400, CodeWrongPassword, wrongMsg)
	}
	s.limit.reset(accountKey, t.Email)
	return nil
}

// ListUsers returns every account, oldest first (GET /core/users, admin).
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := coredb.New(s.db.Reader()).ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	out := make([]User, len(rows))
	for i, r := range rows {
		out[i] = userFrom(r)
	}
	return out, nil
}

// UpdateOwnName changes the display name of the signed-in user (PATCH /core/account): 1 to 80 characters,
// no control characters (400 invalid_name). The account must not be disabled and the session (keepSessionID)
// must still be live when the name is written.
func (s *Service) UpdateOwnName(ctx context.Context, userID, keepSessionID, name string) error {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 80 || !utf8.ValidString(name) || HasInvisible(name) {
		return apierr.New(400, CodeInvalidName, "Enter a display name (at most 80 characters).")
	}
	_, err := write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		q := coredb.New(tx)
		if refusal, err := s.callerRefusal(ctx, q, userID, keepSessionID); refusal != nil || err != nil {
			return struct{}{}, refusal, err
		}
		t, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read user: %w", err)
		}
		if _, err := q.UpdateUserName(ctx, coredb.UpdateUserNameParams{Name: name, ID: userID}); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: set name: %w", err)
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: t.Email, Action: "account.profile", Target: t.Email, Detail: "display name changed"})
	})
	return err
}

// NewTempCredential makes a random temporary password for an account an administrator creates, and its
// hash (computed under the argon2 concurrency cap, outside any transaction). The caller shows the password
// once and stores only the hash.
func (s *Service) NewTempCredential(ctx context.Context) (password, hash string, err error) {
	password, err = NewTempPassword()
	if err != nil {
		return "", "", err
	}
	hash, err = s.hashPassword(ctx, password)
	if err != nil {
		return "", "", err
	}
	return password, hash, nil
}
