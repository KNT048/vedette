package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Codes of an SSO sign-in that core/auth decides (D-195); the protocol's own (sso_expired, sso_failed) are auth-oidc's.
const (
	CodeNoAccess        = "no_access"
	CodeEmailInUse      = "email_in_use"
	CodeEmailUnverified = "email_unverified"
)

// SSOIdentity is what the auth-oidc module proved about a person: it verified the ID token (signature, iss, aud, azp, exp,
// nonce) before calling SSOSignIn, and mapped the groups to Role. core/auth trusts these fields and nothing else from the IdP.
type SSOIdentity struct {
	Issuer, Subject string
	Email           string
	EmailVerified   *bool // nil: the ID token has no email_verified claim (Entra ID)
	Name            string
	Role            routes.Role // "" = no mapped group and no default role: no access
	IP              netip.Addr
	UserAgent       string
}

// SSOSignIn finds or creates the account of an SSO identity and starts a session like a password sign-in (D-71), in one write
// transaction (D-195, D-196):
//   - the account is keyed by (iss, sub), never by email;
//   - Role "" → 403 no_access, and an existing account's sessions end (leaving the group at the IdP takes effect now);
//   - a new identity: no email or email_verified=false → 403 email_unverified; an email that belongs to a password account, or to
//     an SSO account of the same issuer → 409 email_in_use (never linked); to an SSO account of another issuer (the IdP changed) →
//     re-linked to the new (iss, sub) only when email_verified is true (user.sso_relink); else a new SSO account (user.create SSO);
//   - a disabled account → 403 disabled, whatever the IdP said;
//   - the role follows the groups at every sign-in; a change ends the account's other sessions (user.role "… (SSO groups)");
//   - email and name never change after creation.
//
// Every refusal writes auth.login_failed "SSO: <reason>" in the same transaction as what it changed. No device cookie (D-196 (2)).
func (s *Service) SSOSignIn(ctx context.Context, in SSOIdentity) (Issued, error) {
	if !in.IP.IsValid() {
		return Issued{}, errNoIP()
	}
	if in.Issuer == "" || in.Subject == "" || utf8.RuneCountInString(in.Subject) > 255 || len(in.Issuer) > 2048 {
		return Issued{}, fmt.Errorf("auth: SSO identity without a usable issuer or subject")
	}
	if in.Role != "" && !validRole(in.Role) {
		return Issued{}, fmt.Errorf("auth: SSO role %q is not a role", in.Role)
	}
	email := normalizeEmail(in.Email)
	// A new account gets the hash of a random value nobody holds: password sign-in fails like a wrong password (same timing), and
	// no code path treats the column specially. Hashed before the write so the single writer never waits on argon2.
	var hash string
	if in.Role != "" {
		_, err := coredb.New(s.db.Reader()).GetUserBySSO(ctx, coredb.GetUserBySSOParams{SsoIssuer: &in.Issuer, SsoSubject: &in.Subject})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, hash, err = s.NewTempCredential(ctx); err != nil {
				return Issued{}, err
			}
		case err != nil:
			return Issued{}, fmt.Errorf("auth: look up SSO user: %w", err)
		}
	}
	return write(ctx, s.db, func(tx *sql.Tx) (Issued, *apierr.Error, error) {
		q := coredb.New(tx)
		refuse := func(who, why string, e *apierr.Error) (Issued, *apierr.Error, error) {
			if who == "" {
				who = "unknown"
			}
			if err := s.audit.Append(ctx, tx, audit.Entry{User: who, Action: "auth.login_failed", Target: who, Detail: "SSO: " + why}); err != nil {
				return Issued{}, nil, err
			}
			return Issued{}, e, nil
		}
		u, err := q.GetUserBySSO(ctx, coredb.GetUserBySSOParams{SsoIssuer: &in.Issuer, SsoSubject: &in.Subject})
		found := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Issued{}, nil, fmt.Errorf("auth: look up SSO user: %w", err)
		}
		if in.Role == "" {
			who := email
			if found {
				who = u.Email
				if _, err := s.Sessions.RevokeAllForUser(ctx, tx, u.ID); err != nil {
					return Issued{}, nil, err
				}
			}
			return refuse(who, "no_access", apierr.New(403, CodeNoAccess, "Your company account is not in a group that may use Vedette. Ask an administrator."))
		}
		if !found {
			if !emailRE.MatchString(email) || len(email) > 320 || HasInvisible(email) || (in.EmailVerified != nil && !*in.EmailVerified) {
				return refuse(email, "email_unverified", apierr.New(403, CodeEmailUnverified, "Your identity provider says this email address is not verified. Verify it there, or ask an administrator."))
			}
			inUse := apierr.New(409, CodeEmailInUse, "A Vedette account already uses "+email+" and does not belong to this SSO identity. Use another email at the identity provider, or ask an administrator.")
			same, err := q.GetUserByEmail(ctx, email)
			switch {
			case err == nil:
				if same.SsoIssuer == nil || *same.SsoIssuer == in.Issuer || in.EmailVerified == nil || !*in.EmailVerified {
					return refuse(email, "email_in_use", inUse)
				}
				if n, err := q.RelinkSSOUser(ctx, coredb.RelinkSSOUserParams{SsoIssuer: &in.Issuer, SsoSubject: &in.Subject, ID: same.ID}); err != nil || n == 0 {
					if err == nil {
						err = errors.New("no row")
					}
					return Issued{}, nil, fmt.Errorf("auth: relink SSO user: %w", err)
				}
				if err := s.audit.Append(ctx, tx, audit.Entry{User: email, Action: "user.sso_relink", Target: email, Detail: "from " + *same.SsoIssuer + " to " + in.Issuer}); err != nil {
					return Issued{}, nil, err
				}
				u = same
			case errors.Is(err, sql.ErrNoRows):
				if hash == "" { // the account was deleted between the read above and this write; never insert without a hash
					return Issued{}, nil, errors.New("auth: SSO user vanished while signing in")
				}
				id := store.NewID("u")
				now := store.FormatTS(s.now())
				err := q.InsertSSOUser(ctx, coredb.InsertSSOUserParams{ID: id, Name: ssoName(in.Name, email), Email: email, Role: string(in.Role), PasswordHash: hash, CreatedAt: now, SsoIssuer: &in.Issuer, SsoSubject: &in.Subject})
				if store.IsUniqueViolation(err) { // a parallel first sign-in of the same identity or email
					return refuse(email, "email_in_use", inUse)
				}
				if err != nil {
					return Issued{}, nil, fmt.Errorf("auth: insert SSO user: %w", err)
				}
				if err := s.audit.Append(ctx, tx, audit.Entry{User: email, Action: "user.create", Target: email, Detail: "SSO, role " + string(in.Role)}); err != nil {
					return Issued{}, nil, err
				}
				if u, err = q.GetUserByID(ctx, id); err != nil {
					return Issued{}, nil, fmt.Errorf("auth: re-read SSO user: %w", err)
				}
			default:
				return Issued{}, nil, fmt.Errorf("auth: look up email: %w", err)
			}
		}
		if u.Disabled != 0 {
			return refuse(u.Email, "disabled", disabledError())
		}
		if u.Role != string(in.Role) {
			if _, err := q.UpdateUserRole(ctx, coredb.UpdateUserRoleParams{Role: string(in.Role), ID: u.ID}); err != nil {
				return Issued{}, nil, fmt.Errorf("auth: set SSO role: %w", err)
			}
			if _, err := s.Sessions.RevokeAllForUser(ctx, tx, u.ID); err != nil {
				return Issued{}, nil, err
			}
			if err := s.audit.Append(ctx, tx, audit.Entry{User: u.Email, Action: "user.role", Target: u.Email, Detail: u.Role + " to " + string(in.Role) + " (SSO groups)"}); err != nil {
				return Issued{}, nil, err
			}
		}
		now := store.FormatTS(s.now())
		if err := q.UpdateUserLastLogin(ctx, coredb.UpdateUserLastLoginParams{LastLogin: &now, ID: u.ID}); err != nil {
			return Issued{}, nil, fmt.Errorf("auth: set last_login: %w", err)
		}
		sess, err := s.Sessions.Create(ctx, tx, u.ID, in.UserAgent, in.IP)
		if err != nil {
			return Issued{}, nil, err
		}
		if err := s.audit.Append(ctx, tx, audit.Entry{User: u.Email, Action: "auth.login", Target: u.Email, Detail: "SSO"}); err != nil {
			return Issued{}, nil, err
		}
		return sess, nil, nil
	})
}

// RefuseSSO writes auth.login_failed "SSO: <why>" for a sign-in that failed before an identity was proved (state, binding,
// token, id_token): who is the issuer, since nobody is known yet.
func (s *Service) RefuseSSO(ctx context.Context, issuer, why string) error {
	return s.auditFailure(ctx, issuer, issuer, "SSO: "+why)
}

// CountSSOUsers is the number of accounts that sign in only through SSO (OidcConfig.sso_users).
func (s *Service) CountSSOUsers(ctx context.Context) (int, error) {
	n, err := coredb.New(s.db.Reader()).CountSSOUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("auth: count SSO users: %w", err)
	}
	return int(n), nil
}

// ssoName is the display name of a new SSO account: the IdP's name when it is a valid name (ValidateUserFields), else the part
// of the email before @. The IdP's name is not trusted text (SYS-6).
func ssoName(name, email string) string {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > 80 {
		name = string([]rune(name)[:80])
	}
	if n := utf8.RuneCountInString(name); n >= 1 && utf8.ValidString(name) && !HasInvisible(name) {
		return name
	}
	local, _, _ := strings.Cut(email, "@")
	if utf8.RuneCountInString(local) > 80 {
		local = string([]rune(local)[:80])
	}
	return local
}
