package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Cookie and header names (API_CONVENTIONS 7.1, 7.2). These are the only cookies Vedette sets (INV-9).
const (
	CookieSession = "vedette_session"
	CookieCSRF    = "vedette_csrf"
	HeaderCSRF    = "X-CSRF-Token"
)

// Session lifetimes (decision D-71): a session ends after 4 hours without a request or 7 days after sign-in,
// whichever comes first. last_seen is refreshed at most once a minute, so a request storm does not write.
const (
	IdleTimeout     = 4 * time.Hour
	AbsoluteTimeout = 7 * 24 * time.Hour
	touchEvery      = time.Minute
)

// tokenBytes is the size of the session and CSRF tokens (256 bits); encoded as unpadded base64url = 43 characters.
const tokenBytes = 32

var tokenEnc = base64.RawURLEncoding

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return tokenEnc.EncodeToString(b), nil
}

// hashToken is the stored form of a token: lowercase hex SHA-256. Tokens are 256-bit random, so a plain
// hash is enough (no salt or stretching needed).
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func validTokenShape(t string) bool {
	if len(t) != tokenEnc.EncodedLen(tokenBytes) {
		return false
	}
	_, err := tokenEnc.DecodeString(t)
	return err == nil
}

// Issued is a new session: the values the handler puts in the two cookies. The tokens exist only here;
// the database keeps their hashes.
type Issued struct {
	SessionID string
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

// Cookies returns the vedette_session (HttpOnly) and vedette_csrf (readable by the SPA) cookies:
// Secure, SameSite=Strict, Path=/, no Domain, living as long as the absolute timeout.
func (i Issued) Cookies() []*http.Cookie {
	maxAge := int(AbsoluteTimeout.Seconds()) // Issued is returned the moment the session is created
	return []*http.Cookie{cookie(CookieSession, i.Token, true, maxAge), cookie(CookieCSRF, i.CSRFToken, false, maxAge)}
}

// ClearCookies returns the cookies that delete both cookies in the browser.
func ClearCookies() []*http.Cookie {
	return []*http.Cookie{cookie(CookieSession, "", true, -1), cookie(CookieCSRF, "", false, -1)}
}

func cookie(name, value string, httpOnly bool, maxAge int) *http.Cookie {
	if maxAge == 0 {
		maxAge = -1
	}
	// The CSRF cookie is readable by the SPA on purpose (it copies it into X-CSRF-Token); it is worthless without the session cookie.
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: httpOnly, Secure: true, SameSite: http.SameSiteStrictMode} //nolint:gosec // see above
}

// Sessions stores and checks sessions. It implements server.Authenticator.
type Sessions struct {
	db    *store.DB
	audit *audit.Log
	now   func() time.Time
	log   *slog.Logger
}

var _ server.Authenticator = (*Sessions)(nil)

// Create inserts a session for userID inside tx and returns its tokens. device is the User-Agent (cleaned
// and cut to 200 characters), ip the client address.
func (s *Sessions) Create(ctx context.Context, tx *sql.Tx, userID, device, ip string) (Issued, error) {
	tok, err := newToken()
	if err != nil {
		return Issued{}, err
	}
	csrf, err := newToken()
	if err != nil {
		return Issued{}, err
	}
	now := s.now()
	in := Issued{SessionID: store.NewID("ses"), Token: tok, CSRFToken: csrf, ExpiresAt: now.Add(AbsoluteTimeout)}
	err = coredb.New(tx).InsertSession(ctx, coredb.InsertSessionParams{
		ID: in.SessionID, UserID: userID, TokenHash: hashToken(tok), CsrfHash: hashToken(csrf),
		Device: cleanDevice(device), Ip: normalizeIP(ip),
		StartedAt: store.FormatTS(now), LastSeen: store.FormatTS(now), ExpiresAt: store.FormatTS(in.ExpiresAt),
	})
	if err != nil {
		return Issued{}, fmt.Errorf("auth: insert session: %w", err)
	}
	return in, nil
}

// Info is a session as listed in My account.
type Info struct {
	ID        string
	Device    string
	IP        string
	StartedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// Found is what Lookup knows about a valid session.
type Found struct {
	ID        string
	UserID    string
	Email     string
	Role      routes.Role
	StartedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	csrfHash  string
}

// Lookup resolves a session cookie value. An unknown, malformed, revoked, expired or idle session is
// server.ErrNoSession; a session of a disabled user is 403 disabled. The role is read from the database
// here, on every call (API_CONVENTIONS 7.4). last_seen is refreshed when it is a minute old.
func (s *Sessions) Lookup(ctx context.Context, token string) (Found, error) {
	if !validTokenShape(token) {
		return Found{}, server.ErrNoSession
	}
	r, err := coredb.New(s.db.Reader()).GetSessionByTokenHash(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return Found{}, server.ErrNoSession
	}
	if err != nil {
		return Found{}, fmt.Errorf("auth: look up session: %w", err)
	}
	now := s.now()
	if r.RevokedAt != nil || r.ExpiresAt <= store.FormatTS(now) || r.LastSeen <= store.FormatTS(now.Add(-IdleTimeout)) {
		return Found{}, server.ErrNoSession
	}
	if r.Disabled != 0 {
		return Found{}, apierr.New(403, CodeDisabled, "This account has been disabled.")
	}
	role := routes.Role(r.Role)
	if role != routes.Viewer && role != routes.Operator && role != routes.Admin {
		return Found{}, fmt.Errorf("auth: user %s has unknown role %q", r.UserID, r.Role)
	}
	if r.LastSeen <= store.FormatTS(now.Add(-touchEvery)) {
		// Best effort: failing to refresh last_seen must not sign the user out.
		err := s.db.Write(ctx, func(tx *sql.Tx) error {
			return coredb.New(tx).TouchSession(ctx, coredb.TouchSessionParams{LastSeen: store.FormatTS(now), ID: r.ID})
		})
		if err != nil {
			s.log.WarnContext(ctx, "could not refresh session last_seen", "error", err)
		}
	}
	return Found{
		ID: r.ID, UserID: r.UserID, Email: r.Email, Role: role,
		StartedAt: parseTS(r.StartedAt), LastSeen: parseTS(r.LastSeen), ExpiresAt: parseTS(r.ExpiresAt), csrfHash: r.CsrfHash,
	}, nil
}

func tokenFrom(r *http.Request) (string, error) {
	c, err := r.Cookie(CookieSession)
	if err != nil {
		return "", server.ErrNoSession
	}
	return c.Value, nil
}

// Authenticate implements server.Authenticator.
func (s *Sessions) Authenticate(r *http.Request) (server.Principal, error) {
	tok, err := tokenFrom(r)
	if err != nil {
		return server.Principal{}, err
	}
	f, err := s.Lookup(r.Context(), tok)
	if err != nil {
		return server.Principal{}, err
	}
	return server.Principal{ID: f.UserID, Email: f.Email, Role: f.Role}, nil
}

// CheckCSRF implements server.Authenticator: the X-CSRF-Token header must hash to the session's csrf_hash
// (constant-time compare). The session is looked up again because Authenticate returns only the principal.
func (s *Sessions) CheckCSRF(r *http.Request, p server.Principal) error {
	tok, err := tokenFrom(r)
	if err != nil {
		return apierr.CSRFInvalid()
	}
	f, err := s.Lookup(r.Context(), tok)
	if err != nil {
		return apierr.CSRFInvalid()
	}
	h := r.Header.Get(HeaderCSRF)
	if f.UserID != p.ID || !validTokenShape(h) || subtle.ConstantTimeCompare([]byte(hashToken(h)), []byte(f.csrfHash)) != 1 {
		return apierr.CSRFInvalid()
	}
	return nil
}

// CurrentID returns the id of the session the request belongs to (for "this is your current session"
// and the 400 current_session rule), or server.ErrNoSession.
func (s *Sessions) CurrentID(r *http.Request) (string, error) {
	tok, err := tokenFrom(r)
	if err != nil {
		return "", err
	}
	f, err := s.Lookup(r.Context(), tok)
	return f.ID, err
}

// List returns the live sessions of a user, newest first.
func (s *Sessions) List(ctx context.Context, userID string) ([]Info, error) {
	now := s.now()
	rows, err := coredb.New(s.db.Reader()).ListSessions(ctx, coredb.ListSessionsParams{
		UserID: userID, ExpiresAt: store.FormatTS(now), LastSeen: store.FormatTS(now.Add(-IdleTimeout)),
	})
	if err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}
	out := make([]Info, len(rows))
	for i, r := range rows {
		out[i] = Info{ID: r.ID, Device: r.Device, IP: r.Ip, StartedAt: parseTS(r.StartedAt), LastSeen: parseTS(r.LastSeen), ExpiresAt: parseTS(r.ExpiresAt)}
	}
	return out, nil
}

// Revoke ends one session of userID (DELETE /core/account/sessions/{id}) and writes auth.session_revoke.
// A session that does not exist, is already ended or belongs to someone else is apierr.NotFound.
// Refusing to end the caller's own session (400 current_session) is the handler's job: see CurrentID.
func (s *Sessions) Revoke(ctx context.Context, actorEmail, userID, sessionID string) error {
	_, err := write(ctx, s.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		n, err := coredb.New(tx).RevokeSession(ctx, coredb.RevokeSessionParams{RevokedAt: ptr(store.FormatTS(s.now())), ID: sessionID, UserID: userID})
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: revoke session: %w", err)
		}
		if n == 0 {
			return struct{}{}, apierr.NotFound(), nil
		}
		return struct{}{}, nil, s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: "auth.session_revoke", Target: actorEmail})
	})
	return err
}

// RevokeOthers ends every live session of userID except keepID and returns how many ended.
func (s *Sessions) RevokeOthers(ctx context.Context, actorEmail, userID, keepID string) (int, error) {
	return write(ctx, s.db, func(tx *sql.Tx) (int, *apierr.Error, error) {
		n, err := coredb.New(tx).RevokeOtherSessions(ctx, coredb.RevokeOtherSessionsParams{RevokedAt: ptr(store.FormatTS(s.now())), UserID: userID, ID: keepID})
		if err != nil {
			return 0, nil, fmt.Errorf("auth: revoke other sessions: %w", err)
		}
		return int(n), nil, s.audit.Append(ctx, tx, audit.Entry{User: actorEmail, Action: "auth.sessions_revoke_others", Target: actorEmail, Detail: fmt.Sprintf("%d ended", n)})
	})
}

// RevokeAllForUser ends every live session of userID inside the caller's transaction (password reset,
// disabling an account, INV-7) and returns how many ended. The caller writes the audit row.
func (s *Sessions) RevokeAllForUser(ctx context.Context, tx *sql.Tx, userID string) (int, error) {
	n, err := coredb.New(tx).RevokeAllSessions(ctx, coredb.RevokeAllSessionsParams{RevokedAt: ptr(store.FormatTS(s.now())), UserID: userID})
	if err != nil {
		return 0, fmt.Errorf("auth: revoke sessions: %w", err)
	}
	return int(n), nil
}

// Logout ends the session of a cookie value and writes auth.logout. A missing, unknown or already ended
// session is not an error (POST /auth/logout never fails because the session ran out).
func (s *Sessions) Logout(ctx context.Context, token string) error {
	if !validTokenShape(token) {
		return nil
	}
	r, err := coredb.New(s.db.Reader()).GetSessionByTokenHash(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auth: look up session: %w", err)
	}
	if r.RevokedAt != nil {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		n, err := coredb.New(tx).RevokeSession(ctx, coredb.RevokeSessionParams{RevokedAt: ptr(store.FormatTS(s.now())), ID: r.ID, UserID: r.UserID})
		if err != nil || n == 0 {
			return err
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: r.Email, Action: "auth.logout", Target: r.Email})
	})
}

func ptr[T any](v T) *T { return &v }
