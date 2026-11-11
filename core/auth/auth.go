// Package auth is the sign-in library of the core module: argon2id passwords, cookie sessions with CSRF
// tokens (implementing server.Authenticator), TOTP and email two-step codes, the login rate limit, the
// Login flow of core INV-8 and the user and two-step rules of INV-7. The HTTP handlers (WP-04b part 2)
// are thin: they decode a request, call this package and encode the result.
//
// Conventions: errors meant for the client are *apierr.Error (the codes of docs/API_CONVENTIONS.md 3.3);
// anything else is an internal failure for the handler to log and turn into a 500. Every mutation writes
// core_audit in its own transaction (audit.Append); audit details never carry passwords, codes or tokens.
// Methods that take a *sql.Tx run in the caller's transaction (so the caller can add its own changes);
// the others open their own with store.DB.Write. Password and key derivation always happen outside a
// write transaction: the single writer connection is never held for the length of an argon2 run.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// API error codes owned by this package (all listed in docs/API_CONVENTIONS.md 3.3).
const (
	CodeInvalidCredentials = "invalid_credentials" //nolint:gosec // an error code, not a credential
	CodeTwofaRequired      = "twofa_required"
	CodeDisabled           = "disabled"
	CodeEmailUnavailable   = "twofa_email_unavailable"
	CodeInvalidCode        = "invalid_code"
	CodeWrongCode          = "wrong_code"
	CodeNoCode             = "no_code"
	CodeCodeExpired        = "code_expired"
	CodeTooManyTries       = "too_many_tries"
	CodeResendTooSoon      = "resend_too_soon"
	CodeTooManyCodes       = "too_many_codes"
	CodeRateLimited        = "rate_limited"
	CodeWeakPassword       = "weak_password"
	CodeWrongPassword      = "wrong_password"
	CodeSamePassword       = "same_password"
	CodeNotEmailMethod     = "not_email_method"
	CodeAlreadyOn          = "already_on"
	CodeNotOn              = "not_on"
	CodeNoPending          = "no_pending"
	CodeEmailNotReady      = "email_channel_not_ready"
	CodeSelfDisable        = "self_disable"
	CodeSelfReset          = "self_reset"
	CodeLastAdmin          = "last_admin"
	CodeDuplicate          = "duplicate"
	CodeInvalidName        = "invalid_name"
	CodeInvalidEmail       = "invalid_email"
	CodeInvalidRole        = "invalid_role"
	CodeTempExpired        = "temp_password_expired"
	CodeBusy               = "server_busy" // 503: too many password checks at once (the 409 `busy` of the update module is another thing)
)

const emailUnavailableMsg = "Two-step email codes cannot be sent right now. Ask an administrator to turn the email channel back on, or to reset your two-step sign-in."

// CodeMailer sends two-step codes by email. The notify module implements it (core never imports notify,
// FORBID-2); main wires it in. A nil mailer means "unavailable".
type CodeMailer interface {
	// Available reports whether SendCode can work now: notify is on and its email channel is configured and enabled.
	Available(ctx context.Context) bool
	// SendCode mails the 6-digit code to the address. The implementation must not log the code.
	SendCode(ctx context.Context, to, code string) error
}

// StepUpMailer is the optional second interface of a CodeMailer: it mails a step-up code (VerifyTwoStep) with a
// summary of what is being approved, so the message cannot be mistaken for a sign-in code (OWASP Transaction
// Authorization). A mailer without it cannot serve email step-up: VerifyTwoStep answers 503
// twofa_email_unavailable. summary is one line built by the server, never user text; the implementation must not log the code.
type StepUpMailer interface {
	SendStepUpCode(ctx context.Context, to, code, summary string) error
}

// Config wires a Service.
type Config struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Mailer  CodeMailer // nil: email codes are unavailable
	Clock   func() time.Time
	Log     *slog.Logger
	// Argon2 overrides DefaultParams. Tests lower it; production leaves it zero.
	Argon2 Params
	// MaxHashing caps the argon2 runs at once (each takes Argon2.Memory); 0 means half the CPUs this process
	// may use (GOMAXPROCS, so a container quota counts), at least 1, and at most a quarter of the Go memory
	// limit (GOMEMLIMIT) divided by Argon2.Memory.
	MaxHashing int
	// HashWait is how long a request waits for a free slot before 503 server_busy; 0 means 2 s.
	HashWait time.Duration
}

// Service is the auth library. Create it once with New.
type Service struct {
	Sessions *Sessions
	Codes    *EmailCodes

	db      *store.DB
	secrets *secrets.Store
	audit   *audit.Log
	mailer  CodeMailer
	now     func() time.Time
	log     *slog.Logger
	params  Params
	limit   *limiter
	gate    *gate
	dummy   string // a valid hash no password matches, verified against for unknown emails

	auditKeyMu sync.Mutex
	auditKey   []byte // HMAC key of the unknown-email audit target, read from core_secret on first use

	deviceKeyMu sync.Mutex
	deviceKeyV  []byte // HMAC key of the device cookies (D-77), read from core_secret on first use

	pendingTries pendingTries // wrong codes of the pending authenticator key (twofa.go)

	probe func(delta int) // tests only (export_test.go): +1 when an argon2 run starts, -1 when it ends
}

// New builds a Service. DB, Secrets, Audit and Log are required.
func New(c Config) (*Service, error) {
	if c.DB == nil || c.Secrets == nil || c.Audit == nil || c.Log == nil {
		return nil, errors.New("auth: Config needs DB, Secrets, Audit and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Argon2 == (Params{}) {
		c.Argon2 = DefaultParams
	}
	dummy, err := c.Argon2.Hash("dummy password for timing; nobody can sign in with it")
	if err != nil {
		return nil, err
	}
	s := &Service{
		db: c.DB, secrets: c.Secrets, audit: c.Audit, mailer: c.Mailer, now: c.Clock, log: c.Log,
		params: c.Argon2, limit: newLimiter(c.Clock), gate: newGate(c.MaxHashing, c.HashWait, c.Argon2), dummy: dummy,
	}
	s.Sessions = &Sessions{db: c.DB, audit: c.Audit, now: c.Clock, log: c.Log}
	s.Codes = &EmailCodes{db: c.DB, secrets: c.Secrets, mailer: c.Mailer, now: c.Clock, log: c.Log}
	return s, nil
}

// HashPassword applies the password policy for email and hashes with the configured parameters, under the
// argon2 concurrency cap. A policy failure is a 400 weak_password *apierr.Error; a full queue is 503 server_busy.
func (s *Service) HashPassword(ctx context.Context, password, email string) (string, error) {
	if e := ValidatePassword(password, email); e != nil {
		return "", e
	}
	return s.hashPassword(ctx, password)
}

// User is an account as the API shows it (never the password hash).
type User struct {
	ID          string
	Name        string
	Email       string
	Role        routes.Role
	TwofaMethod string // "app", "email" or "" (two-step sign-in off)
	Disabled    bool
	CreatedAt   time.Time
	LastLogin   *time.Time // nil: never signed in
	// PasswordChangeRequired: an administrator set the password and the user has not replaced it yet (D-180).
	PasswordChangeRequired bool
}

// TempPasswordLifetime is how long a password an administrator set can sign in (D-180). core/auth has no other
// one-time credential with a window of hours (email codes and the pending TOTP key last 10 minutes), so the
// window is the 72 hours of the decision.
const TempPasswordLifetime = 72 * time.Hour

// tempExpiry is the text stored in core_user.temp_password_expires_at for a password set now.
func (s *Service) tempExpiry() *string { return ptr(store.FormatTS(s.now().Add(TempPasswordLifetime))) }

// tempExpired reports whether a temporary password (expires != nil) is past its window.
func tempExpired(expires *string, now time.Time) bool {
	return expires != nil && *expires <= store.FormatTS(now)
}

func userFrom(r coredb.CoreUser) User {
	u := User{ID: r.ID, Name: r.Name, Email: r.Email, Role: routes.Role(r.Role), Disabled: r.Disabled != 0, CreatedAt: parseTS(r.CreatedAt), PasswordChangeRequired: r.TempPasswordExpiresAt != nil}
	if r.TwofaMethod != nil {
		u.TwofaMethod = *r.TwofaMethod
	}
	if r.LastLogin != nil {
		t := parseTS(*r.LastLogin)
		u.LastLogin = &t
	}
	return u
}

// GetUser returns an account by id; apierr.NotFound when there is none.
func (s *Service) GetUser(ctx context.Context, id string) (User, error) {
	r, err := coredb.New(s.db.Reader()).GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, apierr.NotFound()
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: get user: %w", err)
	}
	return userFrom(r), nil
}

const tsLayout = "2006-01-02T15:04:05.000Z"

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{} // the column CHECK makes this unreachable
	}
	return t
}

// normalizeEmail trims and lowercases (emails are stored lowercase).
func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// ipText is the canonical text of a client address (IPv4-mapped IPv6 as IPv4, no zone); it is what a
// session row stores. The address must be valid: callers parse r.RemoteAddr with netip.ParseAddrPort and
// refuse to go on when that fails, because there is no address to fall back to that would not be shared.
func ipText(a netip.Addr) string { return a.Unmap().WithZone("").String() }

// ipLimitKeys are the address parts of the (IP, email) rate-limit keys of one request: the address itself
// and, for IPv6, its /64 as well (a host rotates through the addresses of its /64 for free, so the /64 is
// bounded too, at a higher limit: see ratelimit.go).
func ipLimitKeys(a netip.Addr) []string {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		return []string{a.String(), netip.PrefixFrom(a, 64).Masked().String()}
	}
	return []string{a.String()}
}

func errNoIP() error { return errors.New("auth: the client address is missing or not an IP address") }

// cleanDevice makes a User-Agent safe to store and show: control characters dropped, at most 200 characters.
func cleanDevice(ua string) string {
	var b strings.Builder
	n := 0
	for _, r := range ua {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			continue
		}
		if n++; n > 200 {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// write runs fn in a write transaction. fn returns a value, a refusal and an error: a non-nil err rolls
// everything back and is returned as an internal failure; a refusal (an *apierr.Error the client should see)
// is returned AFTER the commit, so what fn saved before refusing (a failed-attempt counter, an audit row)
// is kept.
func write[T any](ctx context.Context, db *store.DB, fn func(tx *sql.Tx) (T, *apierr.Error, error)) (T, error) {
	var out T
	var refusal *apierr.Error
	err := db.Write(ctx, func(tx *sql.Tx) (err error) {
		out, refusal, err = fn(tx)
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	if refusal != nil {
		var zero T
		return zero, refusal
	}
	return out, nil
}
