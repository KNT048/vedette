package notify

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/notify/channel"
)

// User sign-ins of the email channel (D-480). A sign-in lives in memory only, belongs to the admin who started it, ends 15 minutes
// after it started, and is used once: SaveChannel takes its refresh token as the channel secret. Nothing of it reaches the browser
// but the user code, the addresses to open and the mailbox.

const (
	maxSignIns = 8
	signinLife = 15 * time.Minute
	// signinGrace keeps an ended sign-in so the page can still read "expired"; then it is dropped with whatever it held.
	signinGrace = time.Minute
	// maxStarts sign-ins per admin per startWindow: each start asks Microsoft for a device code or makes a consent address.
	maxStarts   = 5
	startWindow = 10 * time.Minute
)

// EmailSigninStart is the body of POST /notify/email-signin.
type EmailSigninStart struct {
	Provider     string `json:"provider"`
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// EmailSignin is what the API shows of a sign-in.
type EmailSignin struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Flow            string    `json:"flow"`
	Status          string    `json:"status"`
	UserCode        string    `json:"user_code,omitempty"`
	VerificationURI string    `json:"verification_uri,omitempty"`
	Interval        int       `json:"interval,omitempty"`
	ConsentURL      string    `json:"consent_url,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	Mailbox         string    `json:"mailbox,omitempty"`
}

type emailSignin struct {
	mu                       sync.Mutex // one check at a time
	id, by, provider, tenant string
	client                   string
	device                   *channel.MicrosoftDevice
	consent                  *channel.GoogleConsent
	status                   string
	expires, nextPoll        time.Time
	mailbox                  string
	secret                   secrets.Value
	taken                    bool // a save holds its secret (takeSignin); a second save at the same moment is refused
}

func (e *emailSignin) view() EmailSignin {
	v := EmailSignin{ID: e.id, Provider: e.provider, Status: e.status, ExpiresAt: e.expires, Mailbox: e.mailbox}
	if e.device != nil {
		v.Flow, v.UserCode, v.VerificationURI, v.Interval = "device", e.device.UserCode, e.device.VerificationURI, int(e.device.Interval/time.Second)
	} else {
		v.Flow, v.ConsentURL = "paste", e.consent.URL
	}
	return v
}

type signInSet struct {
	mu     sync.Mutex
	m      map[string]*emailSignin
	starts map[string][]time.Time // per admin, the starts within startWindow
}

// prune drops the sign-ins that ended more than signinGrace ago (their refresh token with them) and the old starts. Hold mu.
func (t *signInSet) prune(now time.Time) {
	for k, o := range t.m {
		if !now.Before(o.expires.Add(signinGrace)) {
			delete(t.m, k)
		}
	}
	for who, l := range t.starts {
		kept := l[:0]
		for _, at := range l {
			if now.Sub(at) < startWindow {
				kept = append(kept, at)
			}
		}
		if t.starts[who] = kept; len(kept) == 0 {
			delete(t.starts, who)
		}
	}
}

var errNoSignin = apierr.New(http.StatusNotFound, "not_found", "This sign-in is over or belongs to another administrator. Start the sign-in again.")

// signinAPIError turns an adapter error into the API answer: a field to fix (400 by its code), or a refusal of the provider
// (400 signin_refused, our sentence).
func signinAPIError(err error) error {
	var si *channel.SignInError
	if errors.As(err, &si) {
		return apierr.New(http.StatusBadRequest, "signin_refused", si.Msg)
	}
	return configAPIError(err)
}

// StartEmailSignin begins a user sign-in (POST /notify/email-signin).
func (s *Service) StartEmailSignin(ctx context.Context, actor string, in EmailSigninStart) (EmailSignin, error) {
	auth, ok := channel.EmailAuth(in.Provider)
	if !ok || (auth != channel.AuthMicrosoftUser && auth != channel.AuthGoogleUser) {
		return EmailSignin{}, badRequest("bad_provider", "Only Microsoft 365, Outlook.com and Gmail sign in this way.")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return EmailSignin{}, fmt.Errorf("notify: sign-in id: %w", err)
	}
	now := s.now()
	s.signIns.mu.Lock()
	s.signIns.prune(now)
	if s.signIns.starts == nil {
		s.signIns.starts = map[string][]time.Time{}
	}
	if len(s.signIns.starts[actor]) >= maxStarts {
		s.signIns.mu.Unlock()
		return EmailSignin{}, apierr.New(http.StatusTooManyRequests, "rate_limited", "You started 5 sign-ins in the last 10 minutes. Finish the last one, or wait a few minutes and try again.")
	}
	s.signIns.starts[actor] = append(s.signIns.starts[actor], now)
	s.signIns.mu.Unlock()
	e := &emailSignin{id: hex.EncodeToString(id[:]), by: actor, provider: in.Provider, client: strings.TrimSpace(in.ClientID), status: channel.SigninWaiting, expires: now.Add(signinLife)}
	if auth == channel.AuthMicrosoftUser {
		e.tenant = strings.TrimSpace(in.TenantID)
		if in.Provider == "outlook" {
			e.tenant = "consumers" // personal Microsoft accounts
		}
		d, err := channel.StartMicrosoftDevice(ctx, s.cfg.HTTPClient, e.tenant, e.client)
		if err != nil {
			return EmailSignin{}, signinAPIError(err)
		}
		e.device, e.nextPoll = d, now.Add(d.Interval)
		if d.ExpiresIn < signinLife {
			e.expires = now.Add(d.ExpiresIn)
		}
	} else {
		g, err := channel.StartGoogleConsent(e.client, strings.TrimSpace(in.ClientSecret))
		if err != nil {
			return EmailSignin{}, signinAPIError(err)
		}
		e.consent = g
	}
	s.signIns.mu.Lock()
	defer s.signIns.mu.Unlock()
	if s.signIns.m == nil {
		s.signIns.m = map[string]*emailSignin{}
	}
	s.signIns.prune(now)
	for k, o := range s.signIns.m {
		if o.by == actor { // one sign-in per admin: a new one replaces the last
			delete(s.signIns.m, k)
		}
	}
	if len(s.signIns.m) >= maxSignIns {
		return EmailSignin{}, apierr.New(http.StatusTooManyRequests, "rate_limited", "Too many sign-ins are open. Wait a few minutes and try again.")
	}
	s.signIns.m[e.id] = e
	return e.view(), nil
}

func (s *Service) signin(actor, id string) (*emailSignin, bool) {
	s.signIns.mu.Lock()
	defer s.signIns.mu.Unlock()
	s.signIns.prune(s.now())
	e, ok := s.signIns.m[id]
	return e, ok && e.by == actor
}

// CheckEmailSignin asks Microsoft once whether the person finished (never before the interval Microsoft gave), or finishes a Google
// sign-in with the pasted address (POST /notify/email-signin/{id}).
func (s *Service) CheckEmailSignin(ctx context.Context, actor, id, pasted string) (EmailSignin, error) {
	e, ok := s.signin(actor, id)
	if !ok {
		return EmailSignin{}, errNoSignin
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := s.now()
	if e.status == channel.SigninWaiting && !now.Before(e.expires) {
		e.status = channel.SigninExpired
	}
	if e.status != channel.SigninWaiting {
		return e.view(), nil
	}
	var in channel.UserSignIn
	if e.device != nil {
		if now.Before(e.nextPoll) {
			return e.view(), nil
		}
		e.nextPoll = now.Add(e.device.Interval) // before the call: a failure (network, an odd refusal) waits the interval too
		st, got, err := e.device.Poll(ctx, s.cfg.HTTPClient)
		if err != nil {
			return EmailSignin{}, signinAPIError(err)
		}
		e.status, e.nextPoll, in = st, now.Add(e.device.Interval), got // slow_down lengthened the interval
	} else {
		got, err := e.consent.Finish(ctx, s.cfg.HTTPClient, pasted)
		var ce *channel.ConfigError
		if errors.As(err, &ce) && ce.Code == "declined" {
			e.status = channel.SigninDeclined
			return e.view(), nil
		}
		if err != nil {
			return EmailSignin{}, signinAPIError(err)
		}
		e.status, in = channel.SigninSignedIn, got
	}
	if e.status == channel.SigninSignedIn {
		e.mailbox, e.secret = in.Mailbox, in.Secret
	}
	return e.view(), nil
}

// takeSignin hands SaveChannel the secret of a finished sign-in of this admin, for these fields, once; it sets the mailbox as the
// username. A sign-in that is unknown, unfinished, already held by another save, or for another provider, client or tenant is
// refused. The sign-in is marked taken at once; release gives it back when the save fails, so the admin can save again.
func (s *Service) takeSignin(actor, id string, fields map[string]string) (secret string, release func(), err error) {
	gone := badRequest("secret_required", "The sign-in is over or does not match these settings. Sign in again, then save.")
	e, ok := s.signin(actor, id)
	if !ok {
		return "", nil, gone
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.taken || e.status != channel.SigninSignedIn || !s.now().Before(e.expires) || e.provider != fields["provider"] || e.client != fields["client_id"] ||
		(e.device != nil && e.provider != "outlook" && e.tenant != fields["tenant_id"]) {
		return "", nil, gone
	}
	e.taken = true
	fields["username"] = e.mailbox
	if e.provider == "outlook" {
		fields["tenant_id"] = "consumers"
	}
	return e.secret.Reveal(), func() { e.mu.Lock(); e.taken = false; e.mu.Unlock() }, nil
}

// forgetSignin drops a sign-in once its secret is saved.
func (s *Service) forgetSignin(id string) {
	s.signIns.mu.Lock()
	delete(s.signIns.m, id)
	s.signIns.mu.Unlock()
}

// rotateEmailSecret keeps a refresh token the provider rotated (channel.EmailConfig.SaveSecret). It runs on its own goroutine: a send
// may happen inside another module's write transaction, where a second DB.Write would wait for the one writer forever. It replaces
// the saved secret when the saved grant is the same sign-in as the sender's (channel.GrantID), whichever refresh token each holds: a
// per-address sender (two-step codes, approvals) may have rotated it in between, and the newest rotation must still be saved. When
// the saved grant is another sign-in (saved again since), it is left alone and the cached sender is dropped, so the next send loads
// the saved one. Microsoft keeps the previous refresh token valid, so a write that fails loses nothing: the next rotation writes again.
// Service has no stop hook: a write cut short when the process ends is lost the same way, and the saved token is still valid.
func (s *Service) rotateEmailSecret(ctx context.Context, old, next secrets.Value) error {
	s.rotations.Add(1)
	ctx = context.WithoutCancel(ctx) // the send that rotated may end before the write
	go func() {
		defer s.rotations.Done()
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			c, err := loadChannel(ctx, tx, channel.Email)
			if err != nil || c.SecretID == "" {
				return err
			}
			cur, err := s.openSecret(ctx, tx, c.SecretID)
			if err != nil {
				return err
			}
			if id := channel.GrantID(cur); id == "" || id != channel.GrantID(old.Reveal()) {
				s.forget(channel.Email) // another sign-in is saved: the cached sender must not keep using its own
				return nil
			}
			_, l4, err := s.putSecret(ctx, tx, purposeSecret, c.SecretID, next.Reveal())
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE notify_channel SET secret_last4 = ? WHERE type = 'email' AND secret_id = ?`, nullable(l4), c.SecretID)
			return err
		})
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "notify: the rotated email sign-in could not be saved; the previous one stays", "error", err.Error())
		}
	}()
	return nil
}

// rotateZaloSecret keeps the grant of a Zalo OA channel after a refresh (D-483): a refresh token works once, so the new one must replace
// the saved one, but only while the saved grant is the same one (same id): an admin who saved a new refresh token meanwhile wins. Like
// rotateEmailSecret it writes on its own goroutine: a send can run inside another module's write transaction.
func (s *Service) rotateZaloSecret(ctx context.Context, old, next secrets.Value) error {
	s.rotations.Add(1)
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer s.rotations.Done()
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			c, err := loadChannel(ctx, tx, channel.Zalo)
			if err != nil || c.SecretID == "" {
				return err
			}
			cur, err := s.openSecret(ctx, tx, c.SecretID)
			if err != nil {
				return err
			}
			was, ok1 := channel.ParseZaloGrant(cur)
			before, ok2 := channel.ParseZaloGrant(old.Reveal())
			after, ok3 := channel.ParseZaloGrant(next.Reveal())
			if !ok1 || !ok2 || !ok3 || was.ID != before.ID {
				s.forget(channel.Zalo) // another grant is saved: the cached sender must not keep using its own
				return nil
			}
			if _, _, err := s.putSecret(ctx, tx, purposeSecret, c.SecretID, next.Reveal()); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE notify_channel SET secret_last4 = ? WHERE type = 'zalo' AND secret_id = ?`, nullable(lastFour(after.RefreshToken)), c.SecretID)
			return err
		})
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "notify: the new Zalo OA refresh token could not be saved; the next refresh tries again", "error", err.Error())
		}
	}()
	return nil
}
