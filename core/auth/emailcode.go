package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Email two-step codes (D-35, INV-8).
const (
	CodeTTL          = 10 * time.Minute
	MaxCodeTries     = 5
	ResendAfter      = 60 // seconds between two sends
	MaxSendsPerHour  = 5
	mailSendDeadline = 20 * time.Second
)

// Sent is the result of sending a code.
type Sent struct {
	SentTo      string // masked address, a•••@acme.example
	ResendAfter int    // seconds until another code may be asked for
}

// MaskEmail keeps the first character of the name and the whole domain: enough for a person to recognise
// their own mailbox, not enough to enumerate it.
func MaskEmail(email string) string {
	local, domain, _ := strings.Cut(email, "@")
	first := ""
	for _, r := range local {
		first = string(r)
		break
	}
	return first + "•••@" + domain
}

// EmailCodes issues and checks the one pending email code of a user (core_email_code).
type EmailCodes struct {
	db     *store.DB
	mailer CodeMailer
	now    func() time.Time
	log    *slog.Logger
}

// Available reports whether codes can be mailed now (a mailer exists and says so).
func (c *EmailCodes) Available(ctx context.Context) bool {
	return c.mailer != nil && c.mailer.Available(ctx)
}

func errEmailUnavailable() *apierr.Error {
	return apierr.New(503, CodeEmailUnavailable, emailUnavailableMsg)
}

func tooSoon(wait int) *apierr.Error {
	return apierr.New(429, CodeResendTooSoon, fmt.Sprintf("Wait %d seconds before asking for a new code.", wait)).With("retry_after", wait)
}

func randomCode() (string, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("auth: random code: %w", err)
		}
		// Reject the top sliver of the uint32 range so that n % 1e6 is uniform.
		if n := binary.BigEndian.Uint32(b[:]); n < 4_294_000_000 {
			return fmt.Sprintf("%06d", n%1_000_000), nil
		}
	}
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// Send mails a new code to the user. When mail cannot be sent it fails with 503 twofa_email_unavailable
// before changing anything. With reuseFresh (the sign-in page, which may be reloaded), a code sent less than
// 60 s ago is kept and nothing is sent. Otherwise a code asked for within 60 s of the last is 429
// resend_too_soon (retry_after), and a sixth code within an hour is 429 too_many_codes.
// If the mailer fails after the code was stored, the code and the send record are removed again: a failed
// send does not use up one of the five.
func (c *EmailCodes) Send(ctx context.Context, userID, email string, reuseFresh bool) (Sent, error) {
	if !c.Available(ctx) {
		return Sent{}, errEmailUnavailable()
	}
	now := c.now()
	nowS := store.FormatTS(now)
	type issued struct {
		sent Sent
		code string // empty when an earlier code was kept
		hash string
	}
	res, err := write(ctx, c.db, func(tx *sql.Tx) (issued, *apierr.Error, error) {
		q := coredb.New(tx)
		cur, err := q.GetEmailCode(ctx, userID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return issued{}, nil, fmt.Errorf("auth: read email code: %w", err)
		default:
			sentAt := parseTS(cur.SentAt)
			if age := now.Sub(sentAt); age >= 0 && age < ResendAfter*time.Second {
				wait := int((ResendAfter*time.Second - age + time.Second - 1) / time.Second)
				if reuseFresh && nowS < cur.ExpiresAt {
					return issued{sent: Sent{SentTo: MaskEmail(email), ResendAfter: wait}}, nil, nil
				}
				return issued{}, tooSoon(wait), nil
			}
		}
		n, err := q.CountEmailCodeSendsSince(ctx, coredb.CountEmailCodeSendsSinceParams{UserID: userID, SentAt: store.FormatTS(now.Add(-time.Hour))})
		if err != nil {
			return issued{}, nil, fmt.Errorf("auth: count sends: %w", err)
		}
		if n >= MaxSendsPerHour {
			return issued{}, apierr.New(429, CodeTooManyCodes, "Too many codes were sent in the last hour. Try again later."), nil
		}
		code, err := randomCode()
		if err != nil {
			return issued{}, nil, err
		}
		hash := hashCode(code)
		if err := q.UpsertEmailCode(ctx, coredb.UpsertEmailCodeParams{UserID: userID, CodeHash: hash, ExpiresAt: store.FormatTS(now.Add(CodeTTL)), SentAt: nowS}); err != nil {
			return issued{}, nil, fmt.Errorf("auth: store email code: %w", err)
		}
		if err := q.InsertEmailCodeSend(ctx, coredb.InsertEmailCodeSendParams{UserID: userID, SentAt: nowS}); err != nil {
			return issued{}, nil, fmt.Errorf("auth: record email send: %w", err)
		}
		if err := q.PruneEmailCodeSends(ctx, coredb.PruneEmailCodeSendsParams{UserID: userID, SentAt: store.FormatTS(now.Add(-time.Hour))}); err != nil {
			return issued{}, nil, fmt.Errorf("auth: prune email sends: %w", err)
		}
		return issued{sent: Sent{SentTo: MaskEmail(email), ResendAfter: ResendAfter}, code: code, hash: hash}, nil, nil
	})
	if err != nil {
		return Sent{}, err
	}
	if res.code == "" {
		return res.sent, nil
	}
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailSendDeadline)
	defer cancel()
	if err := c.mailer.SendCode(mctx, email, res.code); err != nil {
		// Never log the code or the address; the mailer's error text is its own business.
		c.log.WarnContext(ctx, "two-step email code could not be sent", "user_id", userID, "error", err)
		undo := c.db.Write(context.WithoutCancel(ctx), func(tx *sql.Tx) error {
			q := coredb.New(tx)
			if err := q.DeleteEmailCodeIfHash(ctx, coredb.DeleteEmailCodeIfHashParams{UserID: userID, CodeHash: res.hash}); err != nil {
				return err
			}
			return q.DeleteEmailCodeSend(ctx, coredb.DeleteEmailCodeSendParams{UserID: userID, SentAt: nowS})
		})
		if undo != nil {
			c.log.ErrorContext(ctx, "could not undo a failed email code send", "user_id", userID, "error", undo)
		}
		return Sent{}, errEmailUnavailable()
	}
	return res.sent, nil
}

// Verify checks a code the user typed. The code is single use and dies after 5 wrong tries; every outcome
// is an *apierr.Error: no_code, code_expired (the code is deleted), invalid_code (not 6 digits; not counted),
// wrong_code (counted; the message says how many tries are left), too_many_tries (the code is deleted).
// A wrong try is saved even though the caller gets an error.
func (c *EmailCodes) Verify(ctx context.Context, userID, input string) error {
	input = strings.Join(strings.Fields(input), "")
	now := c.now()
	_, err := write(ctx, c.db, func(tx *sql.Tx) (struct{}, *apierr.Error, error) {
		q := coredb.New(tx)
		cur, err := q.GetEmailCode(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return struct{}{}, apierr.New(400, CodeNoCode, "No code is waiting. Ask for a new code."), nil
		}
		if err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: read email code: %w", err)
		}
		if store.FormatTS(now) > cur.ExpiresAt {
			if err := q.DeleteEmailCode(ctx, userID); err != nil {
				return struct{}{}, nil, fmt.Errorf("auth: delete email code: %w", err)
			}
			return struct{}{}, apierr.New(400, CodeCodeExpired, "This code has expired. Ask for a new code."), nil
		}
		if !isSixDigits(input) {
			return struct{}{}, apierr.New(400, CodeInvalidCode, "The code is 6 digits."), nil
		}
		if subtle.ConstantTimeCompare([]byte(hashCode(input)), []byte(cur.CodeHash)) == 1 {
			if err := q.DeleteEmailCode(ctx, userID); err != nil {
				return struct{}{}, nil, fmt.Errorf("auth: delete email code: %w", err)
			}
			return struct{}{}, nil, nil
		}
		tries := cur.Tries + 1
		if tries >= MaxCodeTries {
			if err := q.DeleteEmailCode(ctx, userID); err != nil {
				return struct{}{}, nil, fmt.Errorf("auth: delete email code: %w", err)
			}
			return struct{}{}, apierr.New(400, CodeTooManyTries, "Too many wrong codes. Ask for a new code."), nil
		}
		if err := q.SetEmailCodeTries(ctx, coredb.SetEmailCodeTriesParams{Tries: tries, UserID: userID}); err != nil {
			return struct{}{}, nil, fmt.Errorf("auth: count wrong try: %w", err)
		}
		left := MaxCodeTries - tries
		noun := "tries"
		if left == 1 {
			noun = "try"
		}
		return struct{}{}, apierr.New(400, CodeWrongCode, fmt.Sprintf("Wrong code. %d %s left.", left, noun)), nil
	})
	return err
}

// Discard deletes the pending code of a user inside tx (two-step turned off or reset).
func (c *EmailCodes) Discard(ctx context.Context, tx *sql.Tx, userID string) error {
	if err := coredb.New(tx).DeleteEmailCode(ctx, userID); err != nil {
		return fmt.Errorf("auth: delete email code: %w", err)
	}
	return nil
}

func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
