package notify

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Approval tokens (docs/specs/approval-tokens.md §4, D-46, D-57 item 20): the
// link in an approval email carries
//
//	v1.<base64url(token_id)>.<base64url(mac)>
//	token_id = 16 random bytes
//	mac      = first 16 bytes of HMAC-SHA256(K_approval,
//	           "vedette-approval-v1\n" token_id "\n" request_id "\n" user_id "\n" channel "\n" expires_unix)
//
// The token only proves "this box minted it for exactly this request, person,
// channel and expiry". Whether it was used, and every other state, lives in the
// database record found by token_id; the binding (request, user, channel,
// expiry) is read from that record and passed to Verify. Opening the page (GET)
// calls Verify; only the POST of the decision calls Consume.

const (
	approvalTokenVersion = "v1."
	approvalMACPrefix    = "vedette-approval-v1\n"
	// ApprovalTTL is the lifetime of an email or Zalo OA approval link (D-46).
	ApprovalTTL = 30 * time.Minute
	// MinApprovalKeyLen is the shortest accepted K_approval (256 bits).
	MinApprovalKeyLen = 32
	macLen            = 16
	tokenIDLen        = 16
	tokenLen          = len(approvalTokenVersion) + 22 + 1 + 22 // base64url of 16 bytes is 22 characters
)

// Errors of the token functions. ErrTokenInvalid covers a malformed token, a
// wrong MAC and any binding mismatch alike: the HTTP layer answers all of them
// with the same 404 "unknown" (spec §10) so nothing can be probed.
var (
	ErrTokenInvalid     = errors.New("notify: approval token is not valid")
	ErrTokenExpired     = errors.New("notify: approval token has expired")
	ErrTokenUsed        = errors.New("notify: approval token was already used")
	ErrBadBinding       = errors.New("notify: invalid approval token binding")
	ErrKeyTooShort      = errors.New("notify: approval key must be at least 32 bytes")
	ErrHighRiskViaEmail = errors.New("notify: high-risk actions cannot be approved by email; use the app with two-step sign-in")
)

// TokenID identifies a token record (the database stores its hash).
type TokenID [tokenIDLen]byte

// String is the lowercase hex form, for in-memory keys and database lookups.
// Never log it: it identifies a live token record.
func (id TokenID) String() string { return fmt.Sprintf("%x", id[:]) }

// Binding is what a token is bound to.
type Binding struct {
	RequestID string    // the action request
	UserID    string    // the Vedette user who may approve (one token per approver)
	Channel   string    // "email" or "zalo": the channels that carry a link
	ExpiresAt time.Time // min(mint time + 30 min, request expiry)
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,128}$`)

// check validates the binding. Identifiers use a restricted alphabet, so the
// "\n"-joined MAC input can never be ambiguous.
func (b Binding) check() error {
	if !idRE.MatchString(b.RequestID) || !idRE.MatchString(b.UserID) || (b.Channel != "email" && b.Channel != "zalo") || b.ExpiresAt.Unix() <= 0 {
		return ErrBadBinding
	}
	return nil
}

// ApprovalExpiry returns the expiry for a token minted now for a request that
// expires at requestExpires: 30 minutes, never beyond the request (spec §3.2).
func ApprovalExpiry(now, requestExpires time.Time) time.Time {
	if e := now.Add(ApprovalTTL); e.Before(requestExpires) {
		return e
	}
	return requestExpires
}

// Risk is the risk level of an action request.
type Risk string

// Risk levels.
const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// ApprovalViaChannelAllowed reports whether a request of the given risk may be
// approved from channel (D-57 item 20): high risk never over a link channel
// (email, zalo), because a link is a bearer credential. An unknown risk is
// treated as high. Core calls it again when the decision arrives (spec §3.5).
func ApprovalViaChannelAllowed(channel string, risk Risk) error {
	if (channel == "email" || channel == "zalo") && risk != RiskLow && risk != RiskMedium {
		return ErrHighRiskViaEmail
	}
	return nil
}

func mac(key []byte, id TokenID, b Binding) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(approvalMACPrefix))
	h.Write(id[:])
	h.Write([]byte("\n" + b.RequestID + "\n" + b.UserID + "\n" + b.Channel + "\n" + strconv.FormatInt(b.ExpiresAt.Unix(), 10)))
	return h.Sum(nil)[:macLen]
}

func encode(id TokenID, m []byte) string {
	e := base64.RawURLEncoding
	return approvalTokenVersion + e.EncodeToString(id[:]) + "." + e.EncodeToString(m)
}

// MintApprovalToken creates a token for b. The caller stores the TokenID with
// the binding and the key id. It refuses a key shorter than 32 bytes, a binding
// outside the alphabet, an expiry that is not in the future or is more than 30
// minutes away, and (D-57 item 20) a high-risk request for the email channel.
func MintApprovalToken(key []byte, b Binding, risk Risk, now time.Time) (string, TokenID, error) {
	var id TokenID
	if len(key) < MinApprovalKeyLen {
		return "", id, ErrKeyTooShort
	}
	if err := b.check(); err != nil {
		return "", id, err
	}
	if !b.ExpiresAt.After(now) || b.ExpiresAt.After(now.Add(ApprovalTTL)) {
		return "", id, fmt.Errorf("%w: expiry must be within the next 30 minutes", ErrBadBinding)
	}
	if err := ApprovalViaChannelAllowed(b.Channel, risk); err != nil {
		return "", id, err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return "", id, fmt.Errorf("notify: mint approval token: %w", err)
	}
	return encode(id, mac(key, id, b)), id, nil
}

// parse splits a token into its id and MAC. It accepts only the canonical
// encoding, so one token has exactly one valid spelling.
func parse(token string) (TokenID, []byte, error) {
	var id TokenID
	if len(token) != tokenLen || !strings.HasPrefix(token, approvalTokenVersion) || token[len(approvalTokenVersion)+22] != '.' {
		return id, nil, ErrTokenInvalid
	}
	e := base64.RawURLEncoding.Strict()
	rawID, err := e.DecodeString(token[len(approvalTokenVersion) : len(approvalTokenVersion)+22])
	if err != nil || len(rawID) != tokenIDLen {
		return id, nil, ErrTokenInvalid
	}
	m, err := e.DecodeString(token[len(approvalTokenVersion)+23:])
	if err != nil || len(m) != macLen {
		return id, nil, ErrTokenInvalid
	}
	copy(id[:], rawID)
	return id, m, nil
}

// ParseApprovalToken returns the token id (to look the record up) after a
// structural check only; it proves nothing about authenticity.
func ParseApprovalToken(token string) (TokenID, error) {
	id, _, err := parse(token)
	return id, err
}

// VerifyApprovalToken checks token against the binding read from its record:
// structure, MAC (constant time) and expiry. It changes nothing, so the GET that
// shows the confirmation page (and any link scanner) can call it freely. key is
// the K_approval named by the record's key id.
func VerifyApprovalToken(key []byte, token string, b Binding, now time.Time) (TokenID, error) {
	id, got, err := parse(token)
	if err != nil {
		return id, err
	}
	if len(key) < MinApprovalKeyLen {
		return id, ErrKeyTooShort
	}
	if b.check() != nil || !hmac.Equal(got, mac(key, id, b)) {
		return id, ErrTokenInvalid
	}
	if !now.Before(b.ExpiresAt) {
		return id, ErrTokenExpired
	}
	return id, nil
}

// NonceStore records consumed tokens. Consume must be atomic and report true
// only for the first call with an id: the database version is the conditional
// "UPDATE … SET used_at = … WHERE token_id = ? AND used_at IS NULL" inside the
// same transaction as the decision (spec §4.3), so two concurrent POSTs have
// exactly one winner.
type NonceStore interface {
	Consume(ctx context.Context, id TokenID) (first bool, err error)
}

// ConsumeApprovalToken is the POST path: verify, then burn the token. A token
// that was already used returns ErrTokenUsed (409 "used").
func ConsumeApprovalToken(ctx context.Context, store NonceStore, key []byte, token string, b Binding, now time.Time) (TokenID, error) {
	id, err := VerifyApprovalToken(key, token, b, now)
	if err != nil {
		return id, err
	}
	first, err := store.Consume(ctx, id)
	if err != nil {
		return id, fmt.Errorf("notify: consume approval token: %w", err)
	}
	if !first {
		return id, ErrTokenUsed
	}
	return id, nil
}
