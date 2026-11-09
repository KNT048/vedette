package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1; authenticator apps only speak it
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"time"
)

// TOTP parameters (RFC 6238 with the defaults every authenticator app uses).
const (
	TOTPPeriod = 30 // seconds per step
	totpDigits = 6
	totpSkew   = 1 // steps accepted either side of now
	// NoStep is the lastStep to pass to VerifyTOTP when no code has been accepted yet.
	NoStep int64 = -1
)

// totpIssuer is shown by the authenticator app.
const totpIssuer = "Vedette"

// NewTOTPSecret returns a fresh 160-bit key.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("auth: totp secret: %w", err)
	}
	return b, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// SecretBase32 is the key as an authenticator app takes it (unpadded base32).
func SecretBase32(secret []byte) string { return b32.EncodeToString(secret) }

// OTPAuthURI is the otpauth:// URI the SPA draws as a QR code.
func OTPAuthURI(account string, secret []byte) string {
	return "otpauth://totp/" + url.PathEscape(totpIssuer) + ":" + url.PathEscape(account) +
		"?secret=" + SecretBase32(secret) + "&issuer=" + url.QueryEscape(totpIssuer) + "&algorithm=SHA1&digits=6&period=30"
}

// TOTPStep is the time step number of t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCode returns the 6-digit code of secret for a time step (RFC 4226 dynamic truncation of HMAC-SHA1).
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step is a positive time counter
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// VerifyTOTP checks code against the steps around now. A step at or before lastStep is refused, so a code
// cannot be used twice (replay protection); pass NoStep when nothing was accepted before. It returns the
// accepted step, which the caller must store as the new lastStep atomically with accepting the login
// (AdvanceTotpStep refuses a concurrent second use). Every candidate is compared in constant time.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (step int64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if s < 0 || s <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, s)), []byte(code)) == 1 && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}
