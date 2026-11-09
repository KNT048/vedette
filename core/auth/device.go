package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store/coredb"
)

// Device cookies (D-77), after OWASP "Slow Down Online Guessing Attacks with Device Cookies"
// (https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies).
//
// The rate limit of sign-in is keyed by client address, and an IPv6 /64 is one key at a higher limit, so a
// person on the same /64 who guesses 100 times blocks everyone of that /64 for the account they aim at,
// the real owner included. After a successful sign-in the box therefore hands the browser a signed device
// cookie bound to the user. A sign-in that presents a valid cookie of that very account is counted per
// cookie (its own limit: loginMaxFailures in the usual window, with the same growing wait) and is
// exempt from the address and /64 counters, in both directions: it is not blocked by them and does not
// add to them. A missing, malformed, expired, forged or other-user cookie gets no exemption.
//
// The cookie is signed with HMAC-SHA-256 under a key of the box (core_secret), carries the user id, the
// user's cred_version (a password change or reset kills every cookie of the account), a random nonce and
// an expiry. Every successful sign-in issues a new cookie with a new nonce. A stolen cookie lets a thief guess from anywhere, but only loginMaxFailures times per window
// per cookie, and the cookie is useless once the password changes. Only the box reads it: HttpOnly,
// Secure, SameSite=Strict, and a Path that only the sign-in endpoints match. It is a strictly necessary
// cookie for sign-in security, not tracking: the value never leaves the box.
const (
	// CookieDevice is the name of the device cookie (core INV-9).
	CookieDevice = "__Secure-vedette_device"
	// DeviceLifetime is how long a device cookie stays valid after the sign-in that issued it.
	DeviceLifetime = 90 * 24 * time.Hour
	// deviceCookiePath is the only path the browser sends the cookie to: the sign-in endpoints.
	deviceCookiePath = "/api/v1/auth/"
	deviceKeyPurpose = "core_device_cookie.key"
	deviceNonceBytes = 16
)

// DeviceCookie returns the cookie that carries value (from LoginResult.Device).
func DeviceCookie(value string) *http.Cookie {
	return &http.Cookie{Name: CookieDevice, Value: value, Path: deviceCookiePath, MaxAge: int(DeviceLifetime.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}

type deviceClaim struct {
	userID string
	cred   int64
	nonce  string
	exp    time.Time
}

func (c deviceClaim) limiterKey() string { return deviceKeyPrefix + c.nonce }

func (s *Service) deviceKey(ctx context.Context) ([]byte, error) {
	s.deviceKeyMu.Lock()
	defer s.deviceKeyMu.Unlock()
	if s.deviceKeyV == nil {
		k, err := s.secrets.OpenOrCreate(ctx, s.db, deviceKeyPurpose, 32)
		if err != nil {
			return nil, fmt.Errorf("auth: device cookie key: %w", err)
		}
		s.deviceKeyV = k
	}
	return s.deviceKeyV, nil
}

func deviceMAC(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// mintDevice signs a new cookie value for the user, with a fresh random nonce.
func (s *Service) mintDevice(ctx context.Context, userID string, cred int64) (string, error) {
	key, err := s.deviceKey(ctx)
	if err != nil {
		return "", err
	}
	b := make([]byte, deviceNonceBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("auth: device nonce: %w", err)
	}
	nonce := hex.EncodeToString(b)
	payload := strings.Join([]string{"v1", userID, strconv.FormatInt(cred, 10), nonce, strconv.FormatInt(s.now().Add(DeviceLifetime).Unix(), 10)}, "|")
	return tokenEnc.EncodeToString([]byte(payload)) + "." + tokenEnc.EncodeToString(deviceMAC(key, payload)), nil
}

// parseDevice returns the claim of a cookie value that is well formed, signed by this box and not expired.
// It says nothing about whether the claim belongs to the account being signed in to.
func (s *Service) parseDevice(ctx context.Context, v string) (deviceClaim, bool) {
	if v == "" || len(v) > 512 {
		return deviceClaim{}, false
	}
	p, m, ok := strings.Cut(v, ".")
	if !ok {
		return deviceClaim{}, false
	}
	payload, err1 := tokenEnc.DecodeString(p)
	mac, err2 := tokenEnc.DecodeString(m)
	if err1 != nil || err2 != nil {
		return deviceClaim{}, false
	}
	key, err := s.deviceKey(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "device cookie ignored: no key", "error", err)
		return deviceClaim{}, false
	}
	if !hmac.Equal(mac, deviceMAC(key, string(payload))) {
		return deviceClaim{}, false
	}
	f := strings.Split(string(payload), "|")
	if len(f) != 5 || f[0] != "v1" {
		return deviceClaim{}, false
	}
	cred, err1 := strconv.ParseInt(f[2], 10, 64)
	exp, err2 := strconv.ParseInt(f[4], 10, 64)
	if err1 != nil || err2 != nil || f[1] == "" || len(f[3]) != 2*deviceNonceBytes {
		return deviceClaim{}, false
	}
	c := deviceClaim{userID: f[1], cred: cred, nonce: f[3], exp: time.Unix(exp, 0)}
	if !s.now().Before(c.exp) {
		return deviceClaim{}, false
	}
	return c, true
}

// limitKeys picks the rate-limit keys of a sign-in or resend: the cookie's own key when the request
// presents a valid cookie of the account that email names, the address (and /64) keys otherwise.
func (s *Service) limitKeys(ctx context.Context, email string, ip netip.Addr, cookie string) ([]string, error) {
	if cookie != "" {
		if c, ok := s.parseDevice(ctx, cookie); ok {
			row, err := coredb.New(s.db.Reader()).GetUserByEmail(ctx, email)
			switch {
			case err == nil && row.ID == c.userID && row.CredVersion == c.cred:
				return []string{c.limiterKey()}, nil
			case err == nil || isNoRows(err): // another account's cookie, a stale one, or no such account: no exemption
			default:
				return nil, fmt.Errorf("auth: look up user: %w", err)
			}
		}
	}
	return ipLimitKeys(ip), nil
}

// ValidDevice reports whether cookie is, right now, a valid device cookie of the user userID: signed by this
// box, not expired, for the user's current password. A caller that is about to change the password asks
// before the change, then asks NewDevice for the cookie of the new password (D-77: the browser the owner
// already trusted keeps its exemption after a password change they just proved).
func (s *Service) ValidDevice(ctx context.Context, userID, cookie string) bool {
	c, ok := s.parseDevice(ctx, cookie)
	if !ok || c.userID != userID {
		return false
	}
	row, err := coredb.New(s.db.Reader()).GetUserByID(ctx, userID)
	return err == nil && row.CredVersion == c.cred
}

// NewDevice returns a fresh device cookie value for the user's current password, "" when none could be made
// (logged, never an error: the password change itself must not fail for it).
func (s *Service) NewDevice(ctx context.Context, userID string) string {
	row, err := coredb.New(s.db.Reader()).GetUserByID(ctx, userID)
	if err != nil {
		s.log.WarnContext(ctx, "could not issue a device cookie", "error", err)
		return ""
	}
	return s.deviceFor(ctx, userID, row.CredVersion)
}

// deviceFor returns the cookie value to hand out after a successful sign-in: always a new cookie with a
// fresh nonce, never the presented one re-signed (OWASP's scheme issues a new device cookie on every
// successful authentication). A copy stolen earlier then keeps the counter of its old nonce, which the
// owner's current cookie does not share, so a thief burning the stale copy's budget cannot lock the owner's
// browser. A failure is logged and means no cookie: sign-in itself must not fail for it.
func (s *Service) deviceFor(ctx context.Context, userID string, cred int64) string {
	v, err := s.mintDevice(ctx, userID, cred)
	if err != nil {
		s.log.WarnContext(ctx, "could not issue a device cookie", "error", err)
		return ""
	}
	return v
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
