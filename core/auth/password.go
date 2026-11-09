package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/knt048/vedette/core/apierr"
)

// Password length limits, in characters. The maximum is a denial-of-service guard: argon2 work does not
// grow with length, but request bodies and hashing buffers do.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

const (
	saltLen = 16
	keyLen  = 32
)

// Params are the argon2id cost parameters. Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultParams is what new password hashes use: m=64 MiB, t=3, p=2 (OWASP-grade for a login that runs
// once per sign-in). Raising it later makes VerifyPassword report needsRehash for older hashes.
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Threads: 2}

// Upper bounds accepted when reading a hash from the database, so a corrupted or planted row cannot make
// a login allocate gigabytes.
const (
	maxMemory  = 256 * 1024
	maxTime    = 10
	maxThreads = 16
)

// ErrBadHash is returned by Verify for a stored hash that is not a PHC argon2id string within limits.
var ErrBadHash = errors.New("auth: malformed password hash")

// Hash returns the PHC string $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash> for password
// (16-byte random salt, 32-byte key, unpadded standard base64).
func (p Params) Hash(password string) (string, error) {
	if p.Memory < 8*uint32(p.Threads) || p.Time < 1 || p.Threads < 1 || p.Memory > maxMemory || p.Time > maxTime || p.Threads > maxThreads {
		return "", fmt.Errorf("auth: argon2 parameters out of range: %+v", p)
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks password against a PHC string in constant time. needsRehash is true when the hash is valid
// for this password but was made with parameters (or salt/key sizes) other than p's. The error is non-nil
// only when encoded is malformed (ErrBadHash); a wrong password is ok=false with a nil error.
func (p Params) Verify(encoded, password string) (ok, needsRehash bool, err error) {
	got, salt, key, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	derived := argon2.IDKey([]byte(password), salt, got.Time, got.Memory, got.Threads, uint32(len(key))) //nolint:gosec // len(key) is within 16..64
	if subtle.ConstantTimeCompare(derived, key) != 1 {
		return false, false, nil
	}
	return true, got != p || len(salt) != saltLen || len(key) != keyLen, nil
}

func parsePHC(encoded string) (Params, []byte, []byte, error) {
	bad := func() (Params, []byte, []byte, error) { return Params{}, nil, nil, ErrBadHash }
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return bad()
	}
	var p Params
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, found := strings.Cut(kv, "=")
		n, perr := strconv.ParseUint(v, 10, 32)
		if !found || perr != nil {
			return bad()
		}
		switch k {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n > maxThreads {
				return bad()
			}
			p.Threads = uint8(n)
		default:
			return bad()
		}
	}
	if p.Threads < 1 || p.Time < 1 || p.Time > maxTime || p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory {
		return bad()
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(salt) > 64 || len(key) < 16 || len(key) > 64 {
		return bad()
	}
	return p, salt, key, nil
}

// HashPassword hashes with DefaultParams.
func HashPassword(password string) (string, error) { return DefaultParams.Hash(password) }

// VerifyPassword verifies against DefaultParams (see Params.Verify).
func VerifyPassword(encoded, password string) (ok, needsRehash bool, err error) {
	return DefaultParams.Verify(encoded, password)
}

// ValidatePassword applies the password policy to a new password: 12 to 256 characters, valid UTF-8,
// not equal to the account's email. It returns a 400 weak_password error, or nil.
func ValidatePassword(password, email string) *apierr.Error {
	weak := func(msg string) *apierr.Error { return apierr.New(400, CodeWeakPassword, msg) }
	switch n := utf8.RuneCountInString(password); {
	case !utf8.ValidString(password):
		return weak("The password must be valid text.")
	case n < MinPasswordLen:
		return weak(fmt.Sprintf("The password needs at least %d characters. A long sentence is easier to remember than random characters.", MinPasswordLen))
	case n > MaxPasswordLen:
		return weak(fmt.Sprintf("The password can be at most %d characters.", MaxPasswordLen))
	}
	if email != "" && strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(email)) {
		return weak("The password must not be your email address.")
	}
	return nil
}

// tempAlphabet leaves out look-alike characters (0/O, 1/l/I).
const tempAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewTempPassword returns a random 20-character password (about 114 bits) for an account an administrator
// created or reset. The caller shows it once; only its hash is stored.
func NewTempPassword() (string, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("auth: temp password: %w", err)
	}
	for i, c := range b {
		b[i] = tempAlphabet[int(c)%len(tempAlphabet)] // 256 % 54 bias is negligible for a 114-bit password
	}
	return string(b), nil
}
