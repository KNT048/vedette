package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
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
// once per sign-in). Raising it later makes Params.Verify report needsRehash for older hashes. Callers outside this package get hashing through Service, which holds the argon2 concurrency cap.
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
	if guessable(password, email) {
		return weak("This password is too easy to guess: it is built on a common password, a run like 123456 or qwerty, or the name in your email. A sentence of a few unrelated words is stronger.")
	}
	return nil
}

// commonStems are the words the most used passwords are built on (the top of every leaked-password list, and the
// name of the product), kept as stems: "password1234", "Qwerty123456!" and "iloveyou2024" all reduce to one (D-389,
// NIST SP 800-63B 5.1.1.2: compare against commonly used values, repetitive or sequential characters, context words).
// ponytail: a hand-kept list of stems, not a leaked-password corpus; upgrade path: an embedded list such as the
// NCSC top 100k filtered to 12+ characters, with its notice.
var commonStems = map[string]bool{
	"password": true, "passwrd": true, "passwort": true, "qwerty": true, "qwertyuiop": true, "asdfgh": true, "asdfghjkl": true,
	"zxcvbnm": true, "qazwsx": true, "iloveyou": true, "welcome": true, "letmein": true, "admin": true, "administrator": true,
	"changeme": true, "default": true, "secret": true, "monkey": true, "dragon": true, "football": true, "baseball": true,
	"sunshine": true, "princess": true, "superman": true, "master": true, "login": true, "abc": true, "abcdef": true,
	"trustno": true, "vedette": true,
}

// keyRuns are the runs a person types without thinking: digits, the alphabet and the top keyboard rows (checked both ways).
var keyRuns = []string{"01234567890123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm"}

// guessable reports a password that passes the length rule but is among the first a guesser tries: a common stem with
// digits or symbols around or inside it (or repeated), the letters of the email's name, three or fewer distinct
// characters ("aaaaaaaaaaaa", "121212121212"), or a straight run of the digits, alphabet or keyboard.
func guessable(password, email string) bool {
	compact := strings.ReplaceAll(strings.ToLower(password), " ", "")
	var stem, digits strings.Builder
	distinct := map[rune]bool{}
	for _, r := range compact {
		distinct[r] = true
		switch {
		case r == '@':
			stem.WriteRune('a')
		case r == '$':
			stem.WriteRune('s')
		case unicode.IsLetter(r):
			stem.WriteRune(r)
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		}
	}
	if len(distinct) <= 3 {
		return true
	}
	isRun := func(s string) bool {
		for _, run := range keyRuns {
			if strings.Contains(run, s) || strings.Contains(reverse(run), s) {
				return true
			}
		}
		return false
	}
	st := stem.String()
	stemLen := utf8.RuneCountInString(st)
	// A run, alone or with a few other characters around it: "qwertyuiop2024", "1234567890!!".
	if isRun(compact) || (stemLen >= 6 && isRun(st)) || (digits.Len() >= 6 && stemLen < 4 && isRun(digits.String())) {
		return true
	}
	if st == "" {
		return false
	}
	for w := range commonStems {
		if len(st)%len(w) == 0 && st == strings.Repeat(w, len(st)/len(w)) {
			return true
		}
	}
	if local, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@"); ok {
		letters := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) {
				return r
			}
			return -1
		}, local)
		if utf8.RuneCountInString(letters) >= 4 && st == letters {
			return true
		}
	}
	return false
}

func reverse(s string) string {
	b := []byte(s)
	slices.Reverse(b)
	return string(b)
}

// tempAlphabet is 55 characters: it leaves out the look-alikes 0, 1, O, I, l, o and i (23 lowercase, 24
// uppercase, 8 digits).
const tempAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewTempPassword returns a random 20-character password (20 x log2 55, about 115 bits) for an account an administrator
// created or reset. The caller shows it once; only its hash is stored.
func NewTempPassword() (string, error) {
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("auth: temp password: %w", err)
	}
	for i, c := range b {
		b[i] = tempAlphabet[int(c)%len(tempAlphabet)] // 256 % 55 = 36: the first 36 characters are slightly likelier, which costs well under a bit
	}
	return string(b), nil
}
