package feeds

import (
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/secrets"
)

// Secret is a feed credential: a core/secrets.Value (which redacts itself in
// fmt, slog, JSON and text, and is read only through Reveal, SYS-4) plus the
// INV-6 validation and the 4-character hint the UI may show.
type Secret struct{ secrets.Value }

// NewSecret validates INV-6: 8..500 chars, no whitespace or control characters.
func NewSecret(s string) (Secret, error) {
	if err := CheckSecret(s); err != nil {
		return Secret{}, err
	}
	return Secret{secrets.NewValue(s)}, nil
}

// CheckSecret is the INV-6 rule on its own (for API validation).
func CheckSecret(s string) error {
	n := utf8.RuneCountInString(s)
	if n < 8 || n > 500 || !utf8.ValidString(s) || strings.ContainsFunc(s, jsIsSpace) || hasControl(s) {
		return fail(ErrInvalidSecret, "The secret must be 8 to 500 characters with no spaces.")
	}
	return nil
}

// IsSet reports whether a value is held.
func (s Secret) IsSet() bool { return s.Reveal() != "" }

// Last4 is what the UI may show (secret_last4).
func (s Secret) Last4() string {
	r := []rune(s.Reveal())
	if len(r) > 4 {
		r = r[len(r)-4:]
	}
	return string(r)
}
