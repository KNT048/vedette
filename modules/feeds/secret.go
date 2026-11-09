package feeds

import (
	"log/slog"
	"strings"
	"unicode/utf8"
)

const redacted = "[redacted]"

// Secret holds a feed credential. It never prints, logs or marshals its value;
// Reveal is the only way out and is meant for the fetcher and core/secrets.
// The value sits behind a pointer so that even fmt printing a struct with an
// unexported Secret field shows an address, not the text.
type Secret struct{ p *string }

// NewSecret validates INV-6: 8..500 chars, no whitespace or control characters.
func NewSecret(s string) (Secret, error) {
	if err := CheckSecret(s); err != nil {
		return Secret{}, err
	}
	return Secret{p: &s}, nil
}

// CheckSecret is the INV-6 rule on its own (for API validation).
func CheckSecret(s string) error {
	n := utf8.RuneCountInString(s)
	if n < 8 || n > 500 {
		return fail(ErrInvalidSecret, "The secret must be 8 to 500 characters with no spaces.")
	}
	if strings.ContainsFunc(s, jsIsSpace) || hasControl(s) || !utf8.ValidString(s) {
		return fail(ErrInvalidSecret, "The secret must be 8 to 500 characters with no spaces.")
	}
	return nil
}

func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// IsSet reports whether a value is held.
func (s Secret) IsSet() bool { return s.p != nil }

// Last4 is what the UI may show (secret_last4).
func (s Secret) Last4() string {
	r := []rune(s.Reveal())
	if len(r) > 4 {
		r = r[len(r)-4:]
	}
	return string(r)
}

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
