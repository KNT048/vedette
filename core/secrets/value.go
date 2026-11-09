package secrets

import (
	"fmt"
	"log/slog"
)

const redacted = "[redacted]"

// Value holds a plaintext secret in memory. Printing, formatting, JSON/text encoding and
// logging all yield "[redacted]"; the only way out is Reveal. The text sits behind a pointer
// so even fmt's reflection over unexported struct fields (which skips methods) cannot print it.
type Value struct{ p *string }

// NewValue wraps s.
func NewValue(s string) Value { return Value{p: &s} }

// Reveal returns the plaintext. Call it only where the secret is used.
func (v Value) Reveal() string {
	if v.p == nil {
		return ""
	}
	return *v.p
}

// String implements fmt.Stringer.
func (Value) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (Value) GoString() string { return redacted }

// Format implements fmt.Formatter for every verb.
func (Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Value) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(redacted) }

// IsSet reports whether v holds a non-empty secret (the zero Value and NewValue("") are not set).
func (v Value) IsSet() bool { return v.p != nil && *v.p != "" }

// Last4 returns the last 4 characters for the UI (API fields secret_last4, key_last4), or "" when the
// secret has fewer than 8 characters: the same rule as core_secret.last4, since a short secret would be
// mostly revealed by its tail. Characters are Unicode code points.
func (v Value) Last4() string {
	if v.p == nil {
		return ""
	}
	r := []rune(*v.p)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}
