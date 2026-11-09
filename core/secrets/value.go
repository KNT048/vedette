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
