// Package provider talks to LLM providers (Anthropic Messages, OpenAI Chat Completions, Google Gemini
// generateContent) behind one small interface. It knows nothing about jobs, routing or privacy rules:
// the ai package decides which profile may receive which data (INV-3); this package only moves bytes.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// APIStyle is the wire format a server speaks: Messages (anthropic), Chat Completions (openai), generateContent (gemini).
type APIStyle string

// The three wire formats.
const (
	StyleAnthropic APIStyle = "anthropic"
	StyleOpenAI    APIStyle = "openai"
	StyleGemini    APIStyle = "gemini"
)

// Provider sends one normalised request and returns one normalised response.
type Provider interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// Role of a message in the normalised conversation: user, assistant, or tool (results for the previous assistant turn).
type Role string

// Message roles.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool" // carries ToolResults for the tool calls of the previous assistant message
)

// Message is one turn. An assistant turn may carry ToolCalls; a tool turn carries ToolResults.
type Message struct {
	Role        Role
	Text        string
	ToolCalls   []ToolCall
	ToolResults []ToolResult
	// Raw is the provider's own content of an assistant turn (Anthropic: the array of content blocks, which
	// includes thinking blocks). When set, the Anthropic adapter replays it unchanged instead of rebuilding
	// the turn from Text and ToolCalls; other adapters ignore it. It must be a JSON array.
	Raw json.RawMessage
}

// ToolDef describes a read-only tool offered to the model. Which tools may be offered is decided by the
// ai package (INV-14); a provider sends whatever it is given.
type ToolDef struct {
	Name        string
	Description string
	InputSchema json.RawMessage // JSON Schema object
}

// ToolCall is a tool use requested by the model. Arguments is a JSON object.
type ToolCall struct {
	ID        string
	Name      string
	Arguments json.RawMessage
}

// ToolResult answers a ToolCall. Name is needed by Gemini, which matches results by name.
type ToolResult struct {
	CallID  string
	Name    string
	Content string
	IsError bool
}

// Schema asks for structured output: the reply text must be a JSON document matching JSON.
type Schema struct {
	Name string // letters, digits, underscore, dash; at most 64
	JSON json.RawMessage
}

// Request is the normalised request. MaxTokens must be positive; the model comes from the profile.
type Request struct {
	System    string
	Messages  []Message
	Tools     []ToolDef
	Schema    *Schema
	MaxTokens int
}

// StopReason is why generation ended: end, max_tokens, tool_use or other.
type StopReason string

// Stop reasons.
const (
	StopEnd       StopReason = "end"
	StopMaxTokens StopReason = "max_tokens"
	StopToolUse   StopReason = "tool_use"
	StopOther     StopReason = "other"
	// StopRefusal never appears in a successful Response: a refusal is returned as an error (ErrRefused).
	StopRefusal StopReason = "refusal"
)

// Usage counts tokens as reported by the provider.
type Usage struct{ InputTokens, OutputTokens int }

// Response is the normalised reply.
type Response struct {
	Text      string
	ToolCalls []ToolCall
	Usage     Usage
	Stop      StopReason
	Model     string
	// Raw is the assistant content as the provider sent it (Anthropic only); pass it back in Message.Raw.
	Raw json.RawMessage
}

// Secret holds an API key. It never prints, logs or marshals its value; only Reveal returns it.
type Secret struct{ v *string } // a pointer: fmt prints an address, not the text, even for an unexported field

// NewSecret wraps a key.
func NewSecret(v string) Secret { return Secret{v: &v} }

// Reveal returns the key for use in a request header. Call it at the last moment, never log the result.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

// IsSet reports whether a key exists.
func (s Secret) IsSet() bool { return s.Reveal() != "" }

// Last4 returns the last four characters, for the UI (SYS-4).
func (s Secret) Last4() string {
	k := s.Reveal()
	if len(k) < 4 {
		return ""
	}
	return k[len(k)-4:]
}

// String, GoString, LogValue, MarshalText and MarshalJSON all return "[redacted]" so a Secret cannot leak by formatting.
func (s Secret) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer.
func (s Secret) GoString() string { return "provider.Secret([redacted])" }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Sentinel errors, matched with errors.Is. All of them are safe to show: they never contain the key or the URL.
var (
	ErrAuth        = errors.New("provider rejected the credentials")
	ErrRateLimited = errors.New("provider rate limit")
	ErrServer      = errors.New("provider server error")
	ErrTimeout     = errors.New("provider did not answer in time")
	ErrRequest     = errors.New("provider refused the request")
	ErrTooLarge    = errors.New("provider response is too large")
	ErrBadResponse = errors.New("provider response is not valid")
	ErrNetwork     = errors.New("provider is unreachable")
	// ErrOwnAddress is ErrNetwork for a server that is Vedette itself (Own, D-446): the dial was refused before any packet.
	ErrOwnAddress = fmt.Errorf("%w: the server is Vedette itself", ErrNetwork)
	// ErrNoWorkspace: an Anthropic key that is not scoped to a workspace (HTTP 400 on every request, issue #118).
	ErrNoWorkspace = errors.New("the API key is not tied to a workspace")
	// ErrRefused: the model declined (safety refusal). The content is discarded; Error.Category says why.
	ErrRefused = errors.New("the model declined the request")
)

// Error wraps a sentinel with the HTTP status and a short, scrubbed message from the provider.
type Error struct {
	Kind    error
	Status  int
	Message string
	// Category is set for ErrRefused: a short lowercase label such as cyber or safety (never provider free text).
	Category string
	// Usage is what the provider reported for a call that produced no answer (a refusal); zero otherwise.
	Usage Usage
}

func (e *Error) Error() string {
	s := "provider: " + e.Kind.Error()
	if e.Status != 0 {
		s += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Category != "" {
		s += " (" + e.Category + ")"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}
func (e *Error) Unwrap() error { return e.Kind }

func newErr(kind error, status int, msg string, key Secret) *Error {
	return &Error{Kind: kind, Status: status, Message: scrub(msg, key)}
}

var categoryRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// refusal builds the error for a model refusal. The category comes from the provider, so it is accepted only
// if it looks like a label; anything else becomes "refusal".
func refusal(category string, u Usage) error {
	c := strings.ToLower(category)
	if !categoryRE.MatchString(c) {
		c = "refusal"
	}
	return &Error{Kind: ErrRefused, Category: c, Usage: u}
}

// MaxUsageTokens is the largest token count accepted from a provider for one call; more is a bad response.
const MaxUsageTokens = 10_000_000

// usage checks the counts of a response. A missing or out-of-range count is not usable.
func usage(in, out *int) (Usage, bool) {
	if in == nil || out == nil || *in < 0 || *out < 0 || *in > MaxUsageTokens || *out > MaxUsageTokens {
		return Usage{}, false
	}
	return Usage{*in, *out}, true
}

// keyShaped matches the beginning of common API keys, which providers sometimes echo back in error text.
var keyShaped = regexp.MustCompile(`\b(?:sk|AIza|gsk|xai)[-_A-Za-z0-9*.]{6,}`)

const keyWindow = 12

func isTokenByte(b byte) bool {
	return b == '_' || b == '-' || b == '+' || b == '/' || b == '=' || b == '.' || b == '*' || b == '~' ||
		(b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// redactKeyRuns replaces every run of key-like characters that contains a 12-character window of the key, so a
// provider that echoes the key with a change, or only a slice of it, still reveals nothing usable.
func redactKeyRuns(msg, key string) string {
	if len(key) < keyWindow {
		return msg
	}
	windows := make(map[string]struct{}, len(key))
	for i := 0; i+keyWindow <= len(key); i++ {
		windows[key[i:i+keyWindow]] = struct{}{}
	}
	var b strings.Builder
	for i := 0; i < len(msg); {
		if !isTokenByte(msg[i]) {
			b.WriteByte(msg[i])
			i++
			continue
		}
		j := i
		for j < len(msg) && isTokenByte(msg[j]) {
			j++
		}
		hit := false
		for k := i; k+keyWindow <= j && !hit; k++ {
			_, hit = windows[msg[k:k+keyWindow]]
		}
		if hit {
			b.WriteString("[redacted]")
		} else {
			b.WriteString(msg[i:j])
		}
		i = j
	}
	return b.String()
}

// scrub removes the key, any fragment of it and anything key-shaped from a provider message, then shortens it.
// The whole text is scrubbed before it is cut, so a key that starts late in a long body cannot survive the cut.
func scrub(msg string, key Secret) string {
	if k := key.Reveal(); k != "" {
		msg = strings.ReplaceAll(msg, k, "[redacted]")
		msg = redactKeyRuns(msg, k)
	}
	msg = keyShaped.ReplaceAllString(msg, "[redacted]")
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200]) + "..."
	}
	return strings.TrimSpace(msg)
}
