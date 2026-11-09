// Package channel holds the notification channel adapters of the notify module
// (Slack, Telegram, email over SMTP, Zalo OA, generic webhook, Zalo personal).
// Each adapter validates its configuration at the boundary (INV-8) and sends one
// text Message. Message fields are untrusted (they come from feeds, logs and
// customer data): every adapter escapes them for its own target.
package channel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Type is a channel type, spelled as in contract.ts.
type Type string

// The six channel types.
const (
	Telegram     Type = "telegram"
	Slack        Type = "slack"
	Zalo         Type = "zalo"
	ZaloPersonal Type = "zalo-personal"
	Email        Type = "email"
	Webhook      Type = "webhook"
)

var severityLabel = map[string]string{"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

// Message is one notification, as plain text. Adapters render it per channel.
type Message struct {
	ID       string   // stable id, used in the webhook payload and the Message-ID header
	Kind     string   // "incident", "vuln", "approval" or "test"
	Severity string   // critical|high|medium|low|info
	Title    string   // one plain sentence
	Device   string   // optional, e.g. "PC-HR-01 (192.168.10.107)"
	What     string   // what happened and how urgent
	Action   string   // what to do first
	Items    []string // optional detail lines, e.g. the CVEs of a grouped notice
	Link     string   // absolute http(s) URL that opens the item in Vedette
}

// Receipt says where a message went and what the provider answered.
type Receipt struct {
	To     string // destination label for SendRecord.to (never a secret)
	Detail string // short, secret-free text, shown as the test-send result
}

// Sender sends one Message through one configured channel.
type Sender interface {
	Type() Type
	// Dest is the destination label of SendRecord.to (never a secret), known even when a send fails.
	Dest() string
	Send(ctx context.Context, m Message) (Receipt, error)
}

// Sentinel errors.
var (
	// ErrInvalidConfig matches every *ConfigError.
	ErrInvalidConfig = errors.New("notify: invalid channel configuration")
	// ErrInvalidMessage means the Message itself is unusable (unknown severity, empty title, bad link).
	ErrInvalidMessage = errors.New("notify: invalid message")
	// ErrUnsupported means the channel cannot send in this build (Zalo personal, D-46).
	ErrUnsupported = errors.New("notify: this channel cannot send messages yet")
)

// ConfigError is a configuration problem with a stable code (same codes as the
// mock API) and a user-facing English text.
type ConfigError struct {
	Code string
	Msg  string
}

func (e *ConfigError) Error() string { return "notify: " + e.Code + ": " + e.Msg }

// Is makes errors.Is(err, ErrInvalidConfig) true for every ConfigError.
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

func cfgErr(code, msg string) error { return &ConfigError{Code: code, Msg: msg} }

// StatusError is a non-2xx (or provider-level) refusal. Reason is short and secret-free.
type StatusError struct {
	Channel Type
	Code    int
	Reason  string
}

func (e *StatusError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("notify: %s: server answered HTTP %d", e.Channel, e.Code)
	}
	return fmt.Sprintf("notify: %s: server answered HTTP %d: %s", e.Channel, e.Code, e.Reason)
}

// Limits.
const (
	maxResponseBody = 64 << 10
	maxLink         = 1024
	defaultTimeout  = 15 * time.Second
)

// NewHTTPClient returns a client with a total timeout that does not follow
// redirects (a redirect from a webhook host could point inside the LAN).
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func clientOrDefault(c *http.Client) *http.Client {
	if c == nil {
		return NewHTTPClient()
	}
	return c
}

// check validates the Message structure shared by every adapter.
func (m Message) check() error {
	if _, ok := severityLabel[m.Severity]; !ok {
		return fmt.Errorf("%w: unknown severity", ErrInvalidMessage)
	}
	if strings.TrimSpace(clean(m.Title, false)) == "" {
		return fmt.Errorf("%w: empty title", ErrInvalidMessage)
	}
	if _, err := safeLink(m.Link); err != nil {
		return err
	}
	return nil
}

// safeLink accepts only absolute http(s) URLs made of printable ASCII, without
// the characters that break Slack, Telegram or email link syntax. It returns the
// normalised URL string.
func safeLink(link string) (string, error) {
	if link == "" || len(link) > maxLink {
		return "", fmt.Errorf("%w: link must be 1 to 1024 characters", ErrInvalidMessage)
	}
	for _, r := range link {
		if r <= ' ' || r > '~' || strings.ContainsRune("<>|\"\\^`{}", r) {
			return "", fmt.Errorf("%w: link has a character that is not allowed", ErrInvalidMessage)
		}
	}
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("%w: link must be an absolute http or https URL", ErrInvalidMessage)
	}
	return u.String(), nil
}

// do sends req through c, reads at most maxResponseBody bytes of the answer,
// closes the body, and turns transport failures into errors that contain no URL
// and none of the secrets.
func do(c *http.Client, ch Type, req *http.Request, secrets ...Secret) (status int, body []byte, err error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("notify: %s: send failed: %s", ch, transportReason(err, secrets))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("notify: %s: read answer: %s", ch, transportReason(err, secrets))
	}
	return resp.StatusCode, body, nil
}

// transportReason strips the URL from *url.Error (it can carry a bot token) and
// scrubs secrets from what is left.
func transportReason(err error, secrets []Secret) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return truncRunes(scrub(clean(err.Error(), false), secrets...), 160)
}

// reasonFrom turns an untrusted provider answer into a short, printable,
// secret-free reason.
func reasonFrom(body []byte, secrets ...Secret) string {
	s := strings.Join(strings.Fields(clean(string(body), false)), " ")
	return truncRunes(scrub(s, secrets...), 120)
}

// statusErr builds the typed error for a non-2xx answer.
func statusErr(ch Type, code int, body []byte, secrets ...Secret) error {
	return &StatusError{Channel: ch, Code: code, Reason: reasonFrom(body, secrets...)}
}
