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
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
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
	ID           string      // stable id, used in the webhook payload and the Message-ID header
	Kind         string      // "incident", "vuln", "approval" or "test"
	IncidentKind string      // incidents only: trap, bad_address, log_anomaly or unknown_device (webhook "kind")
	Devices      []DeviceRef // the devices as a list (webhook "devices"); Device is the same for people to read
	Severity     string      // critical|high|medium|low|info
	Title        string      // one plain sentence
	Device       string      // optional, e.g. "PC-HR-01 (192.168.10.107)"
	What         string      // what happened and how urgent
	Action       string      // what to do first
	Items        []string    // optional detail lines, e.g. the CVEs of a grouped notice
	Link         string      // absolute http(s) URL that opens the item in Vedette
	// Buttons go under the message on Telegram (inline keyboard; approvals, spec approval-tokens.md 6). Other adapters
	// ignore them. They are never part of the JSON form, so the history (and a resend) never has them.
	Buttons []Button `json:"-"`
	// ReplyCodes are the two reply codes of one approver (Zalo personal, spec approval-tokens.md 7.1). Only the sender of
	// ZaloPersonalTo writes them, on the last line of the message, which is never cut; every other sender refuses or ignores them.
	// Like Buttons they are never part of the JSON form, so the history never has them.
	ReplyCodes *ReplyCodes `json:"-"`
}

// ReplyCodes are the codes an approver replies with: Approve "A-" and Reject "R-" plus 6 characters of the alphabet of spec 7.1, and
// Until the box time (HH:MM) after which they no longer work.
type ReplyCodes struct {
	Approve, Reject, Until string
}

var (
	replyCodeRE  = regexp.MustCompile(`^[AR]-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$`)
	replyUntilRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

func (rc *ReplyCodes) check() error {
	if rc == nil {
		return nil
	}
	if !replyCodeRE.MatchString(rc.Approve) || rc.Approve[0] != 'A' || !replyCodeRE.MatchString(rc.Reject) || rc.Reject[0] != 'R' || !replyUntilRE.MatchString(rc.Until) {
		return fmt.Errorf("%w: reply codes are not in form", ErrInvalidMessage)
	}
	return nil
}

// line is the last line of a message with reply codes.
func (rc *ReplyCodes) line() string {
	return "To decide, reply to this message with " + rc.Approve + " to approve or " + rc.Reject + " to reject, before " + rc.Until +
		" (box time). Each code works once, and only from your own Zalo account."
}

// DeviceRef names a device in a Message. ID is empty when only the name is known.
type DeviceRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// Receipt says where a message went and what the provider answered.
type Receipt struct {
	To     string // destination label for SendRecord.to (never a secret)
	Detail string // short, secret-free text, shown as the test-send result
	// MessageID is the id the provider gave the message (Telegram: message_id, 1 to 2^53), so it can be edited later; 0 = unknown.
	MessageID int64
	// ChatID is the chat the provider says the message is in (Telegram: result.chat.id, a checked number); "" = unknown.
	ChatID string
	// TS is the Slack timestamp of a message posted with chat.postMessage (its id for later edits and for checking a press); "" = unknown.
	TS string
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

// ProviderError is a refusal the provider reports inside an HTTP 2xx answer
// (Zalo "error": -216, Telegram "ok": false). Code is the provider's own code
// (0 when it gave none); Reason is short and secret-free.
type ProviderError struct {
	Channel Type
	Code    int
	Reason  string

	requestRefused bool // Zalo refused the request as a whole (outer error_code), not the message
}

func (e *ProviderError) Error() string {
	if e.Code == 0 {
		return fmt.Sprintf("notify: %s: provider error: %s", e.Channel, e.Reason)
	}
	return fmt.Sprintf("notify: %s: provider error %d: %s", e.Channel, e.Code, e.Reason)
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
		CheckRedirect: noRedirect,
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// clientOrDefault returns the caller's client on a shallow copy that never
// follows redirects (the caller's own client is left untouched), or a new
// default client.
func clientOrDefault(c *http.Client) *http.Client {
	if c == nil {
		return NewHTTPClient()
	}
	cp := *c
	cp.CheckRedirect = noRedirect
	return &cp
}

// noPrint is embedded in every sender. Its String and GoString are promoted to
// the sender, so printing a sender (or a slice of them) with any verb never
// walks its fields: fmt cannot call a secret's Format on unexported fields and
// would print the raw value.
type noPrint struct{}

func (noPrint) String() string   { return "notify sender" }
func (noPrint) GoString() string { return "notify sender" }

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
	if err := m.ReplyCodes.check(); err != nil {
		return err
	}
	return checkButtons(m.Buttons)
}

// safeLink accepts only absolute http(s) URLs made of printable ASCII, without
// the characters that break Slack, Telegram or email link syntax. It returns the
// normalised URL string.
func safeLink(link string) (string, error) {
	if link == "" {
		return "", nil // the box address is not known: the message says to open Vedette instead
	}
	if len(link) > maxLink {
		return "", fmt.Errorf("%w: link must be at most 1024 characters", ErrInvalidMessage)
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
func do(c *http.Client, ch Type, req *http.Request, hide ...secrets.Value) (status int, body []byte, err error) {
	return doLimit(c, ch, req, maxResponseBody, hide...)
}

// doLimit is do with another cap on the answer (a Telegram updates answer is bigger than a send answer).
func doLimit(c *http.Client, ch Type, req *http.Request, limit int64, hide ...secrets.Value) (status int, body []byte, err error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("notify: %s: send failed: %s", ch, transportReason(err, hide))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("notify: %s: read answer: %s", ch, transportReason(err, hide))
	}
	return resp.StatusCode, body, nil
}

// transportReason strips the URL from *url.Error (it can carry a bot token) and
// scrubs secrets from what is left.
func transportReason(err error, hide []secrets.Value) string {
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
	return truncRunes(scrub(clean(err.Error(), false), hide...), 160)
}

// reasonFrom turns an untrusted provider answer into a short, printable,
// secret-free reason.
func reasonFrom(body []byte, hide ...secrets.Value) string {
	s := strings.Join(strings.Fields(clean(string(body), false)), " ")
	return truncRunes(scrub(s, hide...), 120)
}

// statusErr builds the typed error for a non-2xx answer.
func statusErr(ch Type, code int, body []byte, hide ...secrets.Value) error {
	return &StatusError{Channel: ch, Code: code, Reason: reasonFrom(body, hide...)}
}
