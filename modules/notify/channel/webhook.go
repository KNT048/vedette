package channel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WebhookConfig configures the generic webhook channel.
type WebhookConfig struct {
	URL        string       // https; http only for internal hosts (see internalHost)
	SigningKey Secret       // at least 16 bytes; signs every request
	Client     *http.Client // nil = NewHTTPClient()
	Now        func() time.Time
}

// Request headers of a signed webhook call. A receiver computes
// hex(HMAC-SHA256(key, timestamp + "." + raw request body)), compares it in
// constant time with the part after "sha256=", and rejects timestamps that are
// too old (replay).
const (
	WebhookTimestampHeader = "X-Vedette-Timestamp" // Unix seconds, decimal
	WebhookSignatureHeader = "X-Vedette-Signature" // "sha256=" + lowercase hex
	minSigningKey          = 16
)

type webhookSender struct {
	url    string
	to     string
	key    Secret
	client *http.Client
	now    func() time.Time
}

// NewWebhook validates cfg (INV-8: https, or http only for internal hosts) and returns the adapter.
func NewWebhook(cfg WebhookConfig) (Sender, error) {
	raw := strings.TrimSpace(cfg.URL)
	u, err := url.Parse(raw)
	bad := cfgErr("bad_url", "The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.")
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return nil, bad
	}
	for _, r := range raw {
		if r <= ' ' || r > '~' {
			return nil, bad
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !internalHost(u.Hostname()) {
			return nil, cfgErr("insecure_url", "Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.")
		}
	default:
		return nil, bad
	}
	if cfg.SigningKey.IsZero() {
		return nil, cfgErr("secret_required", "Enter the webhook signing key.")
	}
	if len(cfg.SigningKey.Reveal()) < minSigningKey {
		return nil, cfgErr("bad_secret", "The signing key needs at least 16 characters. Press Generate if you want a random one.")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	to := *u
	to.RawQuery = "" // a query string may carry a token: never shown
	return &webhookSender{url: u.String(), to: to.String(), key: cfg.SigningKey, client: clientOrDefault(cfg.Client), now: now}, nil
}

func (*webhookSender) Type() Type { return Webhook }

type webhookPayload struct {
	Event    string   `json:"event"` // the Message kind: incident, vuln, approval, test
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Device   string   `json:"device,omitempty"`
	What     string   `json:"what,omitempty"`
	Action   string   `json:"action,omitempty"`
	Items    []string `json:"items,omitempty"`
	URL      string   `json:"url"`
}

// sign returns the signature header value for body at timestamp ts.
func sign(key Secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key.Reveal()))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (w *webhookSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	n := m.norm()
	body, err := json.Marshal(webhookPayload{Event: n.Kind, ID: n.ID, Severity: n.Severity, Title: n.Title, Device: n.Device, What: n.What, Action: n.Action, Items: n.Items, URL: link})
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: webhook: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: webhook: build request: %s", transportReason(err, []Secret{w.key}))
	}
	ts := strconv.FormatInt(w.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vedette-notify")
	req.Header.Set(WebhookTimestampHeader, ts)
	req.Header.Set(WebhookSignatureHeader, sign(w.key, ts, body))
	code, ans, err := do(w.client, Webhook, req, w.key)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Webhook, code, ans, w.key)
	}
	return Receipt{To: w.to, Detail: fmt.Sprintf("The webhook returned HTTP %d.", code)}, nil
}
