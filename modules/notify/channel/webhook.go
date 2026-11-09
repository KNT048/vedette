package channel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kiennt048/vedette/core/secrets"
)

// WebhookConfig configures the generic webhook channel.
type WebhookConfig struct {
	// URL is a secret: its path or query often carries a token. https; http only for internal hosts.
	URL        secrets.Value
	SigningKey secrets.Value // at least 16 bytes; signs every request
	BoxAddrs   []netip.Addr  // this box's own addresses: never a valid target
	Client     *http.Client  // nil = a client whose dialer refuses forbidden addresses (see dialControl)
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
	noPrint
	url    secrets.Value
	to     string // scheme://host only
	key    secrets.Value
	client *http.Client
	now    func() time.Time
}

var numericLabelRE = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)$`)

// forbiddenAddr reports whether a webhook may never connect to a. Loopback is
// forbidden unless allowLoopback (plain http to the internal list, which
// includes 127/8). Link-local, unspecified, multicast and the box's own
// addresses are always forbidden. Private RFC 1918 addresses are allowed on both
// schemes: an internal SIEM is a normal target.
func forbiddenAddr(a netip.Addr, allowLoopback bool, box []netip.Addr) bool {
	a = a.Unmap()
	switch {
	case a.IsUnspecified(), a.IsMulticast(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return true
	case a.IsLoopback() && !allowLoopback:
		return true
	}
	for _, b := range box {
		if b.Unmap() == a {
			return true
		}
	}
	return false
}

var errForbiddenDial = errors.New("notify: webhook: refusing to connect to a loopback, link-local, multicast, unspecified or box address")

// dialControl runs after name resolution, on the address about to be dialled,
// so a DNS name that resolves to a forbidden address (or rebinds to one) is
// refused too.
func dialControl(allowLoopback bool, box []netip.Addr) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errForbiddenDial
		}
		if a, err := netip.ParseAddr(host); err != nil || forbiddenAddr(a, allowLoopback, box) {
			return errForbiddenDial
		}
		return nil
	}
}

func webhookClient(allowLoopback bool, box []netip.Addr) *http.Client {
	return &http.Client{
		Timeout:       defaultTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                 nil, // never an environment proxy: it would see the signed body
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, Control: dialControl(allowLoopback, box)}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: defaultTimeout,
			DisableKeepAlives:     true,
		},
	}
}

// NewWebhook validates cfg (INV-8) and returns the adapter. Rules: https, or
// http only for hosts on the internal list; never loopback over https, never
// link-local, unspecified, multicast or the box itself; no numeric host
// spellings such as 2130706433 or 0x7f.1.
func NewWebhook(cfg WebhookConfig) (Sender, error) {
	raw := strings.TrimSpace(cfg.URL.Reveal())
	u, err := url.Parse(raw)
	bad := cfgErr("bad_url", "The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.")
	if raw == "" || err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return nil, bad
	}
	for _, r := range raw {
		if r <= ' ' || r > '~' {
			return nil, bad
		}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	blocked := cfgErr("blocked_host", "The webhook cannot point at this machine, a link-local or multicast address, or an unspecified address.")
	https := u.Scheme == "https"
	switch u.Scheme {
	case "https":
	case "http":
		if !internalHost(host) {
			return nil, cfgErr("insecure_url", "Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.")
		}
	default:
		return nil, bad
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if forbiddenAddr(a, !https, cfg.BoxAddrs) {
			return nil, blocked
		}
	} else {
		labels := strings.Split(host, ".")
		if numericLabelRE.MatchString(labels[len(labels)-1]) {
			return nil, bad // a number-like host is an IP in disguise
		}
		if https && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
			return nil, blocked
		}
	}
	if !isSet(cfg.SigningKey) {
		return nil, cfgErr("secret_required", "Enter the webhook signing key.")
	}
	if len(cfg.SigningKey.Reveal()) < minSigningKey {
		return nil, cfgErr("bad_secret", "The signing key needs at least 16 characters. Press Generate if you want a random one.")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client := cfg.Client
	if client == nil {
		client = webhookClient(!https, cfg.BoxAddrs)
	}
	return &webhookSender{url: secrets.NewValue(u.String()), to: u.Scheme + "://" + u.Host, key: cfg.SigningKey, client: clientOrDefault(client), now: now}, nil
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
func sign(key secrets.Value, ts string, body []byte) string {
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
	hide := []secrets.Value{w.url, w.key}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url.Reveal(), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: webhook: build request: %s", transportReason(err, hide))
	}
	ts := strconv.FormatInt(w.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vedette-notify")
	req.Header.Set(WebhookTimestampHeader, ts)
	req.Header.Set(WebhookSignatureHeader, sign(w.key, ts, body))
	code, ans, err := do(w.client, Webhook, req, hide...)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Webhook, code, ans, hide...)
	}
	return Receipt{To: w.to, Detail: fmt.Sprintf("The webhook returned HTTP %d.", code)}, nil
}

func (w *webhookSender) Dest() string { return w.to }
