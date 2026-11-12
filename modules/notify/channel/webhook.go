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

	"github.com/knt048/vedette/core/secrets"
)

// WebhookConfig configures the generic webhook channel.
type WebhookConfig struct {
	// URL is a secret: its path or query often carries a token. https; http only for internal hosts.
	URL        secrets.Value
	SigningKey secrets.Value // at least 16 bytes; signs every request
	BoxAddrs   []netip.Addr  // this box's own addresses: never a valid target
	// BoxAddrsFunc is asked again at every connection, so an address the box gets later is refused too
	// (the caller fills it from the network interfaces). known=false means the box does not know its own
	// addresses yet: NewWebhook returns ErrBoxAddrsUnknown and every connection is refused (fail closed, #157).
	BoxAddrsFunc func() (addrs []netip.Addr, known bool)

	allowLoopback bool         // tests only: the package tests talk to httptest servers on 127.0.0.1
	Client        *http.Client // nil = a client whose dialer refuses forbidden addresses (see dialControl)
	Now           func() time.Time
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

// forbiddenAddr reports whether a webhook may never connect to a: loopback (on http and https alike, unless
// allowLoopback, which only package tests set:
// the box's own services listen there), link-local, unspecified, multicast, a cloud metadata endpoint and the box's own
// addresses, in any transition form (NAT64, 6to4, IPv4-compatible, IPv4-mapped). Private RFC 1918 addresses are allowed on both
// schemes: an internal SIEM is a normal target.
func forbiddenAddr(a netip.Addr, allowLoopback bool, box []netip.Addr) bool {
	for _, f := range addrForms(a) {
		switch {
		case f.IsUnspecified(), f.IsMulticast(), f.IsLinkLocalUnicast(), f.IsLinkLocalMulticast(), metadataAddr(f):
			return true
		case f.IsLoopback() && !allowLoopback:
			return true
		}
		for _, b := range box {
			if b.Unmap() == f {
				return true
			}
		}
	}
	return false
}

// metadataAddrs are cloud instance-metadata endpoints that are not link-local (169.254.169.254 is): AWS and Google Cloud over
// IPv6, Alibaba, Oracle. Same list as feeds and logs.
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("fd20:ce::254"), netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("192.0.0.192")}

func metadataAddr(a netip.Addr) bool {
	for _, m := range metadataAddrs {
		if a == m {
			return true
		}
	}
	return false
}

// metadataName is a name of the cloud metadata service (Google Cloud): refused at save, before any lookup. Other names that
// resolve to a metadata address are refused when connecting (dialControl).
func metadataName(host string) bool {
	return host == "metadata" || host == "metadata.google.internal" || host == "metadata.goog"
}

// addrForms is a plus the IPv4 address that a transition form carries (NAT64, 6to4, IPv4-compatible): a connection to one of
// them reaches that IPv4 address through a translator, so both are judged (as feeds and logs do).
func addrForms(a netip.Addr) []netip.Addr {
	a = a.Unmap().WithZone("")
	out := []netip.Addr{a}
	if !a.Is6() {
		return out
	}
	b := a.As16()
	var v4 [4]byte
	zeros := func(from, to int) bool {
		for _, x := range b[from:to] {
			if x != 0 {
				return false
			}
		}
		return true
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && zeros(4, 12):
		copy(v4[:], b[12:16])
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1:
		for _, x := range nat64Local(b) {
			out = append(out, netip.AddrFrom4(x))
		}
		return out
	case b[0] == 0x20 && b[1] == 0x02:
		copy(v4[:], b[2:6])
	case zeros(0, 12) && !a.IsUnspecified() && a != netip.IPv6Loopback():
		copy(v4[:], b[12:16])
	default:
		return out
	}
	return append(out, netip.AddrFrom4(v4))
}

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry: the operator's prefix length is not known,
// so the address is read in every RFC 6052 layout (/32 /40 /48 /56 /64 /96; byte 8 is the reserved u octet) and each is judged.
func nat64Local(b [16]byte) [][4]byte {
	return [][4]byte{
		{b[4], b[5], b[6], b[7]},
		{b[5], b[6], b[7], b[9]},
		{b[6], b[7], b[9], b[10]},
		{b[7], b[9], b[10], b[11]},
		{b[9], b[10], b[11], b[12]},
		{b[12], b[13], b[14], b[15]},
	}
}

var errForbiddenDial = errors.New("notify: refusing to connect to a loopback, link-local, multicast, unspecified, cloud metadata or box address")

// ErrBoxAddrsUnknown means the box does not know its own addresses yet (vedette-host has not answered since the start), so a
// webhook target cannot be checked against them: the webhook is not saved or built, and no connection is made (#157).
var ErrBoxAddrsUnknown = errors.New("notify: webhook: the box's own addresses are not known yet")

// dialControl runs after name resolution, on the address about to be dialled,
// so a DNS name that resolves to a forbidden address (or rebinds to one) is
// refused too.
func dialControl(allowLoopback bool, box func() ([]netip.Addr, bool)) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errForbiddenDial
		}
		addrs, known := box()
		if !known {
			return ErrBoxAddrsUnknown
		}
		if a, err := netip.ParseAddr(host); err != nil || forbiddenAddr(a, allowLoopback, addrs) {
			return errForbiddenDial
		}
		return nil
	}
}

func webhookClient(allowLoopback bool, box func() ([]netip.Addr, bool)) *http.Client {
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
// http only for hosts on the internal list; never loopback (on http or https), never
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
	boxFn := func() ([]netip.Addr, bool) {
		out := append([]netip.Addr(nil), cfg.BoxAddrs...)
		if cfg.BoxAddrsFunc == nil {
			return out, true
		}
		more, known := cfg.BoxAddrsFunc()
		return append(out, more...), known
	}
	blocked := cfgErr("blocked_host", "The webhook cannot point at this machine, a link-local or multicast address, a cloud metadata service, or an unspecified address.")

	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, bad
	}
	// A forbidden target is named as such before the http rule, so http://169.254.169.254 (cloud metadata) gets the precise
	// sentence, as loopback does, not "plain http:// is only for internal hosts" (walk 3 G13).
	box, known := boxFn()
	if a, err := netip.ParseAddr(host); err == nil {
		if forbiddenAddr(a, cfg.allowLoopback, box) {
			return nil, blocked
		}
	} else {
		labels := strings.Split(host, ".")
		if numericLabelRE.MatchString(labels[len(labels)-1]) {
			return nil, bad // a number-like host is an IP in disguise
		}
		if !cfg.allowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost")) || metadataName(host) {
			return nil, blocked
		}
	}
	if u.Scheme == "http" && !internalHost(host) {
		return nil, cfgErr("insecure_url", "Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.")
	}
	if !isSet(cfg.SigningKey) {
		return nil, cfgErr("secret_required", "Enter the webhook signing key.")
	}
	if len(cfg.SigningKey.Reveal()) < minSigningKey {
		return nil, cfgErr("bad_secret", "The signing key needs at least 16 characters. Press Generate random if you want a random one.")
	}
	if !known { // every field is fine, but the target cannot be checked against the box's own addresses yet
		return nil, ErrBoxAddrsUnknown
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client := cfg.Client
	if client == nil {
		client = webhookClient(cfg.allowLoopback, boxFn)
	}
	return &webhookSender{url: secrets.NewValue(u.String()), to: u.Scheme + "://" + u.Host, key: cfg.SigningKey, client: clientOrDefault(client), now: now}, nil
}

func (*webhookSender) Type() Type { return Webhook }

type webhookPayload struct {
	Event    string      `json:"event"`          // incident.created, vuln.created, approval.requested or test
	Kind     string      `json:"kind,omitempty"` // incidents: trap, bad_address, log_anomaly or unknown_device
	ID       string      `json:"id"`
	Severity string      `json:"severity"`
	Title    string      `json:"title"`
	Devices  []DeviceRef `json:"devices"`
	What     string      `json:"what,omitempty"`
	Action   string      `json:"action,omitempty"`
	Items    []string    `json:"items,omitempty"`
	URL      string      `json:"url,omitempty"`
}

// newWebhookPayload builds the JSON body of a webhook call from a normalised Message.
func newWebhookPayload(n Message, link string) webhookPayload {
	event := n.Kind
	switch n.Kind {
	case "incident", "vuln":
		event += ".created"
	case "approval":
		event += ".requested"
	}
	devices := n.Devices
	if devices == nil {
		devices = []DeviceRef{}
	}
	return webhookPayload{Event: event, Kind: n.IncidentKind, ID: n.ID, Severity: n.Severity, Title: n.Title, Devices: devices, What: n.What, Action: n.Action, Items: n.Items, URL: link}
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
	body, err := json.Marshal(newWebhookPayload(n, link))
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
