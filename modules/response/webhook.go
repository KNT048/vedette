package response

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/netguard"
)

// webhook_call: a generic HTTPS POST of a short text (a ticket system, an automation tool). Same guard as the webhook
// channel of notify: no loopback, link-local, multicast, unspecified, cloud metadata or box address, in any transition form
// (core/netguard, shared with the other outbound guards, D-411), checked on the resolved address at connect time (so a name that
// resolves to one, or rebinds to one, is refused too), no redirects, no proxy, timeouts and size caps. Nothing on the customer's network changes (INV-1: a box action), and the URL is a secret that never reaches
// the log or the API.

const (
	webhookTimeout  = 15 * time.Second
	webhookBodyCap  = 64 << 10
	webhookReplyCap = 64 << 10
	minSigningKey   = 16
)

var (
	numericLabelRE   = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)$`)
	errForbiddenDial = errors.New("response: webhook: refusing to connect to a loopback, link-local, multicast, unspecified, cloud metadata or box address")
)

// forbiddenAddr reports whether a webhook may never connect to a: each of its forms (the address and the IPv4 address a NAT64, 6to4
// or IPv4-compatible form carries) is judged. allowLoopback is for the package tests only.
func forbiddenAddr(a netip.Addr, allowLoopback bool, box []netip.Addr) bool {
	for _, f := range netguard.Forms(a) {
		if f.IsLoopback() {
			if !allowLoopback {
				return true
			}
		} else if netguard.Always(f) {
			return true
		}
		for _, b := range box {
			if allowLoopback && b.Unmap().IsLoopback() {
				continue // tests only: the interface list holds 127.0.0.1
			}
			if b.Unmap().WithZone("") == f {
				return true
			}
		}
	}
	return false
}

func dialControl(allowLoopback bool, box func() ([]netip.Addr, error)) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errForbiddenDial
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return errForbiddenDial
		}
		list, err := box()
		if err != nil || forbiddenAddr(a, allowLoopback, list) { // the box addresses cannot be read: refuse, do not guess
			return errForbiddenDial
		}
		return nil
	}
}

func (s *Service) guardedClient() *http.Client {
	if s.webhookClient != nil {
		return s.webhookClient
	}
	return &http.Client{
		Timeout:       webhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil, // never an environment proxy: it would see the signed body
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, Control: dialControl(s.allowLoopback, s.boxAddrs)}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: webhookTimeout,
			DisableKeepAlives:     true,
		},
	}
}

const blockedWebhook = "The webhook cannot point at this machine, a link-local or multicast address, a cloud metadata service, or an unspecified address."

// checkWebhookURL accepts an https URL without credentials whose host is not a number in disguise or a local name.
func (s *Service) checkWebhookURL(raw string) (*url.URL, error) {
	bad := shown("The webhook address must start with https:// and name a host on your network or the Internet.")
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return nil, bad
	}
	for _, r := range raw {
		if r <= ' ' || r > '~' {
			return nil, bad
		}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		box, err := s.boxAddrs()
		if err != nil {
			return nil, shown("This box's own addresses could not be read, so the webhook address cannot be checked. Nothing was sent.")
		}
		if forbiddenAddr(a, s.allowLoopback, box) {
			return nil, shown(blockedWebhook)
		}
		return u, nil
	}
	labels := strings.Split(host, ".")
	if numericLabelRE.MatchString(labels[len(labels)-1]) {
		return nil, bad // a number-like host is an IP in disguise
	}
	if !s.allowLoopback && (host == "localhost" || strings.HasSuffix(host, ".localhost")) || netguard.MetadataName(host) {
		return nil, shown(blockedWebhook)
	}
	return u, nil
}

// postWebhook sends the text of an item to the webhook. It returns a plain result, or an error whose text is safe to show.
func (s *Service) postWebhook(ctx context.Context, reqID string, it itemRec) (string, error) {
	if s.cfg.Webhooks == nil {
		return "", shown("No webhook is set up, so nothing was sent.")
	}
	t, ok, err := s.cfg.Webhooks.Target(ctx)
	if err != nil || !ok {
		return "", shown("No webhook is set up, so nothing was sent.")
	}
	if len(t.SigningKey) < minSigningKey {
		return "", shown("The webhook has no signing key of at least 16 characters, so nothing was sent.")
	}
	u, err := s.checkWebhookURL(t.URL)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"source": "vedette-response", "request_id": reqID, "item_id": it.ID, "text": it.Values[PText]})
	if err != nil || len(body) > webhookBodyCap {
		return "", shown("The webhook message is too large.")
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(t.SigningKey))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return "", shown("The webhook address is not valid.")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vedette-Timestamp", ts)
	req.Header.Set("X-Vedette-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := s.guardedClient().Do(req)
	if err != nil {
		// the error text can hold the URL: it is not passed on
		return "", shown("The webhook could not be reached. Nothing was sent.")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookReplyCap))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", shown("The webhook answered with an error (HTTP " + strconv.Itoa(resp.StatusCode) + ").")
	}
	return "The webhook answered HTTP " + strconv.Itoa(resp.StatusCode) + ".", nil
}

// shownError is an error whose text is written for the person who reads the item result: a capitalised sentence.
type shownError string

func (e shownError) Error() string { return string(e) }

func shown(s string) error { return shownError(s) }
