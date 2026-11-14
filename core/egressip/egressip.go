// Package egressip asks three public "what is my IP" services which address the box leaves the Internet through, and says which
// IPv4 addresses are public (D-81, D-82). exposure uses it to verify and re-check the box's own public IP (INV-2, INV-13 there);
// the scan container's worker uses the same code for its own-IP fence right before nmap -sV (D-514). It is a leaf: standard
// library only, because the sensor binary links it (TestBinaryDependencies).
package egressip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// DefaultServices are the three independent public "what is my IP" services the box asks (D-81, PRIVACY
// flow 9), run by three different operators: AWS, Cloudflare and Google Cloud. They are fixed in code: never typed in by a user, never read
// from a feed. No server of the project is involved.
var DefaultServices = []string{
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
	"https://ifconfig.me/ip", // the /ip path: the root page returns HTML to user agents that are not curl
}

const (
	maxAnswerBody = 64 // INV-2: the answer is one address; anything longer is refused (an IPv6 address has 45 characters at most)
	probeTimeout  = 5 * time.Second
)

// The two ways a round can end without an address.
var (
	// ErrNoAgreement: some services answered, but no two of them gave the same address.
	ErrNoAgreement = errors.New("egressip: the public IP services did not agree")
	// ErrServicesDown: no service gave a usable answer.
	ErrServicesDown = errors.New("egressip: no public IP service answered")
)

// Prober asks the services over HTTPS. One Round asks each of the three services once, each
// on a connection of its own (no keep-alive), and accepts an address only when at least two services return
// the same one, so a single wrong or hostile service cannot make the box accept someone else's address. It
// follows no redirect, caps every answer at 64 bytes and has a deadline.
type Prober struct {
	urls   []string
	client *http.Client
}

// New returns a prober for exactly three https URLs without user info (nil: DefaultServices;
// tests pass the addresses of httptest servers). transport may be nil (a clone of the default transport); keep-alive
// is always switched off, whatever it says.
func New(urls []string, transport *http.Transport, timeout time.Duration) (*Prober, error) {
	if urls == nil {
		urls = DefaultServices
	}
	if len(urls) != 3 {
		return nil, errors.New("egressip: creating prober: three services are needed for a two-of-three rule")
	}
	checked := make([]string, 0, 3)
	hosts := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return nil, errors.New("egressip: creating prober: every service must be an https URL without user info")
		}
		// Two services on one host would be one vote cast twice: the 2-of-3 rule needs independent services.
		host := strings.ToLower(u.Hostname())
		if hosts[host] {
			return nil, errors.New("egressip: creating prober: the three services must be on three different hosts")
		}
		hosts[host] = true
		checked = append(checked, u.String())
	}
	if transport == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("egressip: creating prober: no default transport")
		}
		transport = dt.Clone()
	} else {
		transport = transport.Clone()
	}
	// No proxy, whatever the environment says: a customer proxy (HTTPS_PROXY) would make all three services answer with the
	// proxy vendor's address, and the box would verify, then scan, an IP that is not its own. TLS verification stays at its default.
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	if timeout <= 0 {
		timeout = probeTimeout
	}
	return &Prober{
		urls: checked,
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Round asks the three services at the same time and applies the rule: the address that at least two of them
// returned, else ErrNoAgreement (some answered, no two alike: one down plus two that differ ends here too) or
// ErrServicesDown (none answered).
func (p *Prober) Round(ctx context.Context) (netip.Addr, error) {
	type answer struct {
		addr netip.Addr
		err  error
	}
	answers := make([]answer, len(p.urls))
	var wg sync.WaitGroup
	for i, u := range p.urls {
		wg.Go(func() { answers[i].addr, answers[i].err = p.ask(ctx, u) })
	}
	wg.Wait()
	votes := map[netip.Addr]int{}
	answered := 0
	for _, a := range answers {
		if a.err == nil {
			answered++
			votes[a.addr]++
		}
	}
	for addr, n := range votes {
		if n >= 2 { // with three answers at most one address can have two votes
			return addr, nil
		}
	}
	if answered == 0 {
		return netip.Addr{}, ErrServicesDown
	}
	return netip.Addr{}, ErrNoAgreement
}

// ask queries one service.
func (p *Prober) ask(ctx context.Context, u string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egressip: asking a public IP service: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	// No User-Agent of our own: Go sets its default one, so the request carries nothing that names the product (PRIVACY flow 9).
	resp, err := p.client.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egressip: asking a public IP service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("egressip: asking a public IP service: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBody+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("egressip: asking a public IP service: reading the answer: %w", err)
	}
	return ParseAnswer(body)
}

// ParseAnswer reads the answer of a service: plain text holding one address and nothing else (a trailing newline
// is trimmed). Anything else is refused, fail closed: too long, not text, not an address, an address with a zone,
// and an address that is not global unicast (unspecified, loopback, multicast, link-local).
func ParseAnswer(body []byte) (netip.Addr, error) {
	if len(body) > maxAnswerBody {
		return netip.Addr{}, errors.New("egressip: a service's answer is too long")
	}
	text := string(body)
	if !utf8.ValidString(text) {
		return netip.Addr{}, errors.New("egressip: a service's answer is not text")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, errors.New("egressip: a service's answer is not an address")
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("egressip: a service's answer is not a global unicast address")
	}
	return a, nil
}

// Address ranges the box never verifies (exposure INV-3). IsPrivate, IsLoopback, IsLinkLocalUnicast and the multicast tests of
// net/netip cover the rest; these are the shared-carrier and the special-purpose blocks that are not "private" in net/netip's
// sense. The documentation ranges (RFC 5737) are in the list: no real box leaves the Internet through them.
var reservedRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// IsPublicIPv4 reports whether a is a global unicast IPv4 address the box may verify and scan: not private, loopback, link-local,
// shared carrier (CGNAT 100.64.0.0/10), documentation, multicast or reserved. IPv6 is refused for now (ponytail: the scans
// target IPv4; IPv6 is a later story).
func IsPublicIPv4(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
