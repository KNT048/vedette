package exposure

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
// flow 9): Amazon, Cloudflare and ipify. They are fixed in code: never typed in by a user, never read
// from a feed. No server of the project is involved.
var DefaultServices = []string{
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
	"https://api.ipify.org",
}

const (
	maxAnswerBody = 64 // INV-2: the answer is one address; anything longer is refused (an IPv6 address has 45 characters at most)
	probeTimeout  = 5 * time.Second
)

// The two ways a round can end without an address.
var (
	// ErrNoAgreement: some services answered, but no two of them gave the same address.
	ErrNoAgreement = errors.New("exposure: the public IP services did not agree")
	// ErrServicesDown: no service gave a usable answer.
	ErrServicesDown = errors.New("exposure: no public IP service answered")
)

// PublicServiceProber is the EgressProber over HTTPS. One Round asks each of the three services once, each
// on a connection of its own (no keep-alive), and accepts an address only when at least two services return
// the same one, so a single wrong or hostile service cannot make the box accept someone else's address. It
// follows no redirect, caps every answer at 64 bytes and has a deadline.
type PublicServiceProber struct {
	urls   []string
	client *http.Client
}

// NewPublicServiceProber returns a prober for exactly three https URLs without user info (nil: DefaultServices;
// tests pass the addresses of httptest servers). transport may be nil (a clone of the default transport); keep-alive
// is always switched off, whatever it says.
func NewPublicServiceProber(urls []string, transport *http.Transport, timeout time.Duration) (*PublicServiceProber, error) {
	if urls == nil {
		urls = DefaultServices
	}
	if len(urls) != 3 {
		return nil, errors.New("exposure: creating prober: three services are needed for a two-of-three rule")
	}
	checked := make([]string, 0, 3)
	hosts := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return nil, errors.New("exposure: creating prober: every service must be an https URL without user info")
		}
		// Two services on one host would be one vote cast twice: the 2-of-3 rule needs independent services.
		host := strings.ToLower(u.Hostname())
		if hosts[host] {
			return nil, errors.New("exposure: creating prober: the three services must be on three different hosts")
		}
		hosts[host] = true
		checked = append(checked, u.String())
	}
	if transport == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("exposure: creating prober: no default transport")
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
	return &PublicServiceProber{
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
func (p *PublicServiceProber) Round(ctx context.Context) (netip.Addr, error) {
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
func (p *PublicServiceProber) ask(ctx context.Context, u string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("exposure: asking a public IP service: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	// No User-Agent of our own: Go sets its default one, so the request carries nothing that names the product (PRIVACY flow 9).
	resp, err := p.client.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("exposure: asking a public IP service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("exposure: asking a public IP service: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBody+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("exposure: asking a public IP service: reading the answer: %w", err)
	}
	return parseAnswer(body)
}

// parseAnswer reads the answer of a service: plain text holding one address and nothing else (a trailing newline
// is trimmed). Anything else is refused, fail closed: too long, not text, not an address, an address with a zone,
// and an address that is not global unicast (unspecified, loopback, multicast, link-local).
func parseAnswer(body []byte) (netip.Addr, error) {
	if len(body) > maxAnswerBody {
		return netip.Addr{}, errors.New("exposure: a service's answer is too long")
	}
	text := string(body)
	if !utf8.ValidString(text) {
		return netip.Addr{}, errors.New("exposure: a service's answer is not text")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, errors.New("exposure: a service's answer is not an address")
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() {
		return netip.Addr{}, errors.New("exposure: a service's answer is not a global unicast address")
	}
	return a, nil
}
