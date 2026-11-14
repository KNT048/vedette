package feeds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fetch limits.
const (
	DefaultFetchTimeout = 60 * time.Second
	maxRedirects        = 5
	maxValidatorLen     = 256
)

// ErrRedirect is a redirect the fetcher refuses.
var ErrRedirect = errors.New("feeds: redirect refused")

// StatusError is a non-200 answer (other than a usable 304). RetryAfter is the answer's Retry-After (seconds or an
// HTTP date; 0 when absent or unreadable, at most maxRetryAfter).
type StatusError struct {
	Code       int
	RetryAfter time.Duration
}

// maxRetryAfter bounds what a source's Retry-After can ask for.
const maxRetryAfter = time.Hour

// retryAfter reads a Retry-After header: delay-seconds or an HTTP date (RFC 9110 10.2.3).
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		return 0
	}
	return min(d, maxRetryAfter)
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("feeds: the source answered HTTP %d", e.Code)
}

// Request is one pull of one declared feed address (INV-1).
type Request struct {
	URL          string
	Auth         Auth
	ETag         string // sent as If-None-Match
	LastModified string // sent as If-Modified-Since
	MaxBytes     int64  // 0 means MaxBodyBytes
	// HeaderTimeout, when longer than the client's, is how long the source may take before it starts to answer
	// (NVD: W3-1). The whole request is then bounded by the context deadline only.
	HeaderTimeout time.Duration
	// Stream, when set, reads the body as it arrives instead of Response.Body (D-516: the distribution archives are
	// tens of megabytes and are parsed while they download). The reader stops with ErrTooLarge past MaxBytes, counted
	// after the transport's gzip decoding; the client's whole-request timeout is lifted, so the context deadline is the
	// bound. Its error is the error of the fetch.
	Stream func(io.Reader) error
}

// Response is what came back.
type Response struct {
	Body         []byte // nil when NotModified
	NotModified  bool
	ETag         string
	LastModified string
	FinalURL     string // may carry a query string: do not log it
}

// Fetcher performs the HTTPS GET of a feed. The zero value works.
type Fetcher struct {
	Client  *http.Client // nil uses NewClient(DefaultFetchTimeout)
	Version string       // product version for the User-Agent
	// BoxAddrs lists the machine's addresses (vedette-host), asked again at every connection: a pull never connects to Vedette's
	// own ports on one of them, nor to loopback or the container's own interfaces on any port (D-208, D-446). known false
	// (vedette-host has never answered) allows only global unicast destinations (D-208 (2)). nil: none.
	BoxAddrs func() (addrs []netip.Addr, known bool)

	// Gateway is the container's default gateway, which is the machine too (set by wiring; nil: not asked).
	Gateway func() (netip.Addr, bool)

	// Self lists addresses that are Vedette itself beyond this process's own interfaces (the honeypot's decoys): refused on every
	// port, like loopback (D-446). nil: none.
	Self func() []netip.Addr

	dialOverride func(ctx context.Context, network, addr string) (net.Conn, error) // tests only (unexported)

	allowLoopback bool // tests only (unexported): the httptest servers live on 127.0.0.1
}

var versionTokenRE = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,32}$`)

// UserAgent is the fixed identity of every pull: no box id, no host name (FORBID-2).
func (f Fetcher) UserAgent() string {
	if versionTokenRE.MatchString(f.Version) {
		return "Vedette/" + f.Version
	}
	return "Vedette/dev"
}

// NewClient returns an http.Client with explicit timeouts (never DefaultClient)
// whose connections go through the address guard: link-local and metadata
// addresses are refused for every feed, plain http only reaches private or
// loopback addresses, and the host is resolved once per connection (no DNS
// rebinding). Environment proxies are not used. A Client supplied to Fetcher
// instead of this one is the caller's responsibility (tests only).
func NewClient(timeout time.Duration) *http.Client { return newClient(timeout, systemResolver) }

func newClient(timeout time.Duration, res resolver) *http.Client {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           guardedDial(res),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// slowHeaders lets the client wait up to d for the answer's headers: a transport with a shorter
// ResponseHeaderTimeout is replaced by a clone (same guarded dialer) the caller closes after the request, and the
// client's own whole-request timeout is lifted (Fetch always has a context deadline). It returns that clone, or nil.
func slowHeaders(c *http.Client, d time.Duration) *http.Transport {
	c.Timeout = 0
	t, ok := c.Transport.(*http.Transport)
	if !ok || t.ResponseHeaderTimeout == 0 || t.ResponseHeaderTimeout >= d {
		return nil
	}
	t = t.Clone()
	t.ResponseHeaderTimeout = d
	c.Transport = t
	return t
}

// capReader fails with ErrTooLarge once more than the limit was read, so an
// endless or decompressed-bomb body stops at a hard ceiling.
type capReader struct {
	r    io.Reader
	left int64
}

func newCapReader(r io.Reader, limit int64) *capReader { return &capReader{r: r, left: limit} }

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, ErrTooLarge
	}
	return n, err
}

// checkRedirect is the policy for every hop. Mirrors and CDNs do redirect, but
// a hop to another host would contact a source that is not declared (INV-1,
// FORBID-3, the Privacy list of INV-13) and could carry the credentials along,
// so only same-host redirects are followed; the error names the other host so
// an admin can set the final address. Each hop must pass INV-2 and never
// downgrades https to http.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fail(ErrRedirect, "The feed redirected more than %d times.", maxRedirects)
	}
	if err := checkURL(req.URL.String(), EPSSURLMaxLen); err != nil {
		return fail(ErrRedirect, "The feed redirected to an address that is not allowed.")
	}
	req.Header.Del("Referer") // the previous address may carry a token in its query
	prev := via[len(via)-1]
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fail(ErrRedirect, "The feed redirected from https to http.")
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fail(ErrRedirect, "The feed redirected to another host (%s). Set the feed address to the final address.", quoteVal(req.URL.Hostname()))
	}
	return nil
}

func validValidator(s string) bool {
	return s != "" && len(s) <= maxValidatorLen && !hasControl(s) && !strings.ContainsAny(s, "\r\n")
}

// Fetch does one GET to exactly req.URL: no body, no customer data, fixed
// User-Agent, size cap enforced while reading, conditional headers when given,
// 304 reported as NotModified. Without a context deadline it applies
// DefaultFetchTimeout.
func (f Fetcher) Fetch(ctx context.Context, req Request) (*Response, error) {
	if err := checkURL(req.URL, EPSSURLMaxLen); err != nil {
		return nil, err
	}
	if req.Auth.Type != "" && req.Auth.Type != AuthNone {
		if err := CheckAuth(req.Auth.Type, req.Auth.HeaderName, req.Auth.Username, nil, req.Auth.Secret.IsSet()); err != nil {
			return nil, err
		}
	}
	limit := req.MaxBytes
	if limit <= 0 {
		limit = MaxBodyBytes
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultFetchTimeout)
		defer cancel()
	}
	target := strings.TrimSpace(req.URL)
	scheme := "https"
	if strings.HasPrefix(strings.ToLower(target), "http://") {
		scheme = "http"
	}
	ctx = context.WithValue(context.WithValue(ctx, schemeKey{}, scheme), guardKey{}, &destGuard{box: f.BoxAddrs, gateway: f.Gateway, self: f.Self, dial: f.dialOverride, allowLoopback: f.allowLoopback})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fail(ErrInvalidURL, "Enter a full address such as https://example.com/feed.json.")
	}
	hreq.Header.Set("User-Agent", f.UserAgent())
	hreq.Header.Set("Accept", "*/*")
	conditional := false
	if validValidator(req.ETag) {
		hreq.Header.Set("If-None-Match", req.ETag)
		conditional = true
	}
	if validValidator(req.LastModified) {
		hreq.Header.Set("If-Modified-Since", req.LastModified)
		conditional = true
	}
	switch req.Auth.Type {
	case AuthBearer:
		hreq.Header.Set("Authorization", "Bearer "+req.Auth.Secret.Reveal())
	case AuthHeader:
		hreq.Header.Set(req.Auth.HeaderName, req.Auth.Secret.Reveal())
	case AuthBasic:
		hreq.SetBasicAuth(strings.TrimSpace(req.Auth.Username), req.Auth.Secret.Reveal())
	}

	var client http.Client
	if f.Client != nil {
		client = *f.Client // a copy: the redirect policy below must always apply
	} else {
		client = *NewClient(DefaultFetchTimeout)
	}
	client.CheckRedirect = checkRedirect
	if req.Stream != nil {
		client.Timeout = 0 // the context deadline bounds a streamed body (Fetch always has one)
	}
	if req.HeaderTimeout > 0 {
		if t := slowHeaders(&client, req.HeaderTimeout); t != nil {
			defer t.CloseIdleConnections()
		}
	}

	host := hreq.URL.Hostname()
	resp, err := client.Do(hreq)
	if err != nil {
		// The URL may carry a token in its query: report the host and the cause only.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("feeds: fetch %s: %w", host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	out := &Response{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), FinalURL: resp.Request.URL.String()}
	if !validValidator(out.ETag) {
		out.ETag = ""
	}
	if !validValidator(out.LastModified) {
		out.LastModified = ""
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && conditional:
		out.NotModified = true
		return out, nil
	case resp.StatusCode != http.StatusOK:
		return nil, &StatusError{Code: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	if resp.ContentLength > limit {
		return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
	}
	if req.Stream != nil {
		if err := req.Stream(newCapReader(resp.Body, limit)); err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
			}
			return nil, err
		}
		return out, nil
	}
	body, err := io.ReadAll(newCapReader(resp.Body, limit))
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
		}
		return nil, fmt.Errorf("feeds: fetch %s: reading the answer: %w", host, err)
	}
	out.Body = body
	return out, nil
}
