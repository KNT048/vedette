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
	"slices"
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
	// (NVD). The whole request is then bounded by the context deadline only.
	HeaderTimeout time.Duration
	// Stream, when set, reads the body as it arrives instead of Response.Body (the distribution archives are
	// tens of megabytes and are parsed while they download). The reader stops with ErrTooLarge past MaxBytes, counted
	// after the transport's gzip decoding; the client's whole-request timeout is lifted, so the context deadline is the
	// bound. Its error is the error of the fetch.
	Stream func(io.Reader) error `json:"-"`
	// RedirectHosts are the other hosts a redirect may lead to (exact names, lower case): a source that serves its files from a
	// storage host of its own (GitHub's release files). Every hop still passes the address guard and never leaves https.
	RedirectHosts []string
	// From, when above zero, asks for the body from that byte on (Range: bytes=From-), to resume a download: Response.Partial says
	// the source answered with that part. A source that answers the whole body (200) is read from that byte on too, the bytes before
	// it skipped, so the caller always gets the body from From on.
	From int64
}

// Response is what came back.
type Response struct {
	Body         []byte // nil when NotModified
	NotModified  bool
	ETag         string
	LastModified string
	FinalURL     string    // may carry a query string: do not log it
	Date         time.Time // the server's Date header (zero when missing or unreadable): its clock, for the CISA list's plausibility (#946 r2)
	// Partial: the source answered the part asked for by Request.From (206). Total is the whole body's size when the source said it
	// (Content-Range of a part, Content-Length of a whole answer), else -1.
	Partial bool
	Total   int64
}

// Fetcher performs the HTTPS GET of a feed. The zero value works.
type Fetcher struct {
	Client  *http.Client // nil uses NewClient(DefaultFetchTimeout)
	Version string       // product version for the User-Agent
	// BoxAddrs lists the machine's addresses (vedette-host), asked again at every connection: a pull never connects to Vedette's
	// own ports on one of them, nor to loopback or the container's own interfaces on any port. known false
	// (vedette-host has never answered) allows only global unicast destinations. nil: none.
	BoxAddrs func() (addrs []netip.Addr, known bool)

	// Gateway is the container's default gateway, which is the machine too (set by wiring; nil: not asked).
	Gateway func() (netip.Addr, bool)

	// Self lists addresses that are Vedette itself beyond this process's own interfaces (the honeypot's decoys): refused on every
	// port, like loopback. nil: none.
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
// fetchURLMaxLen is the longest request address the fetcher accepts.
const fetchURLMaxLen = 2048

func checkRedirect(req *http.Request, via []*http.Request) error {
	return checkRedirectTo(req, via, nil)
}

// checkRedirectTo is checkRedirect allowing a hop to one of hosts too.
func checkRedirectTo(req *http.Request, via []*http.Request, hosts []string) error {
	if len(via) > maxRedirects {
		return fail(ErrRedirect, "The feed redirected more than %d times.", maxRedirects)
	}
	if err := checkURL(req.URL.String(), fetchURLMaxLen); err != nil {
		return fail(ErrRedirect, "The feed redirected to an address that is not allowed.")
	}
	req.Header.Del("Referer") // the previous address may carry a token in its query
	prev := via[len(via)-1]
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fail(ErrRedirect, "The feed redirected from https to http.")
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) && (req.URL.Port() != "" || !slices.Contains(hosts, strings.ToLower(req.URL.Hostname()))) {
		return fail(ErrRedirect, "The feed redirected to another host (%s). Set the feed address to the final address.", quoteVal(req.URL.Hostname()))
	}
	return nil
}

// rangeTotal reads "bytes <from>-<last>/<total>" of a part asked from from on: the whole body's size; ok false for another part.
func rangeTotal(h string, from int64) (int64, bool) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(h), "bytes ")
	if !ok {
		return 0, false
	}
	span, size, ok := strings.Cut(spec, "/")
	first, last, ok2 := strings.Cut(span, "-")
	a, e1 := strconv.ParseInt(first, 10, 64)
	b, e2 := strconv.ParseInt(last, 10, 64)
	n, e3 := strconv.ParseInt(size, 10, 64)
	if !ok || !ok2 || e1 != nil || e2 != nil || e3 != nil || a != from || b < a || b != n-1 {
		return 0, false
	}
	return n, true
}

func validValidator(s string) bool {
	return s != "" && len(s) <= maxValidatorLen && !hasControl(s) && !strings.ContainsAny(s, "\r\n")
}

// Fetch does one GET to exactly req.URL: no body, no customer data, fixed
// User-Agent, size cap enforced while reading, conditional headers when given,
// 304 reported as NotModified. Without a context deadline it applies
// DefaultFetchTimeout.
func (f Fetcher) Fetch(ctx context.Context, req Request) (*Response, error) {
	if err := checkURL(req.URL, fetchURLMaxLen); err != nil {
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
	if len(req.RedirectHosts) > 0 {
		hosts := req.RedirectHosts
		client.CheckRedirect = func(r *http.Request, via []*http.Request) error { return checkRedirectTo(r, via, hosts) }
	}
	if req.From > 0 {
		hreq.Header.Set("Range", "bytes="+strconv.FormatInt(req.From, 10)+"-")
	}
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

	out := &Response{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), FinalURL: resp.Request.URL.String(), Total: resp.ContentLength}
	if d, derr := http.ParseTime(resp.Header.Get("Date")); derr == nil {
		out.Date = d.UTC()
	}
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
	case resp.StatusCode == http.StatusPartialContent && req.From > 0:
		total, ok := rangeTotal(resp.Header.Get("Content-Range"), req.From)
		if !ok {
			return nil, fail(ErrBadSample, "The source answered a part Vedette did not ask for.")
		}
		out.Partial, out.Total = true, total
	case resp.StatusCode != http.StatusOK:
		return nil, &StatusError{Code: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	if resp.ContentLength > limit {
		return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
	}
	var body io.Reader = resp.Body
	if req.From > 0 && !out.Partial { // the whole body came: what was asked for starts at From
		if n, err := io.CopyN(io.Discard, body, req.From); err != nil || n != req.From {
			return nil, fmt.Errorf("feeds: fetch %s: the answer is shorter than the part already read", host)
		}
	}
	if req.Stream != nil {
		if err := req.Stream(newCapReader(body, limit)); err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
			}
			return nil, err
		}
		return out, nil
	}
	data, err := io.ReadAll(newCapReader(body, limit))
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
		}
		return nil, fmt.Errorf("feeds: fetch %s: reading the answer: %w", host, err)
	}
	out.Body = data
	return out, nil
}
