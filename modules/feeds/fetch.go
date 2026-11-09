package feeds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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

// StatusError is a non-200 answer (other than a usable 304).
type StatusError struct{ Code int }

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
}

var versionTokenRE = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,32}$`)

// UserAgent is the fixed identity of every pull: no box id, no host name (FORBID-2).
func (f Fetcher) UserAgent() string {
	if versionTokenRE.MatchString(f.Version) {
		return "Vedette/" + f.Version
	}
	return "Vedette/dev"
}

// NewClient returns an http.Client with explicit timeouts (never DefaultClient).
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
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
	if err := CheckURL(req.URL.String()); err != nil {
		return fail(ErrRedirect, "The feed redirected to an address that is not allowed.")
	}
	prev := via[len(via)-1]
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fail(ErrRedirect, "The feed redirected from https to http.")
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fail(ErrRedirect, "The feed redirected to another host (%s). Set the feed address to the final address.", req.URL.Hostname())
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
	if err := CheckURL(req.URL); err != nil {
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
		return nil, &StatusError{Code: resp.StatusCode}
	}
	if resp.ContentLength > limit {
		return nil, fail(ErrTooLarge, "The source is larger than %d bytes; Vedette would skip it.", limit)
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
