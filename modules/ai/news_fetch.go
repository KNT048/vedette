package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// The box fetches the public pages about a CVE itself (S-AI-3, INV-6, FORBID-6): the AI never browses. Only the hosts below are
// ever contacted, over HTTPS on port 443, with no proxy, and only the CVE id travels in a request (D-280).

// newsFeed is one public RSS or Atom feed of the fixed list. The whole feed is fetched (nothing of the box is in the request) and
// the box looks for the CVE id in it.
type newsFeed struct{ Title, URL string }

// newsFeeds is the fixed feed list (D-280): research and threat-intelligence blogs that write about exploited CVEs.
var newsFeeds = []newsFeed{
	{"watchTowr Labs", "https://labs.watchtowr.com/rss/"},
	{"GreyNoise blog", "https://www.greynoise.io/blog/rss.xml"},
	{"SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml"},
	{"Rapid7 blog", "https://www.rapid7.com/rss.xml"},
	{"Unit 42", "https://unit42.paloaltonetworks.com/feed/"},
	{"Google Project Zero", "https://projectzero.google/feed.xml"},
}

const (
	nvdHost    = "services.nvd.nist.gov"
	githubHost = "api.github.com"
)

// advisoryHosts are the vendor sites whose advisory pages the box reads when the exploited-list entry or the NVD record links to
// them (D-280). A link to any other host is shown as not fetched: links in a feed are untrusted and are never followed off this list.
// Each serves its advisory as HTML a plain GET can read (checked 2026-11-11); sites that need JavaScript are left out.
var advisoryHosts = map[string]bool{
	"sec.cloudapps.cisco.com":          true,
	"fortiguard.fortinet.com":          true,
	"www.fortiguard.com":               true,
	"security.paloaltonetworks.com":    true,
	"chromereleases.googleblog.com":    true,
	"source.android.com":               true,
	"support.apple.com":                true,
	"helpx.adobe.com":                  true,
	"learn.microsoft.com":              true,
	"www.oracle.com":                   true,
	"access.redhat.com":                true,
	"support.broadcom.com":             true,
	"www.zyxel.com":                    true,
	"supportannouncement.us.dlink.com": true,
	"wiki.zimbra.com":                  true,
	"git.kernel.org":                   true,
}

// newsHostAllowed reports whether the fetcher may contact host at all: NVD, the GitHub API, a feed of the list or an advisory site.
func newsHostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == nvdHost || host == githubHost || advisoryHosts[host] {
		return true
	}
	for _, f := range newsFeeds {
		if u, err := url.Parse(f.URL); err == nil && u.Hostname() == host {
			return true
		}
	}
	return false
}

const (
	newsFetchTimeout = 20 * time.Second // one request, redirects included; NVD without a key often takes over 15 s
	newsTotalTimeout = 30 * time.Second // every fetch of one news call
	newsMaxBody      = 2 << 20          // bytes read from one answer, after decompression
	newsMaxRedirects = 3
	newsCacheTTL     = 30 * time.Minute
	newsCacheMax     = 128
	newsLimitTTL     = time.Minute // a host's rate-limit answer is remembered this long: no request goes to that host meanwhile, for any CVE
)

// Errors of one fetch. The note a person sees is chosen from them (fetchNote); the text of the error itself is never shown, as it
// can carry what a remote site sent.
var (
	errNewsAddress  = errors.New("ai news: the address is not a public Internet address")
	errNewsHost     = errors.New("ai news: the host is not on the list")
	errNewsRedirect = errors.New("ai news: the site redirected off its own host")
	errNewsTooLarge = errors.New("ai news: the answer is too large")
	errNewsParse    = errors.New("ai news: the answer could not be read")
)

// statusError is an answer other than 200.
type statusError struct {
	code    int
	limited bool // GitHub's limit for requests without a key
}

func (e *statusError) Error() string { return fmt.Sprintf("ai news: HTTP %d", e.code) }

// newsFetcher fetches and caches the public sources. One per service; safe for concurrent use.
type newsFetcher struct {
	client  *http.Client
	now     func() time.Time
	timeout time.Duration // one request; newsFetchTimeout (tests shorten it)
	total   time.Duration // every fetch of one news call; newsTotalTimeout

	mu       sync.Mutex
	cache    map[string]newsCacheEntry
	inflight map[string]*cveLock   // the news calls running or waiting, per CVE (lockCVE)
	limited  map[string]limitEntry // per host: a rate-limit answer, remembered newsLimitTTL (D-284)
}

type limitEntry struct {
	err *statusError
	at  time.Time
}

type newsCacheEntry struct {
	v  any
	at time.Time
}

func newNewsFetcher(now func() time.Time) *newsFetcher {
	return &newsFetcher{
		client:   &http.Client{Transport: newsTransport(systemResolve, nil), CheckRedirect: newsRedirect},
		now:      now,
		timeout:  newsFetchTimeout,
		total:    newsTotalTimeout,
		cache:    map[string]newsCacheEntry{},
		inflight: map[string]*cveLock{},
		limited:  map[string]limitEntry{},
	}
}

// newsRedirect follows at most three redirects, and only on the same host over HTTPS: a site cannot send the box elsewhere.
func newsRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= newsMaxRedirects {
		return errNewsRedirect
	}
	if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) || (req.URL.Port() != "" && req.URL.Port() != "443") {
		return errNewsRedirect
	}
	return nil
}

func systemResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// newsTransport is the transport of the fetcher: no proxy, a dialer that connects only to a public address of an allowed host on
// port 443 (checked on the resolved address, and again in the socket Control hook just before connect, so DNS rebinding is
// covered), and bounded handshakes and headers. connect nil = the real connect with the Control hook; tests replace only it.
func newsTransport(resolve func(context.Context, string) ([]netip.Addr, error), connect dialFunc) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            newsDial(resolve, connect),
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  newsFetchTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns:           8,
		IdleConnTimeout:        30 * time.Second,
	}
}

func newsDial(resolve func(context.Context, string) ([]netip.Addr, error), connect dialFunc) dialFunc {
	if connect == nil {
		connect = (&net.Dialer{Timeout: 10 * time.Second, Control: newsControl}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port != "443" {
			return nil, errNewsAddress
		}
		if !newsHostAllowed(host) {
			return nil, errNewsHost
		}
		ips, err := resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ai news: resolve: %w", err)
		}
		last := errNewsAddress
		for _, ip := range ips {
			if !newsPublicAddr(ip) {
				continue
			}
			c, err := connect(ctx, network, netip.AddrPortFrom(ip.Unmap(), 443).String())
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
}

// newsControl runs on the address the socket is about to connect to: only a public address on port 443.
func newsControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() != 443 || !newsPublicAddr(ap.Addr()) {
		return errNewsAddress
	}
	return nil
}

// newsNonGlobal lists ranges that are not global unicast and are not caught by the netip predicates (D-208's list).
var newsNonGlobal = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("fec0::/10"),
}

// newsPublicAddr reports whether ip is a global unicast address: never loopback, private (RFC 1918, ULA), link-local (which holds
// the metadata services), CGNAT, multicast, a documentation or reserved range, or an IPv6 form that carries an IPv4 address (NAT64,
// 6to4, Teredo, IPv4-compatible; provider.Forbidden refuses those for every AI connection). Every host the fetcher may contact is
// a public site, so nothing else is needed; the box's own public address, if it has one, is not checked (D-280, as D-208 (2)).
func newsPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || provider.Forbidden(ip) || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, p := range newsNonGlobal {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// get fetches one URL of an allowed host and returns the body (at most newsMaxBody bytes). accept is the Accept header.
func (f *newsFetcher) get(ctx context.Context, raw, accept string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return nil, errNewsAddress
	}
	if !newsHostAllowed(u.Hostname()) {
		return nil, errNewsHost
	}
	host := strings.ToLower(u.Hostname())
	f.mu.Lock()
	lim, isLimited := f.limited[host]
	f.mu.Unlock()
	if age := f.now().Sub(lim.at); isLimited && age >= 0 && age < newsLimitTTL {
		return nil, lim.err // the host said "too many requests" a moment ago: not asked again, whatever the CVE
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errNewsAddress
	}
	req.Header.Set("Accept", accept)
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && errors.Is(ue.Err, errNewsRedirect) {
			return nil, errNewsRedirect
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		limited := strings.EqualFold(u.Hostname(), githubHost) && (resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0"))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		se := &statusError{code: resp.StatusCode, limited: limited}
		if limited || resp.StatusCode == http.StatusTooManyRequests {
			f.mu.Lock()
			f.limited[host] = limitEntry{err: se, at: f.now()} // one entry per allowed host: bounded by the list
			f.mu.Unlock()
		}
		return nil, se
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, newsMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > newsMaxBody {
		return nil, errNewsTooLarge
	}
	return body, nil
}

// cached returns what fn made for key in the last newsCacheTTL, or runs fn and keeps a result that is not an error. Asking again
// within the window reads the same inputs, so the stored answer is reused and no tokens are spent (INV-6); it also keeps the box
// under GitHub's limit for requests without a key. Errors are not kept here (a timeout is worth retrying at once); a site's
// rate-limit answer is remembered per host by get (newsLimitTTL).
func cachedFetch[T any](f *newsFetcher, key string, fn func() (T, error)) (T, error) {
	now := f.now()
	f.mu.Lock()
	e, hit := f.cache[key]
	f.mu.Unlock()
	if age := now.Sub(e.at); hit && age >= 0 && age < newsCacheTTL {
		if v, ok := e.v.(T); ok {
			return v, nil
		}
	}
	v, err := fn()
	if err != nil {
		return v, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cache) >= newsCacheMax {
		victim := ""
		for k, e := range f.cache { // an expired entry first, else the oldest
			if age := now.Sub(e.at); age < 0 || age >= newsCacheTTL {
				victim = k
				break
			}
			if victim == "" || e.at.Before(f.cache[victim].at) {
				victim = k
			}
		}
		delete(f.cache, victim)
	}
	f.cache[key] = newsCacheEntry{v: v, at: now}
	return v, nil
}

// lockCVE serialises the news calls of one CVE (D-284): a second press while the first is fetching or asking waits for it, then
// finds the fetched pages in the cache and the answer stored, so it fetches nothing and spends no tokens. A caller that gives up
// while waiting gets its context's error.
func (f *newsFetcher) lockCVE(ctx context.Context, cve string) (unlock func(), err error) {
	f.mu.Lock()
	l, ok := f.inflight[cve]
	if !ok {
		l = &cveLock{ch: make(chan struct{}, 1)}
		f.inflight[cve] = l
	}
	l.n++
	f.mu.Unlock()
	release := func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if l.n--; l.n == 0 {
			delete(f.inflight, cve)
		}
	}
	select {
	case l.ch <- struct{}{}:
		return func() { <-l.ch; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

type cveLock struct {
	ch chan struct{} // holds one token while a call of the CVE runs
	n  int           // calls holding or waiting for it, under newsFetcher.mu
}

// fetchNote is what a person sees for a source that could not be used. It never quotes the remote site.
func (f *newsFetcher) fetchNote(err error) string {
	var se *statusError
	var ne net.Error
	switch {
	case errors.As(err, &se) && se.limited:
		return "GitHub's limit for requests without a key was reached; try again in a few minutes"
	case errors.As(err, &se):
		return fmt.Sprintf("The site answered HTTP %d, source skipped", se.code)
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		if f.timeout%time.Second == 0 {
			return fmt.Sprintf("Timed out after %d seconds, source skipped", int(f.timeout/time.Second))
		}
		return fmt.Sprintf("Timed out after %s, source skipped", f.timeout)
	case errors.Is(err, errNewsTooLarge):
		return fmt.Sprintf("The answer is larger than %d MB, source skipped", newsMaxBody>>20)
	case errors.Is(err, errNewsRedirect):
		return "The site redirected to another address, source skipped"
	case errors.Is(err, errNewsAddress), errors.Is(err, errNewsHost):
		return "Not fetched: the site's address is not a public Internet address on the box's list"
	case errors.Is(err, errNewsParse):
		return "The answer could not be read, source skipped"
	}
	return "Could not connect, source skipped"
}
