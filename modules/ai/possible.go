package ai

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/pagetext"
	"github.com/knt048/vedette/core/store"
)

// Checking possible findings. Findings asks two things of this module for a CVE it cannot decide: the text of the CVE's public
// reference pages (the box fetches them itself: the AI never browses), and, only when findings' own reading of that text decides
// nothing, the AI's proposal of a verdict with the sentence it relied on. The call runs as the explain-finding job (its profile,
// fallback, budget, skill switch and internal-only rule), with no tools, no memory and no knowledge documents; what is sent is the CVE,
// the product's vendor and name, the version and release line, and the public text. Never a device name, address or other customer
// data.

// The limits of the reference fetch.
const (
	refMaxPages     = 8 // usable pages read per CVE (a failed, empty, duplicate or non-text one leaves its place)
	refFetchTimeout = 20 * time.Second
	refTotalTimeout = 90 * time.Second
	refMaxBody      = 2 << 20
	refMaxRedirects = 3
	refScanBytes    = 1 << 20 // the page's text the box keeps: its full copy for the excerpts and the quote check
	refCacheTTL     = 6 * time.Hour
	refCacheBytes   = 48 << 20
)

// RefPage is one reference page as the box read it.
type RefPage struct {
	URL    string `json:"url"`
	Title  string `json:"title,omitempty"`
	Status string `json:"status"` // ok, failed, skipped
	Note   string `json:"note,omitempty"`
	Text   string `json:"-"` // the page's full text (its blocks one per line; JSON as sent), at most refScanBytes; "" unless ok
	JSON   bool   `json:"-"` // the page is a JSON document (a CSAF advisory)
	Empty  bool   `json:"-"` // the page answered with no advisory text (an empty page, a script-rendered shell): fetching it again gives the same
	// Blocks is the page as headings, paragraphs and table rows with their header rows (pagetext), what excerpts are cut from.
	Blocks []pagetext.Block `json:"-"`
	Bytes  int              `json:"-"` // bytes of the body as received
	final  string           // the address the page was read from, after redirects
	hash   [32]byte         // the body's hash: two references to one page are read once
}

var errRefRedirect = errors.New("ai refs: redirect refused")

// reAdvisoryContent is what a page needs to be an advisory the box can read: a CVE id or a version number.
var reAdvisoryContent = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b|\b[0-9]+\.[0-9]+`)

// refFetcher reads public reference pages over HTTPS: only global unicast addresses on port 443, checked on the resolved address and
// again in the socket's Control hook (and so on every redirect, at most refMaxRedirects), no proxy, no cookies, no credentials. Pages
// are kept for refCacheTTL by address (refCacheBytes in all), so a page many CVEs cite (a quarterly advisory) is read once.
type refFetcher struct {
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]refCached
	bytes  int
}

type refCached struct {
	page RefPage
	at   time.Time
}

func newRefFetcher(resolve func(context.Context, string) ([]netip.Addr, error), connect dialFunc) *refFetcher {
	if connect == nil {
		connect = (&net.Dialer{Timeout: 10 * time.Second, Control: newsControl}).DialContext
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port != "443" {
			return nil, errNewsAddress
		}
		ips, err := resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ai refs: resolve: %w", err)
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
	tr := &http.Transport{Proxy: nil, DialContext: dial, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: refFetchTimeout, MaxResponseHeaderBytes: 64 << 10, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}
	return &refFetcher{now: time.Now, cache: map[string]refCached{}, client: &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= refMaxRedirects || req.URL.Scheme != "https" || req.URL.User != nil || (req.URL.Port() != "" && req.URL.Port() != "443") {
			return errRefRedirect
		}
		return nil // the new host is checked by the dialer like the first
	}}}
}

// fetch reads the pages of urls, in order, until refMaxPages are read (a failed, empty, non-text or duplicate one does not count),
// within refTotalTimeout. A reference that redirects to a page read already, or whose body is one read already, is skipped as the same.
func (f *refFetcher) fetch(ctx context.Context, urls []string) []RefPage {
	ctx, cancel := context.WithTimeout(ctx, refTotalTimeout)
	defer cancel()
	out := []RefPage{}
	read := 0
	finals, bodies := map[string]string{}, map[[32]byte]string{}
	for _, raw := range urls {
		if read == refMaxPages {
			out = append(out, RefPage{URL: raw, Status: "skipped", Note: fmt.Sprintf("only %d pages are read per CVE", refMaxPages)})
			continue
		}
		p := f.cached(ctx, raw) // a page that fails leaves its place to the next one
		if p.Status == "ok" {
			first, seen := finals[p.final]
			if !seen {
				first, seen = bodies[p.hash]
			}
			if seen {
				out = append(out, RefPage{URL: raw, Status: "skipped", Note: "the same page as " + clipRunes(first, 200)})
				continue
			}
			finals[p.final], bodies[p.hash] = raw, raw
			read++
		}
		out = append(out, p)
	}
	return out
}

// cached is one, kept for refCacheTTL when it was read or answered for good (no text, not a text page); a failure that may pass is
// asked again.
func (f *refFetcher) cached(ctx context.Context, raw string) RefPage {
	now := f.now()
	f.mu.Lock()
	c, ok := f.cache[raw]
	f.mu.Unlock()
	if ok && now.Sub(c.at) < refCacheTTL {
		return c.page
	}
	p := f.one(ctx, raw)
	if p.Status != "ok" && !p.Empty {
		return p
	}
	size := len(p.Text) * 2 // the text and its blocks
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.cache[raw]; ok {
		f.bytes -= len(old.page.Text) * 2
	}
	for f.bytes+size > refCacheBytes && len(f.cache) > 0 { // the oldest go first
		oldest := ""
		for k, e := range f.cache {
			if oldest == "" || e.at.Before(f.cache[oldest].at) {
				oldest = k
			}
		}
		f.bytes -= len(f.cache[oldest].page.Text) * 2
		delete(f.cache, oldest)
	}
	f.cache[raw] = refCached{page: p, at: now}
	f.bytes += size
	return p
}

// refTextType says a Content-Type is a text page the box reads (HTML, plain text, JSON, XML); "" (none given) is read and sniffed.
func refTextType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	return ct == "" || strings.HasPrefix(ct, "text/") || ct == "application/xhtml+xml" || ct == "application/json" || strings.HasSuffix(ct, "+json") ||
		ct == "application/xml" || strings.HasSuffix(ct, "+xml")
}

func (f *refFetcher) one(ctx context.Context, raw string) RefPage {
	p := RefPage{URL: raw, Status: "failed"}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		p.Status, p.Note = "skipped", "not an https address"
		return p
	}
	ctx, cancel := context.WithTimeout(ctx, refFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		p.Status, p.Note = "skipped", "not an address"
		return p
	}
	req.Header.Set("Accept", "text/html, application/json;q=0.9, text/plain;q=0.8")
	req.Header.Set("User-Agent", "Vedette")
	resp, err := f.client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, errRefRedirect):
			p.Note = "the site redirected to an address the box does not follow"
		case errors.Is(err, errNewsAddress):
			p.Note = "the site's address is not a public internet address"
		case errors.Is(err, context.DeadlineExceeded):
			p.Note = "the site did not answer in time"
		default:
			p.Note = "the site could not be reached"
		}
		return p
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		p.Note = "the site answered " + strconv.Itoa(resp.StatusCode)
		return p
	}
	ct := resp.Header.Get("Content-Type")
	if !refTextType(ct) { // a download (a ZIP, an installer, a PDF) is not read at all
		p.Empty, p.Note = true, "the reference is not a text page ("+clipRunes(strings.Split(ct, ";")[0], 80)+")"
		return p
	}
	if resp.ContentLength > refMaxBody {
		p.Note = "the page is larger than 2 MiB"
		return p
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, refMaxBody+1))
	if err != nil {
		p.Note = "the page could not be read"
		return p
	}
	if len(body) > refMaxBody {
		p.Note = "the page is larger than 2 MiB"
		return p
	}
	p.Bytes, p.hash, p.final = len(body), sha256.Sum256(body), resp.Request.URL.String()
	ct = strings.ToLower(ct)
	switch {
	case strings.Contains(ct, "json") || json.Valid(body) && len(body) > 0 && (body[0] == '{' || body[0] == '['):
		p.JSON, p.Text = true, clipBytes(string(body), refScanBytes)
		p.Blocks = pagetext.Plain(p.Text, true)
	case strings.Contains(ct, "html") || strings.Contains(strings.ToLower(string(body[:min(len(body), 512)])), "<html"):
		var title string
		p.Blocks, title = pagetext.HTML(sanitizeWeb(string(body)))
		p.Blocks = pagetext.Clip(p.Blocks, refScanBytes)
		p.Text, p.Title = pagetext.Text(p.Blocks), clipRunes(title, 200)
	default:
		p.Text = clipBytes(sanitizeWeb(string(body)), refScanBytes)
		p.Blocks = pagetext.Plain(p.Text, false)
	}
	// A page with no CVE id and no version number in its text states nothing a check can use: a script-rendered portal answers a
	// shell ("Loading", "Refresh") the box cannot run. It is not read (it leaves its place to the next page) and is marked empty:
	// fetching it again gives the same.
	if strings.TrimSpace(p.Text) == "" || !reAdvisoryContent.MatchString(p.Text) {
		p.Text, p.Blocks, p.Empty = "", nil, true
		p.Note = "the page has no advisory text the box can read (it may need a browser)"
		return p
	}
	p.Status = "ok"
	return p
}

// FetchReferences reads a CVE's public reference pages (findings chooses which, by their tags): the box's own HTTPS requests, no AI,
// no tokens. Each page says whether it was read and why not.
func (s *Service) FetchReferences(ctx context.Context, urls []string) []RefPage {
	return s.refs.fetch(ctx, urls)
}

// autoReadSummary starts the summary of every call of the automatic reading, answered or failed (its count tag): the daily count of
// reads counts these rows.
const autoReadSummary = "Read the vendor's statement"

// dailyReadsReached is the automatic reading's own stop: today's number of reads (Settings.DailyReads) is used up; it goes on tomorrow.
func (s *Service) dailyReadsReached() error {
	wait := max(int(math.Ceil(s.meter.DayStart().AddDate(0, 0, 1).Sub(s.cfg.Clock()).Seconds())), 1)
	return apierr.New(http.StatusTooManyRequests, "budget_reached", "Today's automatic AI reads of vendor advisories are used up; the reading goes on tomorrow. "+
		"An administrator can change the number in Settings, AI assistant.").With("retry_after", wait)
}

// AutoRead is how the automatic reading of vendor advisories stands: on or off, today's number of reads, how many are left, and whether
// background jobs are paused by this month's budget.
type AutoRead struct {
	Auto   bool
	Daily  int
	Used   int
	Left   int
	Paused bool
	// IdentifyUsed is how many of today's calls identified software (identity.go); IdentifyLeft how many more it may make: at most
	// half of the daily number, so the reading of advisories keeps its share.
	IdentifyUsed, IdentifyLeft int
}

// AutoReadState reads how the automatic reading stands now. Its daily number counts the automatic identification of software too
// (identity.go): both are background AI calls of explaining findings under one switch. Every call that reached the provider counts,
// answered or failed (its rows carry the call's tag, JobSpec.countTag); a call stopped before it was sent ("Not sent") does not.
func (s *Service) AutoReadState(ctx context.Context) AutoRead {
	cfg := s.snap.Load().cfg
	st := AutoRead{Auto: !cfg.AutoReadOff, Daily: cfg.dailyReads()}
	start := store.FormatTS(s.meter.DayStart())
	count := func(job Job, tag string) (int, error) {
		var n int
		err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM ai_activity WHERE job = ? AND trigger = 'system:schedule' AND ts >= ? AND
			substr(summary, 1, ?) = ? AND substr(summary, 1, ?) <> ?`, string(job), start, len(tag), tag, len(tag)+10, tag+": Not sent").Scan(&n)
		return n, err
	}
	read, err1 := count(JobExplainFinding, autoReadSummary)
	ident, err2 := count(JobExplainFinding, autoIdentifySummary)
	research, err3 := count(JobResearchCVEs, autoResearchSummary) // each layer of an automatic research is one call
	st.Used, st.IdentifyUsed = read+ident+research, ident
	if err1 != nil || err2 != nil || err3 != nil {
		st.Used, st.IdentifyUsed = st.Daily, st.Daily // a count that cannot be read holds the reading: never more reads than set
	}
	st.Left = max(0, st.Daily-st.Used)
	st.IdentifyLeft = min(st.Left, max(0, identifyShare(st.Daily)-st.IdentifyUsed))
	st.Paused = s.scheduledPaused()
	return st
}

// identifyShare is the most automatic calls a day the identification of software may make: half of the daily number (at least one).
func identifyShare(daily int) int { return max(1, daily/2) }
