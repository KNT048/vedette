package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// Checking possible findings. Findings asks two things of this module for a CVE it cannot decide: the text of the CVE's public
// reference pages (the box fetches them itself: the AI never browses), and, only when findings' own reading of that text decides
// nothing, the AI's proposal of a verdict with the sentence it relied on. The call runs as the explain-finding job (its profile,
// fallback, budget, skill switch and internal-only rule), with no tools, no memory and no knowledge documents; what is sent is the CVE,
// the product's vendor and name, the version and release line, and the public text. Never a device name, address or other customer
// data.

// The limits of the reference fetch.
const (
	refMaxPages     = 3
	refFetchTimeout = 20 * time.Second
	refTotalTimeout = 45 * time.Second
	refMaxBody      = 2 << 20
	refMaxRedirects = 3
	refTextBytes    = 8000 // per page into the prompt (findings' extraction reads up to refScanBytes)
	refScanBytes    = 200 << 10
)

// RefPage is one reference page as the box read it.
type RefPage struct {
	URL    string `json:"url"`
	Title  string `json:"title,omitempty"`
	Status string `json:"status"` // ok, failed, skipped
	Note   string `json:"note,omitempty"`
	Text   string `json:"-"` // the page's text (HTML reduced to text, JSON as sent), at most refScanBytes; "" unless ok
	JSON   bool   `json:"-"` // the page is a JSON document (a CSAF advisory)
}

var errRefRedirect = errors.New("ai refs: redirect refused")

// refFetcher reads public reference pages over HTTPS: only global unicast addresses on port 443, checked on the resolved address and
// again in the socket's Control hook (and so on every redirect, at most refMaxRedirects), no proxy, no cookies, no credentials.
type refFetcher struct {
	client *http.Client
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
	return &refFetcher{client: &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= refMaxRedirects || req.URL.Scheme != "https" || req.URL.User != nil || (req.URL.Port() != "" && req.URL.Port() != "443") {
			return errRefRedirect
		}
		return nil // the new host is checked by the dialer like the first
	}}}
}

// fetch reads the pages of urls, in order, until refMaxPages are read (a failed one does not count), within refTotalTimeout.
func (f *refFetcher) fetch(ctx context.Context, urls []string) []RefPage {
	ctx, cancel := context.WithTimeout(ctx, refTotalTimeout)
	defer cancel()
	out := []RefPage{}
	read := 0
	for _, raw := range urls {
		if read == refMaxPages {
			out = append(out, RefPage{URL: raw, Status: "skipped", Note: fmt.Sprintf("only %d pages are read per CVE", refMaxPages)})
			continue
		}
		p := f.one(ctx, raw) // a page that fails leaves its place to the next one
		if p.Status == "ok" {
			read++
		}
		out = append(out, p)
	}
	return out
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, refMaxBody+1))
	if err != nil {
		p.Note = "the page could not be read"
		return p
	}
	if len(body) > refMaxBody {
		p.Note = "the page is larger than 2 MiB"
		return p
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json") || json.Valid(body) && len(body) > 0 && (body[0] == '{' || body[0] == '['):
		p.JSON, p.Text = true, clipBytes(string(body), refScanBytes)
	case strings.Contains(ct, "html") || strings.Contains(strings.ToLower(string(body[:min(len(body), 512)])), "<html"):
		p.Text = htmlToText(string(body), refScanBytes)
	default:
		p.Text = clipBytes(sanitizeWeb(string(body)), refScanBytes)
	}
	if strings.TrimSpace(p.Text) == "" {
		p.Note = "the page has no text the box can read (it may need a browser)"
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

// PossibleItem is one product of a possible CVE the AI is asked about.
type PossibleItem struct {
	Index   int    `json:"index"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
	Line    string `json:"line"`
}

// PossibleRequest is what one proposal call sends: the CVE's public record and pages, and the products asked about.
type PossibleRequest struct {
	CVE         string
	Description string   // the CVE record's description
	Rows        []string // the record's affected rows as text ("juniper junos [23.2R2-S1, 23.2R2-S5)")
	Items       []PossibleItem
	Pages       []RefPage // the pages the box read (Status ok)
}

// PossibleVerdict is the AI's answer for one item: affected, not_affected or unsure, its reason, the sentence it relied on and the
// number of the page that sentence is from (1-based; 0 for the record).
type PossibleVerdict struct {
	Index   int    `json:"index"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
	Quote   string `json:"quote"`
	Source  int    `json:"source"`
}

// PossibleAnswer is the answer of one proposal call.
type PossibleAnswer struct {
	Verdicts   []PossibleVerdict
	Model      string
	Profile    string
	ActivityID string
}

const possibleTask = `You decide whether specific software versions are affected by one CVE, using only the public text given below as data.
For each item, answer "affected" when the text lists a release or branch range that contains the item's version, "not_affected" when the
text clearly states the item's version or its whole release line is not affected or is fixed, and "unsure" otherwise. Copy, word for word,
the one sentence of the text your answer relies on into "quote" and give the number of the data block it is from in "source" (0 for the
CVE record). Never guess a version range the text does not state. Keep "reason" to one short paragraph naming the range you used.`

const possibleSchema = `{"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","items":{"type":"object",
"additionalProperties":false,"required":["index","verdict","reason","quote","source"],"properties":{"index":{"type":"integer"},
"verdict":{"type":"string","enum":["affected","not_affected","unsure"]},"reason":{"type":"string"},"quote":{"type":"string"},
"source":{"type":"integer"}}}}}}`

// ProposePossible asks the AI to propose a verdict for each item of one CVE from the public text: one call, one activity row (INV-17).
// Errors are those of RunJob (409 ai_unavailable, 429 budget_reached or rate_limited).
func (s *Service) ProposePossible(ctx context.Context, actor string, req PossibleRequest) (PossibleAnswer, error) {
	if !cveRE.MatchString(req.CVE) || len(req.Items) == 0 {
		return PossibleAnswer{}, fmt.Errorf("ai: propose: invalid request")
	}
	var rec strings.Builder
	rec.WriteString(req.CVE + "\n" + clipBytes(sanitizeWeb(req.Description), 4000))
	for _, r := range req.Rows {
		rec.WriteString("\n" + clipBytes(sanitizeWeb(r), 300))
	}
	data := []DataBlock{{Kind: DataFeed, Source: "0: the CVE record", Text: rec.String()}}
	for i, p := range req.Pages {
		data = append(data, DataBlock{Kind: DataWeb, Source: fmt.Sprintf("%d: %s", i+1, webLine(p.URL, 200)), Text: clipBytes(p.Text, refTextBytes)})
	}
	items, err := json.Marshal(req.Items)
	if err != nil {
		return PossibleAnswer{}, err
	}
	var parsed struct {
		Items []PossibleVerdict `json:"items"`
	}
	res, err := s.RunJob(ctx, JobSpec{
		Job: JobExplainFinding, Actor: actor, Task: possibleTask, publicOnly: true,
		Question:  "Which of these items are affected by " + req.CVE + "? Items: " + string(items),
		Data:      data,
		Schema:    &provider.Schema{Name: "possible_check", JSON: json.RawMessage(possibleSchema)},
		MaxTokens: 3000,
		Summary:   fmt.Sprintf("Checked %s for %d products from %d public pages", req.CVE, len(req.Items), len(req.Pages)),
		Check: func(text string) error {
			parsed.Items = nil
			if err := json.Unmarshal([]byte(text), &parsed); err != nil {
				return err
			}
			for _, v := range parsed.Items {
				switch v.Verdict {
				case "affected", "not_affected", "unsure":
				default:
					return fmt.Errorf("verdict %q", v.Verdict)
				}
			}
			return nil
		},
	})
	if err != nil {
		return PossibleAnswer{}, err
	}
	return PossibleAnswer{Verdicts: parsed.Items, Model: res.Model, Profile: res.Profile, ActivityID: res.ActivityID}, nil
}

// PossibleReady is nil when a proposal call can run (the module, a profile for explain-finding, its skill on).
func (s *Service) PossibleReady() error { return s.Ready(JobExplainFinding) }
