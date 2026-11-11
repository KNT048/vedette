package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// FetchedSource is one source the box tried for a news call: what it was, where, and whether it could be used (S-AI-3).
type FetchedSource struct {
	Kind   string `json:"kind"` // advisory, github, rss
	Title  string `json:"title"`
	URL    string `json:"url"`
	Status string `json:"status"` // ok, failed
	Note   string `json:"note"`
}

// NewsResult is the latest on a CVE: the sources the box fetched and the AI's summary of them (S-AI-3). It carries model, profile
// and tokens, and the page shows it as AI-generated (INV-5, S-AI-6).
type NewsResult struct {
	CVE         string          `json:"cve"`
	GeneratedAt string          `json:"generated_at"`
	Sources     []FetchedSource `json:"sources"`
	Lines       []string        `json:"lines"`
	Citations   []Citation      `json:"citations"`
	Model       string          `json:"model"`
	Profile     string          `json:"profile"`
	Tokens      struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
}

// newsBody is what is stored in ai_result.payload for kind news.
type newsBody struct {
	Sources   []FetchedSource `json:"sources"`
	Lines     []string        `json:"lines"`
	Citations []Citation      `json:"citations"`
}

// newsAnswer is the schema the model follows. The box writes the labels of the lines, so each answer says the three things the story
// asks for, in the same order.
type newsAnswer struct {
	Exploited     string   `json:"exploited"`
	PublicExploit string   `json:"public_exploit"`
	Workaround    string   `json:"workaround"`
	Other         []string `json:"other"`
}

const newsSchema = `{"type":"object","properties":{"exploited":{"type":"string"},"public_exploit":{"type":"string"},"workaround":{"type":"string"},"other":{"type":"array","items":{"type":"string"}}},"required":["exploited","public_exploit","workaround","other"],"additionalProperties":false}`

const newsTask = `Summarise the latest public information about one exploited vulnerability for a small-company IT person, in plain English. Use only the data blocks: the exploited-list entry, and the pages the box fetched (the NVD record, a vendor advisory, a GitHub repository search, posts of security blogs). In "exploited" say whether it is exploited in the wild and since when, with the source. In "public_exploit" say whether public exploit or proof-of-concept code appears to exist: a repository that names a CVE may be a scanner, a fake or malware, so say "appears" and never tell the reader to run code from it. In "workaround" give the vendor's fix or mitigation, or say the sources do not give one. In "other" add at most three short points that matter (a new post, a change in severity, a source that could not be fetched). At most three short sentences in each field. Do not invent versions, dates, names or links that are not in the data. Reply with one JSON object only.`

const (
	maxNewsLine  = 600
	maxNewsOther = 3
	maxCitations = 12
)

func parseNews(text string) (newsAnswer, error) {
	var a newsAnswer
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || dec.More() || !hasKeys(text, "exploited", "public_exploit", "workaround", "other") {
		return newsAnswer{}, ErrBadOutput
	}
	a.Exploited, a.PublicExploit, a.Workaround = cleanLine(a.Exploited, maxNewsLine), cleanLine(a.PublicExploit, maxNewsLine), cleanLine(a.Workaround, maxNewsLine)
	if a.Exploited == "" || a.PublicExploit == "" || a.Workaround == "" {
		return newsAnswer{}, ErrBadOutput
	}
	other := []string{}
	for _, s := range a.Other {
		if s = cleanLine(s, maxNewsLine); s != "" && len(other) < maxNewsOther {
			other = append(other, s)
		}
	}
	a.Other = other
	return a, nil
}

func (a newsAnswer) lines() []string {
	return append([]string{"Exploited: " + a.Exploited, "Public exploit code: " + a.PublicExploit, "Workaround: " + a.Workaround}, a.Other...)
}

// newsSource is the outcome of one source: the row the page lists, the data block for the prompt (nil when there is nothing to
// send: a failure, or a feed that does not name the CVE) and the citations it gives.
type newsSource struct {
	row   FetchedSource
	block *DataBlock
	cites []Citation
}

func (f *newsFetcher) failedSource(kind, title, link string, err error) newsSource {
	return newsSource{row: FetchedSource{Kind: kind, Title: title, URL: link, Status: "failed", Note: f.fetchNote(err)}}
}

func sizeNote(n int) string {
	if n < 1024 {
		return fmt.Sprintf("Fetched, %d bytes", n)
	}
	return fmt.Sprintf("Fetched, %d KB", (n+1023)/1024)
}

// nvdSource fetches the NVD record. It also returns the vendor links the record names.
func (f *newsFetcher) nvdSource(ctx context.Context, cve string) (newsSource, []string) {
	page := "https://nvd.nist.gov/vuln/detail/" + cve
	type res struct {
		info nvdInfo
		size int
	}
	r, err := cachedFetch(f, "nvd "+cve, func() (res, error) {
		body, err := f.get(ctx, "https://"+nvdHost+"/rest/json/cves/2.0?cveId="+url.QueryEscape(cve), "application/json")
		if err != nil {
			return res{}, err
		}
		info, err := parseNVD(body, cve)
		return res{info, len(body)}, err
	})
	const title = "NVD record"
	if err != nil {
		return f.failedSource("advisory", title, page, err), nil
	}
	if !r.info.found {
		return newsSource{row: FetchedSource{Kind: "advisory", Title: title, URL: page, Status: "ok", Note: "NVD has no record of this CVE yet"}}, nil
	}
	// NVD's terms ask every product that uses the API to say so.
	return newsSource{
		row:   FetchedSource{Kind: "advisory", Title: title, URL: page, Status: "ok", Note: sizeNote(r.size) + ". This product uses the NVD API but is not endorsed or certified by the NVD."},
		block: &DataBlock{Kind: DataWeb, Source: "NVD record " + cve, Text: r.info.text},
		cites: []Citation{{Title: "NVD: " + cve, URL: page}},
	}, r.info.vendors
}

// fetchable reports whether one of links is on advisoryHosts.
func fetchable(links []string) bool {
	for _, l := range links {
		if u := safeLink(l, ""); u != "" {
			if p, err := url.Parse(u); err == nil && advisoryHosts[strings.ToLower(p.Hostname())] {
				return true
			}
		}
	}
	return false
}

// vendorSource reads the first vendor page among links whose host is on advisoryHosts. With no such link, the first link is listed
// as not fetched, so a person sees which advisory the box did not read; with no link at all there is no row.
func (f *newsFetcher) vendorSource(ctx context.Context, cve string, links []string) (newsSource, bool) {
	first := ""
	for _, l := range links {
		u := safeLink(l, "")
		if u == "" {
			continue
		}
		p, _ := url.Parse(u)
		host := strings.ToLower(p.Hostname())
		if first == "" {
			first = u
		}
		if !advisoryHosts[host] {
			continue
		}
		title := "Vendor advisory (" + strings.TrimPrefix(host, "www.") + ")"
		type res struct {
			text string
			size int
		}
		r, err := cachedFetch(f, "page "+u, func() (res, error) {
			body, err := f.get(ctx, u, "text/html,application/xhtml+xml")
			if err != nil {
				return res{}, err
			}
			return res{htmlToText(string(body), 512<<10), len(body)}, nil
		})
		if err != nil {
			return f.failedSource("advisory", title, u, err), true
		}
		text := excerpt(r.text, cve, maxSourceText)
		note := sizeNote(r.size)
		if !containsCVE(r.text, cve) {
			note += "; the page does not name this CVE"
		}
		return newsSource{
			row:   FetchedSource{Kind: "advisory", Title: title, URL: u, Status: "ok", Note: note},
			block: &DataBlock{Kind: DataWeb, Source: "vendor advisory " + host, Text: "Vendor page " + u + "\n" + text},
			cites: []Citation{{Title: title, URL: u}},
		}, true
	}
	if first == "" {
		return newsSource{}, false
	}
	p, _ := url.Parse(first)
	host := strings.TrimPrefix(strings.ToLower(p.Hostname()), "www.")
	return newsSource{row: FetchedSource{Kind: "advisory", Title: "Vendor advisory (" + host + ")", URL: first, Status: "failed",
		Note: "Not fetched: " + host + " is not on the box's list of advisory sites (or needs JavaScript); open it yourself"}}, true
}

func (f *newsFetcher) githubSource(ctx context.Context, cve string) newsSource {
	page := "https://github.com/search?q=" + url.QueryEscape(cve) + "&type=repositories"
	title := "GitHub: search " + cve
	r, err := cachedFetch(f, "github "+cve, func() (ghInfo, error) {
		body, err := f.get(ctx, "https://"+githubHost+"/search/repositories?q="+url.QueryEscape(cve)+"&sort=updated&order=desc&per_page=30", "application/vnd.github+json")
		if err != nil {
			return ghInfo{}, err
		}
		return parseGitHubSearch(body, cve)
	})
	if err != nil {
		return f.failedSource("github", title, page, err)
	}
	note := fmt.Sprintf("%d public repositories name this CVE", r.named)
	switch r.named {
	case 0:
		note = "No public repository names this CVE"
	case 1:
		note = "1 public repository names this CVE"
	}
	return newsSource{
		row:   FetchedSource{Kind: "github", Title: title, URL: page, Status: "ok", Note: note},
		block: &DataBlock{Kind: DataWeb, Source: "GitHub repository search", Text: r.text},
		cites: []Citation{{Title: title, URL: page}},
	}
}

func (f *newsFetcher) feedSource(ctx context.Context, cve string, feed newsFeed) newsSource {
	title := feed.Title + " (RSS)"
	items, err := cachedFetch(f, "feed "+feed.URL, func() ([]feedItem, error) {
		body, err := f.get(ctx, feed.URL, "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8")
		if err != nil {
			return nil, err
		}
		return parseFeed(body)
	})
	if err != nil {
		return f.failedSource("rss", title, feed.URL, err)
	}
	host := ""
	if u, err := url.Parse(feed.URL); err == nil {
		host = u.Hostname()
	}
	text, hits := feedMentions(items, cve, host)
	if len(hits) == 0 {
		return newsSource{row: FetchedSource{Kind: "rss", Title: title, URL: feed.URL, Status: "ok", Note: fmt.Sprintf("No post mentions this CVE (%d posts read)", len(items))}}
	}
	s := newsSource{
		row:   FetchedSource{Kind: "rss", Title: title, URL: feed.URL, Status: "ok", Note: fmt.Sprintf("%d of %d posts mention this CVE", len(hits), len(items))},
		block: &DataBlock{Kind: DataWeb, Source: "RSS " + feed.Title, Text: text},
	}
	for _, h := range hits {
		link := h.Link
		if link == "" {
			link = feed.URL
		}
		s.cites = append(s.cites, Citation{Title: clipRunes(feed.Title+": "+h.Title, 160), URL: link})
	}
	return s
}

// gather fetches every source at once, within newsTotalTimeout, and returns them in a fixed order: NVD, the vendor page, GitHub,
// then the feeds in list order. Only the CVE id is in any request; the feeds are fetched whole.
func (f *newsFetcher) gather(ctx context.Context, facts CVEFacts) []newsSource {
	ctx, cancel := context.WithTimeout(ctx, f.total)
	defer cancel()
	cve := facts.CVE
	var nvd, vendor, gh newsSource
	var refs []string
	hasVendor := false
	feeds := make([]newsSource, len(newsFeeds))
	var wg sync.WaitGroup
	wg.Go(func() { nvd, refs = f.nvdSource(ctx, cve) })
	// The exploited-list links first (CISA chose them), at once; NVD is often slow without a key.
	wg.Go(func() { vendor, hasVendor = f.vendorSource(ctx, cve, facts.Links) })
	wg.Go(func() { gh = f.githubSource(ctx, cve) })
	for i, fd := range newsFeeds {
		wg.Go(func() { feeds[i] = f.feedSource(ctx, cve, fd) })
	}
	wg.Wait()
	if vendor.block == nil && !fetchable(facts.Links) {
		// No vendor page from the exploited list: try the record's own vendor links, in what is left of the budget.
		if v, ok := f.vendorSource(ctx, cve, append(append([]string{}, facts.Links...), refs...)); ok {
			vendor, hasVendor = v, true
		}
	}
	out := []newsSource{nvd}
	if hasVendor {
		out = append(out, vendor)
	}
	return append(append(out, gh), feeds...)
}

// newsHookCheck runs the before-AI hooks on each fetched block alone. A block a hook stops is left out and its source is marked
// failed; the call goes on with the rest, as memory lines do (INV-8): one page with an ID-shaped number must not stop the news.
// RunJob runs the hooks again on what is sent, with the same generation of hooks or a newer one.
func (s *Service) newsHookCheck(ctx context.Context, hooks *HookRunner, srcs []newsSource) {
	ctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	for i := range srcs {
		b := srcs[i].block
		if b == nil {
			continue
		}
		r, err := hooks.Run(ctx, BeforeAI, b.Text)
		if err != nil || r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld {
			srcs[i].block, srcs[i].cites = nil, nil
			srcs[i].row.Status, srcs[i].row.Note = "failed", "Left out: a hook on this box stopped this text, so it was not sent to the AI"
			continue
		}
		b.Text = r.Text
	}
}

type newsRow struct {
	body      newsBody
	model     string
	profile   string
	tin, tout int
	created   time.Time
}

// loadNews reads the newest stored news of a CVE; with hash set, only one made from exactly those inputs.
func (s *Service) loadNews(ctx context.Context, cve, hash string) (newsRow, bool, error) {
	q := `SELECT payload, model, profile, tokens_in, tokens_out, created_at FROM ai_result WHERE kind = 'news' AND key = ?`
	args := []any{cve}
	if hash != "" {
		q += ` AND inputs_hash = ?`
		args = append(args, hash)
	}
	var payload, created string
	var r newsRow
	err := s.cfg.DB.Reader().QueryRowContext(ctx, q+` ORDER BY created_at DESC, rowid DESC LIMIT 1`, args...).Scan(&payload, &r.model, &r.profile, &r.tin, &r.tout, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return newsRow{}, false, nil
	}
	if err != nil {
		return newsRow{}, false, fmt.Errorf("ai: read news: %w", err)
	}
	if err := json.Unmarshal([]byte(payload), &r.body); err != nil {
		return newsRow{}, false, fmt.Errorf("ai: stored news of %s is not readable: %w", cve, err)
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", created)
	if err != nil {
		return newsRow{}, false, fmt.Errorf("ai: stored news time: %w", err)
	}
	r.created = t
	return r, true, nil
}

func newsView(cve string, r newsRow) NewsResult {
	v := NewsResult{CVE: cve, GeneratedAt: FormatTS(r.created), Sources: r.body.Sources, Lines: r.body.Lines, Citations: r.body.Citations, Model: r.model, Profile: r.profile}
	v.Tokens.Input, v.Tokens.Output = r.tin, r.tout
	return v
}

// CachedNews returns the newest news generated for a CVE, without fetching or calling the AI (INV-6). nil when there is none.
func (s *Service) CachedNews(ctx context.Context, id string) (*NewsResult, error) {
	cve := strings.ToUpper(id)
	if !cveRE.MatchString(cve) {
		return nil, apierr.New(http.StatusBadRequest, "invalid_cve", "A CVE ID looks like CVE-2022-27593.")
	}
	r, ok, err := s.loadNews(ctx, cve, "")
	if err != nil || !ok {
		return nil, err
	}
	v := newsView(cve, r)
	return &v, nil
}

// NewsCVE fetches the public sources about a CVE and has the AI summarise them (S-AI-3): exploited yet, public exploit code yet,
// workaround. The box does the fetching (FORBID-6); the job is public (INV-3): the request carries the exploited-list entry and the
// fetched pages, never a device, a finding, a log line or a memory. The same inputs answer from the stored result without tokens.
func (s *Service) NewsCVE(ctx context.Context, actor, id string) (NewsResult, error) {
	cve := strings.ToUpper(id)
	if err := s.Ready(JobCVENews); err != nil {
		return NewsResult{}, err
	}
	if !cveRE.MatchString(cve) {
		return NewsResult{}, apierr.New(http.StatusBadRequest, "invalid_cve", "A CVE ID looks like CVE-2022-27593.")
	}
	if s.cfg.Facts == nil {
		return NewsResult{}, apiUnavailable("The box has no vulnerability data to look up. Turn on the feeds module in Settings, Modules.")
	}
	facts, ok, err := s.cfg.Facts.CVE(ctx, cve)
	if err != nil {
		return NewsResult{}, fmt.Errorf("ai: read CVE: %w", err)
	}
	if !ok {
		return NewsResult{}, apierr.New(http.StatusNotFound, "unknown_cve", "This CVE is not on the exploited list the box holds, so the box has no source to fetch.")
	}
	facts.CVE = cve

	srcs := s.news.gather(ctx, facts)
	har := s.harness.Load()
	s.newsHookCheck(ctx, har.runner, srcs)
	data := []DataBlock{feedBlock(facts)}
	body := newsBody{Sources: []FetchedSource{}, Citations: []Citation{}}
	for _, src := range srcs {
		body.Sources = append(body.Sources, src.row)
		if src.block != nil {
			data = append(data, *src.block)
		}
		for _, c := range src.cites {
			if len(body.Citations) < maxCitations {
				body.Citations = append(body.Citations, c)
			}
		}
	}
	if len(data) == 1 {
		return NewsResult{}, apiUnavailable("Vedette could not fetch any source about this CVE, so the AI was not asked and no tokens were spent. Try again in a few minutes.")
	}
	var rules []string
	for _, r := range har.rules {
		if r.Enabled && r.appliesTo(JobCVENews) {
			rules = append(rules, r.Text)
		}
	}
	var in strings.Builder
	in.WriteString("news-v1")
	for _, d := range data {
		in.WriteString("\n<" + d.Source + ">\n" + d.Text)
	}
	hash := HashContent(in.String() + "\nrules:" + strings.Join(rules, "\n"))
	if r, ok, err := s.loadNews(ctx, cve, hash); err != nil {
		return NewsResult{}, err
	} else if ok {
		return newsView(cve, r), nil
	}

	var answer newsAnswer
	now := s.cfg.Clock()
	res, err := s.RunJob(ctx, JobSpec{
		Job: JobCVENews, Actor: actor, Task: newsTask,
		Question:  fmt.Sprintf("What is the latest on %s: is it exploited, is there public exploit code, and what is the workaround?", cve),
		Data:      data,
		Schema:    &provider.Schema{Name: "cve_news", JSON: json.RawMessage(newsSchema)},
		MaxTokens: 2000, // a real answer runs to about 600 tokens; a cut-off answer is not JSON and is discarded
		Summary:   fmt.Sprintf("Summarised %d public sources about %s", len(data)-1, cve),
		Check: func(text string) error {
			var perr error
			answer, perr = parseNews(text)
			return perr
		},
		Store: func(ctx context.Context, tx *sql.Tx, r JobResult) error {
			body.Lines = answer.lines()
			payload, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("ai: encode news: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ai_result (id, kind, key, inputs_hash, payload, model, profile, tokens_in, tokens_out, asked_by, activity_id, created_at)
				VALUES (?, 'news', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, store.NewID("res"), cve, hash, string(payload), r.Model, r.Profile, r.TokensIn, r.TokensOut, actor, r.ActivityID, FormatTS(now)); err != nil {
				return fmt.Errorf("ai: store news: %w", err)
			}
			return nil
		},
	})
	if err != nil {
		return NewsResult{}, err
	}
	v := newsView(cve, newsRow{body: body, model: res.Model, profile: res.Profile, tin: res.TokensIn, tout: res.TokensOut, created: now})
	return v, nil
}
