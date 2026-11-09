package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
)

// Pull schedule.
const (
	// PullEvery is how often the pull job looks for feeds that are due. Each feed keeps its own interval and
	// back-off (State); this only bounds how late a due pull can start, so INV-9 (interval + 60 min) holds.
	PullEvery = 5 * time.Minute
	// pullBudget bounds one whole pull (an EPSS pull makes up to dozens of requests).
	pullBudget = 10 * time.Minute
)

// ErrFeedDisabled is returned by Fetch for a feed that is turned off (INV-8, FORBID-3).
var ErrFeedDisabled = errors.New("feeds: the feed is turned off")

// Jobs returns the pull job of the module for the scheduler. The scheduler runs it only while the module is on.
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{{Module: "feeds", Name: "pull", Every: PullEvery, Run: s.RunPull}}
}

// RunPull is one tick of the pull job: every enabled feed that is due (INV-8, INV-9: State.Due with the feed's
// interval and its back-off after errors) is pulled in turn, vulnerabilities first. A failed pull is recorded on
// the feed and never fails the job; only a cancelled context or a database failure does.
func (s *Service) RunPull(ctx context.Context) error {
	now := s.now()
	rows, err := s.sources(ctx)
	if err != nil {
		return err
	}
	force := map[string]bool{}
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !r.Enabled || (!force[r.ID] && !r.state().Due(now, r.IntervalHours)) {
			continue
		}
		_, fresh, err := s.pull(ctx, r.ID, "")
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrFeedDisabled) || errors.Is(err, ErrNotFound) { // changed since the list was read
			continue
		}
		if err != nil { // a database failure: the feed's own error state could not be written either
			s.Log.ErrorContext(ctx, "pulling a feed failed", "feed", r.ID, "error", err)
			continue
		}
		if fresh > 0 {
			force["first-epss"] = true // new CVEs get their EPSS score now, not in a day
		}
	}
	if err := s.st.maintain(ctx, now); err != nil {
		s.Log.ErrorContext(ctx, "pruning feed data failed", "error", err)
	}
	return nil
}

// Fetch pulls one feed now (PRE-1: the feed is on; its address passes INV-2 inside the fetcher). A failed pull is
// recorded on the feed (status error) and is not an error here; ErrFeedDisabled and ErrNotFound are.
func (s *Service) Fetch(ctx context.Context, feedID string) error {
	_, _, err := s.pull(ctx, feedID, "")
	return err
}

// pullPlan is what a pull learned and has to write in one transaction (INV-3: nothing is written for a rejected pull).
type pullPlan struct {
	out outcome

	vulns        []Vuln
	replaceVulns bool
	hasVulns     bool

	templates    []string
	hasTemplates bool

	epssLatest, epssAgo map[string]float64
	hasEPSS             bool

	iocs    []iocInput
	hasIOCs bool
}

func (s *Service) get(ctx context.Context, req Request) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()
	return s.Fetcher.Fetch(ctx, req)
}

func (s *Service) authFor(ctx context.Context, src sourceRow) (Auth, error) {
	a := Auth{Type: src.Auth}
	if src.Auth == AuthNone || src.Auth == "" {
		return a, nil
	}
	if src.HeaderName != nil {
		a.HeaderName = *src.HeaderName
	}
	if src.Username != nil {
		a.Username = *src.Username
	}
	if src.SecretID == nil {
		return Auth{}, fail(ErrInvalidAuth, "The feed has no secret saved. Edit the feed and enter it again.")
	}
	plain, err := s.Secrets.Open(ctx, s.DB.Reader(), *src.SecretID, secretPurpose)
	if err != nil {
		s.Log.ErrorContext(ctx, "opening a feed secret failed", "feed", src.ID, "error", err)
		return Auth{}, fail(ErrInvalidAuth, "The saved secret could not be read. Edit the feed and enter it again.")
	}
	sec, err := NewSecret(string(plain))
	if err != nil {
		return Auth{}, err
	}
	a.Secret = sec
	return a, nil
}

// userError is the sentence stored on a feed after a failed pull and shown in Settings -> Feeds (D-37): what
// went wrong, without addresses (they may carry a token) or internals.
func userError(err error, rawURL string) string {
	host := ""
	if u, perr := url.Parse(rawURL); perr == nil {
		host = u.Hostname()
	}
	var (
		fe  *Error
		se  *StatusError
		dns *net.DNSError
	)
	switch {
	case errors.As(err, &fe):
		return fe.Detail
	case errors.As(err, &se):
		return fmt.Sprintf("The source answered HTTP %d.", se.Code)
	case errors.Is(err, context.DeadlineExceeded):
		return "The source did not answer in time."
	case errors.As(err, &dns):
		return fmt.Sprintf("Could not resolve %s. Check the address.", host)
	}
	return fmt.Sprintf("Could not reach %s.", host)
}

// accepted turns a parse with no accepted row into an error, so a pull never replaces data with nothing.
func accepted(st Stats) error {
	if st.Accepted > 0 {
		return nil
	}
	if st.Rejected > 0 && len(st.Reasons) > 0 {
		return fail(ErrBadSample, "All %d rows were rejected: %s.", st.Rejected, st.Reasons[0].Reason)
	}
	return fail(ErrBadSample, "The feed returned no records.")
}

func note(st Stats) string {
	if st.Rejected == 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d rows were rejected.", st.Rejected, st.Accepted+st.Rejected)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// build runs one pull of src against the network and the parsers and returns what to write. An error is the
// failure of the pull (its text goes through userError).
func (s *Service) build(ctx context.Context, src sourceRow) (pullPlan, error) {
	var p pullPlan
	dec, builtin := DecoderParser, Source{}
	if src.Builtin {
		b, ok := BuiltinByID(src.ID)
		if !ok {
			return p, fail(ErrBadConfig, "This built-in feed is no longer part of Vedette.")
		}
		dec, builtin = b.Decoder, b
	}
	if dec == DecoderEPSS {
		return s.buildEPSS(ctx, src, p)
	}
	auth, err := s.authFor(ctx, src)
	if err != nil {
		return p, err
	}
	req := Request{URL: src.URL, Auth: auth}
	if src.Status == "ok" { // conditional only after a good pull, and only for the address the validators came from
		if src.ETag != nil {
			req.ETag = *src.ETag
		}
		if src.LastModified != nil {
			req.LastModified = *src.LastModified
		}
	}
	resp, err := s.get(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	p.out = outcome{OK: true, Bytes: len(resp.Body), ETag: resp.ETag, LastModif: resp.LastModified}
	switch dec {
	case DecoderKEV:
		cat, err := ParseKEV(resp.Body)
		if err != nil {
			return p, err
		}
		if err := accepted(cat.Stats); err != nil {
			return p, err
		}
		p.vulns, p.hasVulns = cat.Vulns, true
		p.out.fill(cat.Stats, cat.Accepted)
		p.out.CatalogVersion = cat.Version
	case DecoderNuclei:
		n, err := ParseNucleiCVEs(resp.Body)
		if err != nil {
			return p, err
		}
		if err := accepted(n.Stats); err != nil {
			return p, err
		}
		p.templates, p.hasTemplates = n.CVEs, true
		p.out.fill(n.Stats, len(n.CVEs))
	default: // DecoderParser: the built-in IOC lists and every custom feed
		var res Result
		if src.Builtin {
			res, err = ParseSource(ctx, builtin, resp.Body)
		} else {
			res, err = ParseFeed(ctx, resp.Body, src.Kind, *src.Parser)
		}
		if err != nil {
			return p, err
		}
		if err := accepted(res.Stats); err != nil {
			return p, err
		}
		p.out.fill(res.Stats, res.Accepted)
		if src.Kind == KindVulnerabilities {
			p.vulns, p.hasVulns, p.replaceVulns = vulnsOf(res.Records), true, true
		} else {
			p.iocs, p.hasIOCs = iocsOf(res.Records), true
		}
	}
	return p, nil
}

func (o *outcome) fill(st Stats, records int) {
	o.Accepted, o.Rejected, o.Reasons, o.Records, o.Note = st.Accepted, st.Rejected, st.Reasons, records, note(st)
}

// vulnsOf maps the records of a custom vulnerability feed (fields cve, vendor, product, date, description, link).
// A feed that gives no vendor or product is filed under "Unknown".
func vulnsOf(recs []Record) []Vuln {
	out := make([]Vuln, 0, len(recs))
	for _, r := range recs {
		v := Vuln{CVE: str(r["cve"]), Vendor: str(r["vendor"]), Product: str(r["product"]), Description: str(r["description"]), DateAdded: str(r["date"]), Links: []string{}}
		if v.Vendor == "" {
			v.Vendor = "Unknown"
		}
		if v.Product == "" {
			v.Product = "Unknown"
		}
		v.Name = v.CVE
		if l := str(r["link"]); l != "" {
			v.Links = append(v.Links, l)
		}
		out = append(out, v)
	}
	return out
}

func iocsOf(recs []Record) []iocInput {
	out := make([]iocInput, 0, len(recs))
	for _, r := range recs {
		in := iocInput{Kind: str(r["kind"]), Value: str(r["indicator"]), FirstSeen: str(r["first_seen"])}
		if c, ok := r["confidence"].(float64); ok {
			in.Confidence = &c
		}
		out = append(out, in)
	}
	return out
}

// buildEPSS asks api.first.org for the score of every stored CVE now and 7 days ago, 100 CVEs per request
// (INV-2). Any failed request fails the whole pull: scores are never half updated.
func (s *Service) buildEPSS(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	cves, err := s.st.kevCVEs(ctx)
	if err != nil {
		return p, err
	}
	p.out = outcome{OK: true}
	p.hasEPSS = true
	p.epssLatest, p.epssAgo = map[string]float64{}, map[string]float64{}
	if len(cves) == 0 { // nothing to score yet; the KEV pull forces this feed when CVEs arrive
		return p, nil
	}
	now := s.now()
	var st Stats
	for _, c := range []struct {
		date string
		into map[string]float64
	}{{"", p.epssLatest}, {EPSSDate(now, 7), p.epssAgo}} {
		urls, err := EPSSBatchURLs(src.URL, cves, c.date)
		if err != nil {
			return p, err
		}
		for _, u := range urls {
			resp, err := s.get(ctx, Request{URL: u})
			if err != nil {
				return p, err
			}
			d, err := ParseEPSS(resp.Body)
			if err != nil {
				return p, err
			}
			p.out.Bytes += len(resp.Body)
			if c.date == "" {
				st.Accepted += d.Accepted
				st.Rejected += d.Rejected
				if len(st.Reasons) == 0 {
					st.Reasons = d.Reasons
				}
			}
			for _, sc := range d.Scores {
				c.into[sc.CVE] = sc.Score
			}
		}
	}
	if len(p.epssLatest) == 0 {
		return p, accepted(st)
	}
	p.out.fill(st, len(p.epssLatest))
	return p, nil
}

// pull runs one pull of one feed under the feed's lock and writes its result in one transaction (with a core_audit
// row when a person started it: actor is their email). It returns the feed as stored afterwards and how many CVEs
// were new. Only a database failure (or ErrNotFound, ErrFeedDisabled) is an error; a failed pull is recorded.
func (s *Service) pull(ctx context.Context, id, actor string) (sourceRow, int, error) {
	if err := s.ready(ctx); err != nil {
		return sourceRow{}, 0, err
	}
	lock := s.feedLock(id)
	lock.Lock()
	defer lock.Unlock()
	src, err := s.st.source(ctx, id)
	if err != nil {
		return sourceRow{}, 0, err
	}
	if !src.Enabled {
		return sourceRow{}, 0, ErrFeedDisabled
	}
	started := s.now()
	bctx, cancel := context.WithTimeout(ctx, pullBudget)
	p, perr := s.build(bctx, src)
	cancel()
	if perr != nil && ctx.Err() != nil {
		return sourceRow{}, 0, ctx.Err() // cancelled (module turned off, shutdown): not a failure of the feed
	}
	if perr != nil {
		s.Log.WarnContext(ctx, "feed pull failed", "feed", src.ID, "error", perr)
		p = pullPlan{out: outcome{Err: userError(perr, src.URL)}}
	}
	p.out.Started, p.out.Finished = started, s.now()

	var fresh []VulnRow
	var changed []string
	var added, removed int
	err = s.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		switch {
		case p.hasVulns:
			var updated []string
			if fresh, updated, err = applyVulns(ctx, tx, p.out.Finished, src.ID, p.vulns, p.replaceVulns); err != nil {
				return err
			}
			changed = append(changed, updated...)
		case p.hasTemplates:
			if changed, err = applyTemplates(ctx, tx, p.templates); err != nil {
				return err
			}
		case p.hasEPSS:
			if _, err = applyEPSS(ctx, tx, p.epssLatest, p.epssAgo); err != nil {
				return err
			}
		case p.hasIOCs:
			if added, removed, err = applyIOCs(ctx, tx, p.out.Finished, src.ID, p.iocs); err != nil {
				return err
			}
		}
		if err := recordOutcome(ctx, tx, src.ID, p.out); err != nil {
			return err
		}
		if actor == "" {
			return nil
		}
		detail := fmt.Sprintf("%d records", p.out.Records)
		if !p.out.OK {
			detail = p.out.Err
		}
		return s.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "feeds.fetch", Target: src.Name, Detail: detail})
	})
	if err != nil {
		return sourceRow{}, 0, err
	}

	for _, v := range fresh {
		s.publish(ctx, EventNewKEV, NewKEVEvent{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, HasTemplate: v.HasTemplate, DateAdded: v.DateAdded})
	}
	if len(changed) > 0 {
		s.publish(ctx, EventVulnUpdated, VulnUpdatedEvent{CVEs: changed})
	}
	if added > 0 || removed > 0 {
		s.publish(ctx, EventIOCUpdated, IOCUpdatedEvent{FeedID: src.ID, Added: added, Removed: removed})
	}
	if !p.out.OK {
		s.publish(ctx, EventFetchFailed, FetchFailedEvent{FeedID: src.ID, Error: p.out.Err})
	}
	row, err := s.st.source(ctx, id)
	return row, len(fresh), err
}
