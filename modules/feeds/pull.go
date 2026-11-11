package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cur, err := s.st.source(ctx, r.ID); err == nil { // an earlier pull of this tick may have filled it (EPSS after the CISA list)
			r = cur
		}
		if !r.Enabled || !r.state().Due(now, r.IntervalHours) {
			continue
		}
		_, err := s.pull(ctx, r.ID, "") // pull brings the EPSS scores after a CISA list load
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
	}
	if err := s.reconcileDevices(ctx); err != nil && ctx.Err() == nil {
		s.Log.ErrorContext(ctx, "adding the devices of \"I have it\" failed", "error", err)
	}
	if err := s.st.maintain(ctx, now); err != nil {
		s.Log.ErrorContext(ctx, "pruning feed data failed", "error", err)
	}
	return nil
}

// Fetch pulls one feed now (PRE-1: the feed is on; its address passes INV-2 inside the fetcher). A failed pull is
// recorded on the feed (status error) and is not an error here; ErrFeedDisabled and ErrNotFound are.
func (s *Service) Fetch(ctx context.Context, feedID string) error {
	_, err := s.pull(ctx, feedID, "")
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
	case errors.Is(err, ErrBoxAddrsUnknown):
		return "Vedette does not know its own addresses yet, so it did not connect. It will try again at the next pull."
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
	viaCISA := src.ID == "cisa-kev" && src.URL == s.kevPrimary() // the built-in address of the CISA list: D-91 applies
	req := Request{URL: src.URL, Auth: auth}
	mirrorHeldIt := src.AnsweredBy != nil && *src.AnsweredBy == AnsweredMirror
	if src.Status == "ok" && !mirrorHeldIt { // conditional only after a good pull, and only for the address the validators came from
		if src.ETag != nil {
			req.ETag = *src.ETag
		}
		if src.LastModified != nil {
			req.LastModified = *src.LastModified
		}
	}
	resp, err := s.get(ctx, req)
	answered := ""
	if viaCISA {
		answered = AnsweredCISA
		if err != nil && fallbackWorthy(err) {
			mresp, merr := s.get(ctx, Request{URL: s.kevFallback()}) // no validators, no credentials: a plain GET
			if merr != nil {
				return p, &Error{Err: merr, Detail: userError(err, src.URL) + " The CISA GitHub mirror failed too: " + userError(merr, s.kevFallback())}
			}
			resp, err, answered = mresp, nil, AnsweredMirror
		}
	}
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified, AnsweredBy: answered}
		return p, nil
	}
	p.out = outcome{OK: true, Bytes: len(resp.Body), ETag: resp.ETag, LastModif: resp.LastModified, AnsweredBy: answered}
	switch dec {
	case DecoderKEV:
		cat, err := ParseKEV(resp.Body)
		if err != nil {
			return p, err
		}
		if err := accepted(cat.Stats); err != nil {
			return p, err
		}
		if answered == AnsweredMirror && src.CatalogVersion != nil && kevOlder(cat.Version, *src.CatalogVersion) { // never roll back (D-91)
			p.out = outcome{OK: true, NotModified: true, Note: fmt.Sprintf("The CISA GitHub mirror has an older list (%s) than this box (%s), so the list on the box was kept.", cat.Version, *src.CatalogVersion)}
			return p, nil
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
		st := res.Stats
		var vulns []Vuln
		if src.Kind == KindVulnerabilities {
			var long int
			if vulns, long = vulnsOf(res.Records); long > 0 { // fail-closed: such a row is rejected with its reason
				st.Accepted -= long
				st.Rejected += long
				st.Reasons = append(slices.Clone(st.Reasons), Reason{"vendor or product: longer than 200 characters", long})
			}
		}
		if err := accepted(st); err != nil {
			return p, err
		}
		p.out.fill(st, st.Accepted)
		if src.Kind == KindVulnerabilities {
			p.vulns, p.hasVulns, p.replaceVulns = vulns, true, true
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
// A feed that gives no vendor or product is filed under "Unknown"; a vendor or product over 200 characters (or a
// key over 500) is not stored and is counted in tooLong, so the key CHECKs can never fail.
func vulnsOf(recs []Record) (out []Vuln, tooLong int) {
	out = make([]Vuln, 0, len(recs))
	for _, r := range recs {
		v := Vuln{CVE: str(r["cve"]), Vendor: str(r["vendor"]), Product: str(r["product"]), Description: str(r["description"]), DateAdded: str(r["date"]), Links: []string{}}
		if utf8.RuneCountInString(v.Vendor) > maxVendorProduct || utf8.RuneCountInString(v.Product) > maxVendorProduct || utf8.RuneCountInString(v.Key()) > maxProductKey {
			tooLong++
			continue
		}
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
	return out, tooLong
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

// errStoreFailed is the sentence stored on a feed when its result could not be written (a database problem).
const errStoreFailed = "The result could not be stored. Check the disk space and the box logs."

// pullOne runs one pull of one feed under the feed's lock and writes its result in one transaction (with a core_audit
// row when a person started it: actor is their email). It returns the feed as stored afterwards and how many CVEs
// of the CISA list were new. A pull whose feed was edited, turned off or deleted while it ran writes nothing (the
// row is re-read inside the transaction and its rev compared): deleted is ErrNotFound, the others return the feed
// as it is. A failed pull is recorded on the feed; if even that fails to store, a second short transaction records
// the failure. Only a context error, ErrNotFound, ErrFeedDisabled or a database that cannot record anything is an error.
func (s *Service) pullOne(ctx context.Context, id, actor string) (sourceRow, int, error) {
	if err := s.ready(ctx); err != nil {
		return sourceRow{}, 0, err
	}
	release, err := s.lockFeed(ctx, id)
	if err != nil {
		return sourceRow{}, 0, err
	}
	defer release()
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

	var (
		fresh          []VulnRow
		changed        []string
		added, removed int
		stale          bool
		baseline       bool // the CISA list filled an empty table: one baseline event, not one per CVE (D-78)
	)
	finish := func(tx *sql.Tx, out outcome) error { // the outcome row and the audit entry, in the pull's last transaction
		if err := recordOutcome(ctx, tx, src.ID, out); err != nil {
			return err
		}
		if actor == "" {
			return nil
		}
		detail := fmt.Sprintf("%d records", out.Records)
		if !out.OK {
			detail = out.Err
		}
		return s.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "feeds.fetch", Target: src.Name, Detail: detail})
	}
	write := func(p pullPlan) error {
		fresh, changed, added, removed, stale, baseline = nil, nil, 0, 0, false, false
		if p.hasIOCs { // a long list: chunks, not one transaction that holds the writer (applyIOCs)
			var err error
			added, removed, stale, err = applyIOCs(ctx, s.DB, p.out.Finished, src, p.iocs, s.afterChunk, func(tx *sql.Tx, _, _ int) error { return finish(tx, p.out) })
			return err
		}
		return s.DB.Write(ctx, func(tx *sql.Tx) error {
			cur, err := sourceTx(ctx, tx, src.ID)
			if err != nil {
				return err // ErrNotFound: deleted meanwhile
			}
			if cur.Rev != src.Rev || !cur.Enabled { // edited or switched off meanwhile: this result is about old settings
				stale = true
				return nil
			}
			switch {
			case p.hasVulns:
				var updated []string
				if src.ID == "cisa-kev" {
					var have int
					if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'cisa-kev'`).Scan(&have); err != nil {
						return fmt.Errorf("feeds: count KEV rows: %w", err)
					}
					baseline = have == 0
				}
				if fresh, updated, err = applyVulns(ctx, tx, p.out.Finished, src.ID, p.vulns, p.replaceVulns); err != nil {
					return err
				}
				// the entries this pull announces as new (below, after the commit) are recorded with it (D-144)
				if src.ID == "cisa-kev" && !baseline {
					if err := markAnnounced(ctx, tx, fresh, p.out.Finished); err != nil {
						return err
					}
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
			}
			return finish(tx, p.out)
		})
	}
	err = write(p)
	switch {
	case errors.Is(err, ErrNotFound):
		return sourceRow{}, 0, ErrNotFound
	case err != nil && ctx.Err() != nil:
		return sourceRow{}, 0, ctx.Err()
	case err != nil:
		// The data could not be stored: leave a trace on the feed (error text, back-off) in a small transaction
		// that touches nothing else, so Settings shows it and the job does not hit the source on every tick.
		s.Log.ErrorContext(ctx, "storing a pull failed", "feed", src.ID, "error", err)
		p = pullPlan{out: outcome{Err: errStoreFailed, Started: started, Finished: s.now()}}
		if err2 := write(p); err2 != nil {
			return sourceRow{}, 0, fmt.Errorf("feeds: recording the failure of a pull: %w", errors.Join(err, err2))
		}
	}
	row, rerr := s.st.source(ctx, id)
	if stale || rerr != nil {
		return row, 0, rerr
	}

	kev := 0
	if src.ID == "cisa-kev" { // only the CISA list makes KEV events; a custom feed's CVEs are not KEV entries
		kev = len(fresh)
		if baseline {
			if kev > 0 {
				s.publish(ctx, EventSyncBaseline, SyncBaselineEvent{Source: src.ID, Count: kev})
			}
		} else {
			for _, v := range fresh {
				s.publish(ctx, EventNewKEV, NewKEVEvent{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, HasTemplate: v.HasTemplate, DateAdded: v.DateAdded})
			}
		}
	}
	if len(changed) > 0 && (src.ID == "cisa-kev" || p.hasTemplates) {
		s.publish(ctx, EventVulnUpdated, VulnUpdatedEvent{CVEs: changed})
	}
	if added > 0 || removed > 0 {
		s.publish(ctx, EventIOCUpdated, IOCUpdatedEvent{FeedID: src.ID, Added: added, Removed: removed})
	}
	if !p.out.OK {
		s.publish(ctx, EventFetchFailed, FetchFailedEvent{FeedID: src.ID, Error: p.out.Err})
	}
	return row, kev, nil
}

// pull is pullOne plus the rule that every load of the CISA list brings the EPSS scores with it, whoever started it
// (the job or "Fetch now"): new CVEs get their score now, not in a day, and a box whose EPSS feed ran before the list
// existed ("OK, 0 records") is filled. A feed that is off is left alone; EPSS failing is its own feed's status, not the list's.
func (s *Service) pull(ctx context.Context, id, actor string) (sourceRow, error) {
	row, fresh, err := s.pullOne(ctx, id, actor)
	if err != nil || id != "cisa-kev" || row.Status != "ok" {
		return row, err
	}
	if e, err := s.st.source(ctx, "first-epss"); err == nil && e.Enabled && (fresh > 0 || e.Records == nil || *e.Records == 0) {
		if _, _, err := s.pullOne(ctx, "first-epss", ""); err != nil && ctx.Err() != nil {
			return row, ctx.Err()
		}
	}
	return row, nil
}

// fallbackWorthy says whether a failed pull of the CISA address is one the GitHub mirror can answer (D-91): the address
// is blocked for this box (403), the server is sick (5xx) or nothing came back in time.
func fallbackWorthy(err error) bool {
	var se *StatusError
	switch {
	case errors.As(err, &se):
		return se.Code == http.StatusForbidden || se.Code >= 500
	case errors.Is(err, context.DeadlineExceeded):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// kevOlder reports whether catalog version a (such as "2026.11.04") is older than b. A version that is not dotted numbers is
// never older: unknown is taken, not refused.
func kevOlder(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		x, y := 0, 0
		var e1, e2 error
		if i < len(pa) {
			x, e1 = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, e2 = strconv.Atoi(pb[i])
		}
		if e1 != nil || e2 != nil || a == "" || b == "" {
			return false
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func (s *Service) kevPrimary() string {
	if s.KEVPrimary != "" {
		return s.KEVPrimary
	}
	b, _ := BuiltinByID("cisa-kev")
	return b.URL
}

func (s *Service) kevFallback() string {
	if s.KEVFallback != "" {
		return s.KEVFallback
	}
	return KEVMirrorURL
}
