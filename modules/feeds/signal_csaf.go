package feeds

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Cisco and Fortinet publish each security advisory as a CSAF 2.0 document (JSON). Neither marks exploitation with a structured field:
// Cisco states it in the advisory's "Exploitation and Public Announcements" section, Fortinet in the description of each
// vulnerability ("Fortinet has observed this to be exploited in the wild"). So the claim is read from those parts only, by the
// same-sentence rule of signal_claims.go, and belongs to the CVEs the sentence names, or to the part's own CVE when it names none.
// A document's other text (product tree, fixed releases, workarounds, legal notes) is never read for claims.
//
// Which advisories are read: each vendor's own advisory feed (RSS), which lists the 50 most recently published or changed
// advisories. Cisco's gives each advisory's last change, and the box reads the CSAF document of those changed since its last good
// pull (Cisco serves no validators for them); FortiGuard's gives each CSAF document's link, and each document is asked only if it
// changed since the last good pull (If-Modified-Since). A first pull reads every advisory of the feed (about 50: about 13 MB for
// Cisco, which serves its documents uncompressed, 0.3 MB for Fortinet). A box that pulls every few hours sees every change; claims
// older than the feeds reach are almost all on the CISA list already. Every request goes to the feed's own host: a link in the data
// is reduced to its path, checked, and asked of that host.

// Where a person reads an advisory (feeds_signal.url): the vendor's own page, whatever host the feed is pulled from.
const (
	ciscoAdvisoryURL    = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
	fortinetAdvisoryURL = "https://fortiguard.fortinet.com/psirt/"
)

// Bounds: one CSAF document (Cisco's largest seen is 1.1 MB, its product tree), an advisory feed, the advisories one pull reads,
// the items of a feed, the vulnerabilities and notes of one document, and the text of one document read for claims (Fortinet's
// longest is about 20 KB).
const (
	csafMaxBytes     = 32 << 20
	csafListMaxBytes = 8 << 20
	csafMaxDocs      = 2_000
	csafMaxListRows  = 5_000
	csafMaxVulns     = 5_000
	csafMaxNotes     = 2_000
	csafMaxClaimText = 1 << 20
	csafReReadSlack  = time.Hour // an advisory changed this long before the last good pull is read again (clocks, the feed's lag)
)

var (
	ciscoIDRE        = regexp.MustCompile(`^cisco-sa-[A-Za-z0-9][A-Za-z0-9._-]{1,100}$`)
	fortinetIDRE     = regexp.MustCompile(`^FG-IR-[0-9]{2}-[0-9]{1,6}$`)
	fortinetCSAFPath = regexp.MustCompile(`^/fortiguard/psirt/csaf_[A-Za-z0-9._-]{1,200}\.json$`)
	// csafClaimRevRE: a revision whose summary speaks of exploitation dates the claim ("Updated to indicate active exploitation
	// attempts in the wild", "Added information about active exploitation of CVE-2026-20133").
	csafClaimRevRE = regexp.MustCompile(`(?i)exploit|in the wild|malicious use`)
	// csafExploitedFlagRE: the CSAF threat of category exploit_status as some vendors fill it ("Exploited:Yes").
	csafExploitedFlagRE = regexp.MustCompile(`(?i)\bexploited\s*:\s*yes\b`)
)

type csafNote struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Text     string `json:"text"`
}

// csafDoc is the part of a CSAF 2.0 document the claim rules read.
type csafDoc struct {
	Document struct {
		Tracking struct {
			ID              string `json:"id"`
			InitialRelease  string `json:"initial_release_date"`
			RevisionHistory []struct {
				Date    string `json:"date"`
				Summary string `json:"summary"`
			} `json:"revision_history"`
		} `json:"tracking"`
		Notes []csafNote `json:"notes"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE     string     `json:"cve"`
		Notes   []csafNote `json:"notes"`
		Threats []struct {
			Category string `json:"category"`
			Details  string `json:"details"`
		} `json:"threats"`
		References []struct {
			Summary string `json:"summary"`
		} `json:"references"`
	} `json:"vulnerabilities"`
}

// parseCSAF reads one CSAF document: one JSON object and nothing after it, with a tracking id and a readable first release
// (fail-closed); a document with more vulnerabilities or notes than the bounds is refused.
func parseCSAF(r io.Reader) (csafDoc, error) {
	var d csafDoc
	dec := json.NewDecoder(r)
	if err := dec.Decode(&d); err != nil {
		return csafDoc{}, readFail(err, "The advisory document could not be read: %v.", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return csafDoc{}, readFail(err, "The advisory document has data after its end.")
	}
	if strings.TrimSpace(d.Document.Tracking.ID) == "" {
		return csafDoc{}, fail(ErrBadSample, "The advisory document has no id.")
	}
	if _, ok := csafTime(d.Document.Tracking.InitialRelease); !ok {
		return csafDoc{}, fail(ErrBadSample, "The advisory document has no first release date.")
	}
	notes := len(d.Document.Notes)
	for _, v := range d.Vulnerabilities {
		notes += len(v.Notes) + len(v.Threats) + len(v.References)
	}
	if len(d.Vulnerabilities) > csafMaxVulns || notes > csafMaxNotes || len(d.Document.Tracking.RevisionHistory) > csafMaxNotes {
		return csafDoc{}, fail(ErrBadSample, "The advisory document is larger than Vedette reads.")
	}
	return d, nil
}

// csafTime reads a CSAF date: RFC 3339, or Fortinet's local form without a zone ("2026-11-10T00:00:00", read as UTC).
func csafTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", time.DateOnly} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// cves is the document's CVE ids, upper case, distinct, in order.
func (d csafDoc) cves() []string {
	var out []string
	for _, v := range d.Vulnerabilities {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		if len(c) <= 20 && cveRE.MatchString(c) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// claimDate is the date the document gives the claim on one CVE: the first revision whose summary speaks of exploitation and names
// this CVE or none, else the first release.
func (d csafDoc) claimDate(cve string) time.Time {
	first, _ := csafTime(d.Document.Tracking.InitialRelease)
	date := time.Time{}
	for _, r := range d.Document.Tracking.RevisionHistory {
		t, ok := csafTime(r.Date)
		if !ok || t.Before(first) || !csafClaimRevRE.MatchString(r.Summary) || claimNegationRE.MatchString(r.Summary) {
			continue
		}
		if named := claimCVERE.FindAllString(r.Summary, -1); len(named) > 0 && !slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, cve) }) {
			continue
		}
		if date.IsZero() || t.Before(date) {
			date = t
		}
	}
	if date.IsZero() {
		return first
	}
	return date
}

// csafClaims is the CVEs a document claims are exploited, with their dates. section picks the document notes read (scope: every CVE
// of the document); perVuln also reads each vulnerability's own notes, threats and reference summaries (scope: its CVE). A threat of
// category exploit_status that says "Exploited: Yes" is always a claim on its vulnerability.
func csafClaims(d csafDoc, section func(csafNote) bool, perVuln bool) []vendorClaim {
	all := d.cves()
	var claimed []string
	add := func(cs []string) {
		for _, c := range cs {
			if !slices.Contains(claimed, c) {
				claimed = append(claimed, c)
			}
		}
	}
	budget := csafMaxClaimText // the text read for claims, whatever the document's shape
	read := func(text string, scope []string) {
		if budget -= min(len(text), maxClaimText); budget >= 0 {
			add(claimedCVEs(text, scope))
		}
	}
	for _, n := range d.Document.Notes {
		if section(n) {
			read(n.Text, all)
		}
	}
	for _, v := range d.Vulnerabilities {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !slices.Contains(all, c) {
			continue
		}
		scope := []string{c}
		for _, t := range v.Threats {
			if strings.EqualFold(t.Category, "exploit_status") && csafExploitedFlagRE.MatchString(t.Details) {
				add(scope)
			}
		}
		if !perVuln {
			continue
		}
		var texts []string
		for _, n := range v.Notes {
			texts = append(texts, n.Text)
		}
		for _, t := range v.Threats {
			texts = append(texts, t.Details)
		}
		for _, r := range v.References {
			texts = append(texts, r.Summary)
		}
		for _, t := range texts {
			read(t, scope)
		}
	}
	out := make([]vendorClaim, 0, len(claimed))
	for _, c := range claimed {
		out = append(out, vendorClaim{CVE: c, Date: d.claimDate(c)})
	}
	return out
}

// ciscoClaims: Cisco states exploitation in the advisory's "Exploitation and Public Announcements" section only.
func ciscoClaims(d csafDoc) []vendorClaim {
	return csafClaims(d, func(n csafNote) bool { return strings.Contains(strings.ToLower(n.Title), "exploitation") }, false)
}

// fortinetClaims: Fortinet states it in each vulnerability's description (and a document note when there is one).
func fortinetClaims(d csafDoc) []vendorClaim {
	return csafClaims(d, func(n csafNote) bool { return n.Category != "legal_disclaimer" }, true)
}

// csafRef is one advisory a list names: its id, the path of its CSAF document on the feed's host and its last change (zero when the
// list does not say).
type csafRef struct {
	ID      string
	Path    string
	Changed time.Time
}

// feedItem is one item of a vendor's advisory feed (RSS 2.0), as written: its link, guid, publication or change date and, for
// FortiGuard, the link of its CSAF document (csaf:link).
type feedItem struct {
	Link, GUID, PubDate, CSAF string
}

// parseAdvisoryFeed reads a vendor's advisory feed (RSS 2.0) into its items: one channel, at most csafMaxListRows items, each field
// at most 2 KB. who names the feed in errors.
func parseAdvisoryFeed(r io.Reader, who string) ([]feedItem, error) {
	dec := xml.NewDecoder(r)
	var (
		out                []feedItem
		cur                feedItem
		inItem, sawChannel bool
		field              *string
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, readFail(err, "%s could not be read: %v.", who, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			field = nil
			switch {
			case t.Name.Local == "channel":
				sawChannel = true
			case t.Name.Local == "item":
				if len(out) == csafMaxListRows {
					return nil, fail(ErrBadSample, "%s has more than %s items.", who, grouped(csafMaxListRows))
				}
				inItem, cur = true, feedItem{}
			case !inItem:
			case t.Name.Local == "link" && t.Name.Space == "":
				field = &cur.Link
			case t.Name.Local == "link" && strings.HasSuffix(t.Name.Space, "/csaf"):
				field = &cur.CSAF
			case t.Name.Local == "guid":
				field = &cur.GUID
			case t.Name.Local == "pubDate":
				field = &cur.PubDate
			}
		case xml.CharData:
			if field != nil && len(*field)+len(t) <= 2048 {
				*field += string(t)
			}
		case xml.EndElement:
			field = nil
			if t.Name.Local == "item" && inItem {
				inItem = false
				cur.Link, cur.GUID, cur.PubDate, cur.CSAF = strings.TrimSpace(cur.Link), strings.TrimSpace(cur.GUID), strings.TrimSpace(cur.PubDate), strings.TrimSpace(cur.CSAF)
				out = append(out, cur)
			}
		}
	}
	if !sawChannel {
		return nil, fail(ErrBadSample, "%s is not an RSS feed.", who)
	}
	return out, nil
}

// lastPart is the last path segment of a link, without its query.
func lastPart(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Path[strings.LastIndexByte(u.Path, '/')+1:]
}

// ciscoFeedTimeLayout is the feed's form of a change ("2026-11-20 20:37:16.0", UTC as Cisco's advisory list writes it).
const ciscoFeedTimeLayout = "2006-01-02 15:04:05.0"

// parseCiscoFeed reads Cisco's security advisory feed: of each item its advisory id (the last part of its guid, else its link) and
// its last change (pubDate). The path of the CSAF document is Cisco's fixed layout under the id. An item with a bad id or date is
// rejected.
func parseCiscoFeed(r io.Reader) ([]csafRef, Stats, error) {
	items, err := parseAdvisoryFeed(r, "Cisco's advisory feed")
	if err != nil {
		return nil, Stats{}, err
	}
	tl := newTally()
	var out []csafRef
	for i, it := range items {
		id := lastPart(it.GUID)
		if id == "" {
			id = lastPart(it.Link)
		}
		changed, err := time.Parse(ciscoFeedTimeLayout, it.PubDate)
		if !ciscoIDRE.MatchString(id) || err != nil {
			tl.reject(i+1, "item: %s has no advisory id or date", it.Link)
			continue
		}
		tl.Accepted++
		out = append(out, csafRef{ID: id, Path: "/security/center/contentjson/CiscoSecurityAdvisory/" + id + "/csaf/" + id + ".json", Changed: changed.UTC()})
	}
	return out, tl.stats(), nil
}

// parseFortiGuardFeed reads FortiGuard's advisory feed: of each item its advisory id (the last part of its link) and the path of
// its CSAF document (its csaf:link). An item without a CSAF document (an advisory still under investigation) is skipped; one with a
// bad id or document link is rejected.
func parseFortiGuardFeed(r io.Reader) ([]csafRef, Stats, error) {
	items, err := parseAdvisoryFeed(r, "FortiGuard's advisory feed")
	if err != nil {
		return nil, Stats{}, err
	}
	tl := newTally()
	var out []csafRef
	for i, it := range items {
		if it.CSAF == "" {
			continue
		}
		id := lastPart(it.Link)
		u, err := url.Parse(it.CSAF)
		if !fortinetIDRE.MatchString(id) || err != nil || u.Scheme != "https" || u.RawQuery != "" || !fortinetCSAFPath.MatchString(u.Path) {
			tl.reject(i+1, "item: %s has no advisory id or a bad document link", it.Link)
			continue
		}
		tl.Accepted++
		out = append(out, csafRef{ID: id, Path: u.Path})
	}
	return out, tl.stats(), nil
}

// readAdvisories asks the feed's host for the CSAF document of each advisory in turn (vendorPause apart) and reads its claims. since,
// when not zero, is sent as If-Modified-Since (an unchanged document is not read again). A document the vendor took down (404, 410)
// or one that cannot be read is skipped and counted; any other failure fails the pull, so nothing is written from half a list.
func (s *Service) readAdvisories(ctx context.Context, base *url.URL, refs []csafRef, since time.Time, advisoryURL string, claims func(csafDoc) []vendorClaim) (vendorRead, int, error) {
	var (
		read vendorRead
		size int
	)
	tl := newTally()
	if len(refs) > csafMaxDocs {
		return read, 0, fail(ErrBadSample, "The advisory list names more than %s changed advisories.", grouped(csafMaxDocs))
	}
	for i, ref := range refs {
		if i > 0 {
			if err := s.sleep(ctx, vendorPause); err != nil {
				return read, 0, err
			}
		}
		u := *base
		u.Path, u.RawPath, u.RawQuery, u.Fragment = ref.Path, "", "", ""
		req := Request{URL: u.String(), MaxBytes: csafMaxBytes}
		if !since.IsZero() {
			req.LastModified = since.UTC().Format(http.TimeFormat)
		}
		var (
			doc     csafDoc
			parseOK bool
		)
		req.Stream = func(r io.Reader) error {
			c := &countReader{r: r}
			var err error
			doc, err = parseCSAF(c)
			size += c.n
			if err == nil || errors.Is(err, ErrTooLarge) {
				parseOK = err == nil
				return err
			}
			return nil // a bad document is counted below, not a failed pull
		}
		resp, err := s.Fetcher.Fetch(ctx, req)
		var se *StatusError
		switch {
		case errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusGone):
			tl.reject(i+1, "%s: the advisory document is gone", ref.ID)
			continue
		case errors.Is(err, ErrTooLarge):
			tl.reject(i+1, "%s: the advisory document is larger than Vedette reads", ref.ID)
			continue
		case err != nil:
			return read, 0, err
		case resp.NotModified:
			continue
		case !parseOK:
			tl.reject(i+1, "%s: the advisory document could not be read", ref.ID)
			continue
		case !strings.EqualFold(strings.TrimSpace(doc.Document.Tracking.ID), ref.ID):
			tl.reject(i+1, "%s: the document is another advisory's", ref.ID)
			continue
		}
		tl.Accepted++
		detail, _ := json.Marshal(map[string]string{"advisory": ref.ID})
		read.Docs = append(read.Docs, claimDoc{URL: advisoryURL + ref.ID, Detail: string(detail), Claims: claims(doc)})
	}
	read.Stats = tl.stats()
	return read, size, nil
}

// prevGood is the start of the window of changes a pull of a vendor feed reads: the last good pull, or zero for a first pull (and
// after an error, when the feed is read again from its last good pull: the claims of a failed pull were never written).
func prevGood(src sourceRow) time.Time {
	if src.LastSuccess == nil || src.Records == nil {
		return time.Time{}
	}
	return *src.LastSuccess
}

// buildCisco reads Cisco's advisory feed and the CSAF document of each advisory changed since the last good pull (every advisory
// of the feed at a first pull).
func (s *Service) buildCisco(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	base, err := url.Parse(src.URL)
	if err != nil || base.Host == "" {
		return p, fail(ErrBadConfig, "The feed's address is not valid.")
	}
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	var (
		refs []csafRef
		st   Stats
		size int
	)
	if _, err := s.Fetcher.Fetch(ctx, Request{URL: src.URL, MaxBytes: csafListMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		refs, st, err = parseCiscoFeed(c)
		size += c.n
		return err
	}}); err != nil {
		return p, err
	}
	if err := accepted(st); err != nil {
		return p, err
	}
	if g := prevGood(src); !g.IsZero() {
		from := g.Add(-csafReReadSlack)
		refs = slices.DeleteFunc(refs, func(r csafRef) bool { return r.Changed.Before(from) })
	}
	read, n, err := s.readAdvisories(ctx, base, refs, time.Time{}, ciscoAdvisoryURL, ciscoClaims)
	if err != nil {
		return p, err
	}
	if read.Accepted == 0 && read.Rejected > 0 && prevGood(src).IsZero() {
		return p, fail(ErrBadSample, "None of the %s advisory documents could be read: %s.", grouped(read.Rejected), mostOften(read.Reasons[0]))
	}
	read.Rejected += st.Rejected
	read.Reasons = append(read.Reasons, st.Reasons...)
	p.out = outcome{OK: true, Bytes: size + n}
	p.out.fill(read.Stats, 0)
	p.vendor, p.hasVendor = read, true
	return p, nil
}

// buildFortinet reads FortiGuard's advisory feed (conditional on the last good pull's validators) and the CSAF document of each
// advisory it lists that changed since the last good pull.
func (s *Service) buildFortinet(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	base, err := url.Parse(src.URL)
	if err != nil || base.Host == "" {
		return p, fail(ErrBadConfig, "The feed's address is not valid.")
	}
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	var (
		refs []csafRef
		st   Stats
		size int
	)
	req := Request{URL: src.URL, MaxBytes: csafListMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		refs, st, err = parseFortiGuardFeed(c)
		size += c.n
		return err
	}}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	resp, err := s.Fetcher.Fetch(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	if err := accepted(st); err != nil {
		return p, err
	}
	since := time.Time{}
	if g := prevGood(src); !g.IsZero() {
		since = g.Add(-csafReReadSlack)
	}
	read, n, err := s.readAdvisories(ctx, base, refs, since, fortinetAdvisoryURL, fortinetClaims)
	if err != nil {
		return p, err
	}
	if read.Accepted == 0 && read.Rejected > 0 && since.IsZero() {
		return p, fail(ErrBadSample, "None of the %s advisory documents could be read: %s.", grouped(read.Rejected), mostOften(read.Reasons[0]))
	}
	read.Rejected += st.Rejected
	read.Reasons = append(read.Reasons, st.Reasons...)
	p.out = outcome{OK: true, Bytes: size + n, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(read.Stats, 0)
	p.vendor, p.hasVendor = read, true
	return p, nil
}
