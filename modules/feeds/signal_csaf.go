package feeds

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
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
// advisories. Cisco's gives each advisory's last change, and the box reads the CSAF document of those whose change time differs
// from the copy it read (Cisco serves no validators for them); FortiGuard's gives each CSAF document's link, and each document is
// asked with the ETag and Last-Modified it last gave, so an unchanged one answers 304 (advisoryMemory). A first pull, and the first
// after the box restarts, reads every advisory of the feed (about 50: about 13 MB for Cisco, which serves its documents uncompressed,
// 0.3 MB for Fortinet). A box that pulls every few hours sees every change; claims older than the feeds reach are almost all on the
// CISA list already. Every request goes to the feed's own host: a link in the data is reduced to its path, checked, and asked of
// that host.

// Where a person reads an advisory (feeds_signal.url): the vendor's own page, whatever host the feed is pulled from.
const (
	ciscoAdvisoryURL    = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
	fortinetAdvisoryURL = "https://fortiguard.fortinet.com/psirt/"
)

// Bounds: one CSAF document (Cisco's largest seen is 1.1 MB, its product tree), an advisory feed, the advisories one pull reads,
// the items of a feed, the vulnerabilities of one document, its notes, threats, references and revisions together, the text of one
// document read for claims (Fortinet's longest is about 20 KB) and the length of a revision summary read.
const (
	csafMaxBytes      = 4 << 20
	csafListMaxBytes  = 8 << 20
	csafMaxDocs       = 2_000
	csafMaxListRows   = 5_000
	csafMaxVulns      = 500 // Cisco's largest is in the tens; Fortinet repeats each vulnerability once per product
	csafMaxNotes      = 2_000
	csafMaxClaimText  = 1 << 20
	csafMaxRevSummary = maxClaimSentence
)

var (
	ciscoIDRE        = regexp.MustCompile(`^cisco-sa-[A-Za-z0-9][A-Za-z0-9._-]{1,100}$`)
	fortinetIDRE     = regexp.MustCompile(`^FG-IR-[0-9]{2}-[0-9]{1,6}$`)
	fortinetCSAFPath = regexp.MustCompile(`^/fortiguard/psirt/csaf_[A-Za-z0-9._-]{1,200}\.json$`)
	// csafRevExploitRE, csafRevPoCRE: a revision summary that speaks of exploitation in a vendor's short form ("Updated exploitation
	// status.", "Updated with information about becoming aware of exploitation.") states it, unless it speaks of proof-of-concept
	// code or a public announcement.
	csafRevExploitRE = regexp.MustCompile(`(?i)\bexploitation\b|\bexploited\b|in the wild|malicious use`)
	csafRevNegRE     = regexp.MustCompile(`(?i)\b(?:not|no|never|nor)\b|n't\b`)
	csafRevPoCRE     = regexp.MustCompile(`(?i)proof[- ]of[- ]concept|\bpoc\b|exploit code|public(?:ly)? (?:disclos|availab)`)
	// csafExploitedFlagRE: the CSAF threat of category exploit_status as some vendors fill it ("Exploited:Yes").
	csafExploitedFlagRE = regexp.MustCompile(`(?i)\bexploited\s*:\s*(yes|no)\b`)
)

type csafNote struct {
	Category, Title, Text string
}

type csafRevision struct {
	Date, Summary string
}

type csafVuln struct {
	CVE        string
	Notes      []csafNote
	Threats    []csafNote // Category and Details (as Text)
	References []string   // summaries
}

// csafDoc is the part of a CSAF 2.0 document the claim rules read.
type csafDoc struct {
	ID, InitialRelease, CurrentRelease string
	Revisions                          []csafRevision
	Notes                              []csafNote
	Vulnerabilities                    []csafVuln
}

// parseCSAF reads one CSAF document as a stream (jsonStream: every bound holds while reading): one JSON object and nothing after it,
// with a tracking id and a readable first release (fail-closed). Only document.tracking (id, initial_release_date, revision_history
// date and summary), document.notes and, of each vulnerability, its cve, notes, threats and reference summaries are kept; everything
// else (the product tree above all) is skipped token by token.
func parseCSAF(r io.Reader) (csafDoc, error) {
	j := newJSONStream(r, "The advisory document")
	var (
		d     csafDoc
		parts int // notes, threats, references and revisions of the whole document
	)
	note := func(n *csafNote, textKey string, textMax int) func(string) error {
		return func(k string) (err error) {
			switch k {
			case "category":
				n.Category, err = j.str(64)
			case "title":
				n.Title, err = j.str(200)
			case textKey:
				n.Text, err = j.str(textMax)
			default:
				err = j.skip()
			}
			return err
		}
	}
	notes := func(into *[]csafNote, textKey string) error {
		return j.array(csafMaxNotes, &parts, "notes", func() error {
			var n csafNote
			_, err := j.object(note(&n, textKey, maxClaimText))
			*into = append(*into, n)
			return err
		})
	}
	tracking := func(k string) (err error) {
		switch k {
		case "id":
			d.ID, err = j.str(200)
		case "initial_release_date":
			d.InitialRelease, err = j.str(64)
		case "current_release_date":
			d.CurrentRelease, err = j.str(64)
		case "revision_history":
			err = j.array(csafMaxNotes, &parts, "revisions", func() error {
				var rv csafRevision
				_, err := j.object(func(k string) (err error) {
					switch k {
					case "date":
						rv.Date, err = j.str(64)
					case "summary":
						rv.Summary, err = j.str(csafMaxRevSummary)
					default:
						err = j.skip()
					}
					return err
				})
				d.Revisions = append(d.Revisions, rv)
				return err
			})
		default:
			err = j.skip()
		}
		return err
	}
	vuln := func() error {
		var v csafVuln
		_, err := j.object(func(k string) (err error) {
			switch k {
			case "cve":
				v.CVE, err = j.str(64)
			case "notes":
				err = notes(&v.Notes, "text")
			case "threats":
				err = notes(&v.Threats, "details")
			case "references":
				err = j.array(csafMaxNotes, &parts, "references", func() error {
					var n csafNote
					_, err := j.object(note(&n, "summary", maxClaimText))
					v.References = append(v.References, n.Text)
					return err
				})
			default:
				err = j.skip()
			}
			return err
		})
		d.Vulnerabilities = append(d.Vulnerabilities, v)
		return err
	}
	ok, err := j.object(func(k string) error {
		switch k {
		case "document":
			_, err := j.object(func(k string) error {
				switch k {
				case "tracking":
					_, err := j.object(tracking)
					return err
				case "notes":
					return notes(&d.Notes, "text")
				}
				return j.skip()
			})
			return err
		case "vulnerabilities":
			return j.array(csafMaxVulns, nil, "vulnerabilities", vuln)
		}
		return j.skip()
	})
	if err != nil {
		return csafDoc{}, err
	}
	if !ok {
		return csafDoc{}, fail(ErrBadSample, "The advisory document is not a JSON object.")
	}
	if err := j.end(); err != nil {
		return csafDoc{}, err
	}
	if strings.TrimSpace(d.ID) == "" {
		return csafDoc{}, fail(ErrBadSample, "The advisory document has no id.")
	}
	if _, ok := csafTime(d.InitialRelease); !ok {
		return csafDoc{}, fail(ErrBadSample, "The advisory document has no first release date.")
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
	seen := map[string]bool{}
	for _, v := range d.Vulnerabilities {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		if len(c) <= 20 && cveRE.MatchString(c) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// claimDates is the date the document gives the claim on each CVE of cves: the first revision whose summary speaks of exploitation
// ("Updated to indicate active exploitation attempts in the wild", "Updated exploitation status.", "Added information about active
// exploitation of CVE-2026-20133") and names the CVE or none, else the first release. A summary that speaks of proof-of-concept code
// or a public announcement, or with a negation, does not date a claim. One pass over the revisions: the earliest date of each CVE
// named, and the earliest of the revisions that name none.
func (d csafDoc) claimDates(cves []string, work *claimWork) map[string]time.Time {
	first, _ := csafTime(d.InitialRelease)
	var anyRev time.Time
	byCVE := map[string]time.Time{}
	for _, r := range d.Revisions {
		work.step(1)
		t, ok := csafTime(r.Date)
		if !ok || t.Before(first) || !csafRevExploitRE.MatchString(r.Summary) || csafRevNegRE.MatchString(r.Summary) || csafRevPoCRE.MatchString(r.Summary) {
			continue
		}
		named := claimCVERE.FindAllString(r.Summary, -1)
		work.step(len(named))
		if len(named) == 0 {
			anyRev = earliest(anyRev, t)
		}
		for _, id := range named {
			id = strings.ToUpper(id)
			byCVE[id] = earliest(byCVE[id], t)
		}
	}
	out := make(map[string]time.Time, len(cves))
	for _, c := range cves {
		work.step(1)
		date := earliest(anyRev, byCVE[c])
		if date.IsZero() {
			date = first
		}
		out[c] = date
	}
	return out
}

// csafSection picks the document notes a vendor states exploitation in.
type csafSection func(csafNote) bool

// csafClaims is the CVEs a document claims are exploited, with their dates, and the count of its sentences about exploitation in no
// known form. Structured first: when a vulnerability has a CSAF threat of category exploit_status in a known form ("Exploited: Yes"
// or "Exploited: No"), those threats decide and no text is read; an exploit_status in another form is counted and the text is read. Otherwise the vendor's forms are read in the document notes section picks (scope: every
// CVE of the document) and, with perVuln, in each vulnerability's own notes, threats and reference summaries (scope: its CVE). The
// text read is bounded (csafMaxClaimText) and the work grows with the document's size only (claimWork).
func csafClaims(ctx context.Context, d csafDoc, forms []claimForm, section csafSection, perVuln bool, work *claimWork) ([]vendorClaim, int, error) {
	all := d.cves()
	if len(all) == 0 {
		return nil, 0, nil // no CVE to claim (an advisory still under investigation)
	}
	inDoc := make(map[string]bool, len(all))
	for _, c := range all {
		inDoc[c] = true
	}
	r := newClaimReader(forms, csafMaxClaimText, work)
	r.total = len(all)
	structured := false
	for _, v := range d.Vulnerabilities {
		c := strings.ToUpper(strings.TrimSpace(v.CVE))
		for _, t := range v.Threats {
			work.step(1)
			if !strings.EqualFold(t.Category, "exploit_status") {
				continue
			}
			m := csafExploitedFlagRE.FindStringSubmatch(t.Text)
			if m == nil { // a value in no known form: counted, and the document's text is read as usual
				r.unclassified++
				continue
			}
			structured = true
			if inDoc[c] && strings.EqualFold(m[1], "yes") {
				r.claim(c, true)
			}
		}
	}
	if !structured {
		for _, n := range d.Notes {
			if section(n) {
				if err := r.read(ctx, n.Text, all, inDoc); err != nil {
					return nil, 0, err
				}
			}
		}
		for _, v := range d.Vulnerabilities {
			c := strings.ToUpper(strings.TrimSpace(v.CVE))
			if !perVuln || !inDoc[c] {
				continue
			}
			scope, scopeSet := []string{c}, map[string]bool{c: true}
			texts := make([]string, 0, len(v.Notes)+len(v.Threats)+len(v.References))
			for _, n := range v.Notes {
				texts = append(texts, n.Text)
			}
			for _, t := range v.Threats {
				if !strings.EqualFold(t.Category, "exploit_status") { // counted above already
					texts = append(texts, t.Text)
				}
			}
			texts = append(texts, v.References...)
			for _, t := range texts {
				if err := r.read(ctx, t, scope, scopeSet); err != nil {
					return nil, 0, err
				}
			}
		}
	}
	claimed := r.order
	if !structured {
		claimed = r.result()
	}
	dates := d.claimDates(claimed, work)
	out := make([]vendorClaim, 0, len(claimed))
	for _, c := range claimed {
		out = append(out, vendorClaim{CVE: c, Date: dates[c], Flag: structured})
	}
	return out, r.unclassified, nil
}

// ciscoClaims: Cisco states exploitation in the advisory's "Exploitation and Public Announcements" section only.
func ciscoClaims(ctx context.Context, d csafDoc, work *claimWork) ([]vendorClaim, int, error) {
	return csafClaims(ctx, d, ciscoForms, func(n csafNote) bool { return strings.Contains(strings.ToLower(n.Title), "exploitation") }, false, work)
}

// fortinetClaims: Fortinet states it in each vulnerability's description (and a document note when there is one).
func fortinetClaims(ctx context.Context, d csafDoc, work *claimWork) ([]vendorClaim, int, error) {
	return csafClaims(ctx, d, fortinetForms, func(n csafNote) bool { return n.Category != "legal_disclaimer" }, true, work)
}

// csafRef is one advisory a feed names: its id, the path of its CSAF document on the feed's host and its last change as the feed
// writes it.
type csafRef struct {
	ID      string
	Path    string
	Changed string // the change time as the feed writes it ("" when it does not say), compared as written
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
		_, err := time.Parse(ciscoFeedTimeLayout, it.PubDate)
		if !ciscoIDRE.MatchString(id) || err != nil {
			tl.reject(i+1, "item: %s has no advisory id or date", it.Link)
			continue
		}
		tl.Accepted++
		out = append(out, csafRef{ID: id, Path: "/security/center/contentjson/CiscoSecurityAdvisory/" + id + "/csaf/" + id + ".json", Changed: it.PubDate})
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

// advisoryMemory is what the box remembers, between two pulls of one vendor feed, of the advisories it read: for each advisory id
// the mark of the copy read (Cisco: the change time its feed wrote; Fortinet: the document's ETag and Last-Modified, sent back so the
// host answers 304), and for each advisory link the CVEs it claimed. Marks compare the vendor's clock with the vendor's clock, never
// with the box's. It is kept in memory only: after a restart, a new address or the feed turned off and on, the first pull reads every
// advisory of the feed again (about 50).
type advisoryMemory struct {
	url    string
	marks  map[string]advisoryMark
	claims map[string][]string // advisory link → the CVEs it claimed when last read
}

type advisoryMark struct {
	changed, etag, lastModified string
}

// recallAdvisories is a copy of what the box remembers of a feed's advisories, empty when the memory is of another address or the
// feed has no good pull to build on.
func (s *Service) recallAdvisories(src sourceRow) *advisoryMemory {
	m := &advisoryMemory{url: src.URL, marks: map[string]advisoryMark{}, claims: map[string][]string{}}
	s.advMu.Lock()
	defer s.advMu.Unlock()
	if old := s.adv[src.ID]; old != nil && old.url == src.URL && !prevGood(src).IsZero() {
		maps.Copy(m.marks, old.marks)
		maps.Copy(m.claims, old.claims)
	}
	return m
}

// keepAdvisories stores what a pull read, once its claims are written.
func (s *Service) keepAdvisories(id string, m *advisoryMemory) {
	s.advMu.Lock()
	defer s.advMu.Unlock()
	if s.adv == nil {
		s.adv = map[string]*advisoryMemory{}
	}
	s.adv[id] = m
}

// readAdvisories asks the feed's host for the CSAF document of each advisory of the feed (refs, in turn, vendorPause apart) that
// changed since the copy the box read (mem), reads its claims and updates mem. A document the vendor took down (404, 410), one too
// large or one that cannot be read is skipped and counted; any other failure fails the pull, so nothing is written from half a list.
// The claims of every advisory the box knows are given to applyVendorClaims (Claimed), so a CVE stays while any of them claims it.
func (s *Service) readAdvisories(ctx context.Context, base *url.URL, refs []csafRef, mem *advisoryMemory, advisoryURL string,
	claims func(context.Context, csafDoc, *claimWork) ([]vendorClaim, int, error),
) (vendorRead, int, error) {
	var (
		read vendorRead
		size int
	)
	tl := newTally()
	if len(refs) > csafMaxDocs {
		return read, 0, fail(ErrBadSample, "The advisory feed names more than %s advisories.", grouped(csafMaxDocs))
	}
	asked := 0
	inFeed := map[string]bool{}
	for i, ref := range refs {
		inFeed[ref.ID] = true
		mark := mem.marks[ref.ID]
		if ref.Changed != "" && ref.Changed == mark.changed {
			continue // the copy the box read
		}
		if asked++; asked > 1 {
			if err := s.sleep(ctx, vendorPause); err != nil {
				return read, 0, err
			}
		}
		u := *base
		u.Path, u.RawPath, u.RawQuery, u.Fragment = ref.Path, "", "", ""
		req := Request{URL: u.String(), MaxBytes: csafMaxBytes, ETag: mark.etag, LastModified: mark.lastModified}
		var (
			doc     csafDoc
			parseOK bool
		)
		req.Stream = func(r io.Reader) error {
			c := &countReader{r: &transportReader{r: r}}
			var err error
			doc, err = parseCSAF(c)
			size += c.n
			var te transportErr
			switch {
			case err == nil:
				parseOK = true
				return nil
			case errors.Is(err, ErrTooLarge):
				return err
			case errors.As(err, &te):
				return te.err // the connection failed, not the document: the pull fails and the document is asked again
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
		case !strings.EqualFold(strings.TrimSpace(doc.ID), ref.ID):
			tl.reject(i+1, "%s: the document is another advisory's", ref.ID)
			continue
		}
		cs, unclassified, err := claims(ctx, doc, nil)
		if err != nil {
			return read, 0, err
		}
		tl.Accepted++
		if unclassified > 0 { // new wording is noticed on the feed's note, never read as a claim
			if read.Unclassified == 0 {
				read.UnclassifiedIn = ref.ID
			}
			read.Unclassified += unclassified
		}
		link := advisoryURL + ref.ID
		detail, _ := json.Marshal(map[string]string{"advisory": ref.ID})
		read.Docs = append(read.Docs, claimDoc{URL: link, Detail: string(detail), Claims: cs})
		// Cisco: the copy is marked read only when the document is not older than the change the feed announced (the feed can show a
		// change before the document is updated); FortiGuard: the document's own validators.
		changed := ref.Changed
		if ft, err := time.Parse(ciscoFeedTimeLayout, ref.Changed); err == nil {
			if dt, ok := csafTime(doc.CurrentRelease); !ok || dt.Truncate(time.Second).Before(ft.Truncate(time.Second)) {
				changed = ""
			}
		}
		mem.marks[ref.ID] = advisoryMark{changed: changed, etag: resp.ETag, lastModified: resp.LastModified}
		delete(mem.claims, link)
		for _, c := range cs {
			mem.claims[link] = append(mem.claims[link], c.CVE)
		}
	}
	maps.DeleteFunc(mem.marks, func(id string, _ advisoryMark) bool { return !inFeed[id] }) // only the feed's advisories are compared
	read.Claimed = map[string][]string{}
	for _, link := range slices.Sorted(maps.Keys(mem.claims)) {
		for _, c := range mem.claims[link] {
			read.Claimed[c] = append(read.Claimed[c], link)
		}
	}
	read.Stats = tl.stats()
	return read, size, nil
}

// unclassifiedNote adds to a pull's note how many sentences about exploitation were in no known form: they are not read as claims,
// and the note is how new wording gets noticed.
func unclassifiedNote(note string, r vendorRead) string {
	if r.Unclassified == 0 {
		return note
	}
	s := "sentences"
	if r.Unclassified == 1 {
		s = "sentence"
	}
	add := fmt.Sprintf("%s %s about exploitation in no form Vedette knows (first in %s); not read as claims.", grouped(r.Unclassified), s, r.UnclassifiedIn)
	return strings.TrimSpace(note + " " + add)
}

// transportReader marks the errors of the connection itself, so a document cut by the network is told from a bad document.
type transportReader struct{ r io.Reader }

type transportErr struct{ err error }

func (e transportErr) Error() string { return e.err.Error() }
func (e transportErr) Unwrap() error { return e.err }

func (t *transportReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	var corrupt flate.CorruptInputError
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, ErrTooLarge):
	case errors.Is(err, gzip.ErrChecksum), errors.Is(err, gzip.ErrHeader), errors.As(err, &corrupt):
		// a corrupt compressed body is a bad document (counted), not a broken connection
	default:
		err = transportErr{err}
	}
	return n, err
}

// prevGood is the box's last good pull of a feed, zero for a first pull (and after the feed was turned off and on, or given another
// address: its count is cleared then).
func prevGood(src sourceRow) time.Time {
	if src.LastSuccess == nil || src.Records == nil {
		return time.Time{}
	}
	return *src.LastSuccess
}

// buildCisco reads Cisco's advisory feed and the CSAF document of each advisory whose change time differs from the copy the box read
// (every advisory of the feed at a first pull).
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
	mem := s.recallAdvisories(src)
	read, n, err := s.readAdvisories(ctx, base, refs, mem, ciscoAdvisoryURL, ciscoClaims)
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
	p.out.Note = unclassifiedNote(p.out.Note, read)
	p.vendor, p.hasVendor, p.vendorMem = read, true, mem
	return p, nil
}

// buildFortinet reads FortiGuard's advisory feed (conditional on the last good pull's validators, while the box remembers its documents) and the CSAF document of each
// advisory it lists, sending back the document's own ETag and Last-Modified when the box read it before (the host answers 304 only
// to its exact Last-Modified).
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
	mem := s.recallAdvisories(src)
	req := Request{URL: src.URL, MaxBytes: csafListMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		refs, st, err = parseFortiGuardFeed(c)
		size += c.n
		return err
	}}
	if src.Status == "ok" && len(mem.marks) > 0 { // after a restart the feed is read whole, so the documents are compared again
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
	read, n, err := s.readAdvisories(ctx, base, refs, mem, fortinetAdvisoryURL, fortinetClaims)
	if err != nil {
		return p, err
	}
	if read.Accepted == 0 && read.Rejected > 0 && prevGood(src).IsZero() {
		return p, fail(ErrBadSample, "None of the %s advisory documents could be read: %s.", grouped(read.Rejected), mostOften(read.Reasons[0]))
	}
	read.Rejected += st.Rejected
	read.Reasons = append(read.Reasons, st.Reasons...)
	p.out = outcome{OK: true, Bytes: size + n, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(read.Stats, 0)
	p.out.Note = unclassifiedNote(p.out.Note, read)
	p.vendor, p.hasVendor, p.vendorMem = read, true, mem
	return p, nil
}
