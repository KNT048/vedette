package feeds

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Exploitation claims written as prose: Google's Chrome Releases blog, Android's monthly security bulletins, Rapid7's blog and
// Google Threat Intelligence's blog. None of them has a structured field, so a claim is read only from a sentence that names the CVE
// and states its exploitation in one of the source's own forms (claimForm, signal_claims.go): the forms of a prose source name their
// subject (the CVE ids in the group "cve"), and a negation or a hedge in their open parts ("has not", "could", "if", "may") turns the
// sentence away. A sentence that names a CVE and speaks of exploitation as a fact would, in no known form, is counted on the pull's
// note, never read as a claim. Each claim is one feeds_signal row (kind exploited, source = the feed), dated by the post or bulletin,
// linked to it; no text is kept.
//
// What is read: each blog's own feed (Atom for Chrome Releases, RSS for the two others), every post of it at each pull (the feeds
// hold the last 20 to 25 posts), conditional on the feed's ETag and Last-Modified; Android's bulletin pages of this month and the
// month before, each asked with the ETag and Last-Modified it last gave, and of each page only its notes (Android states
// exploitation in a note: "There are indications that CVE-… may be under limited, targeted exploitation"). The feeds keep no
// history, so a new box also loads the claims of the release's seed (content/signals/seed.json) on its first pull of each feed.

// The built-in prose feeds.
const (
	chromeFeedID  = "chrome-releases"
	androidFeedID = "android-bulletin"
	rapid7FeedID  = "rapid7-blog"
	gtiFeedID     = "gti-blog"
)

// The decoders of the prose feeds.
const (
	DecoderChrome  Decoder = "chrome-releases"  // parsePostFeed (Atom), then chromeForms on each post
	DecoderAndroid Decoder = "android-bulletin" // androidNotes of this month's and last month's bulletin pages, then androidForms
	DecoderRapid7  Decoder = "rapid7-blog"      // parsePostFeed (RSS), then rapid7Forms on each post
	DecoderGTI     Decoder = "gti-blog"         // parsePostFeed (RSS), then gtiForms on each post
)

// The licence lines of the prose feeds (THIRD_PARTY_NOTICES.md has the terms read).
const (
	chromeNotice  = "Facts from Google's Chrome Releases blog (its Atom feed), Google Terms of Service. Each claim links its post."
	androidNotice = "Facts from the Android Security Bulletins (source.android.com, content under CC BY 4.0). Each claim links its bulletin."
	rapid7Notice  = "Facts from Rapid7's blog (its RSS feed), Rapid7 website terms of use. Each claim links its post; no text is kept."
	gtiNotice     = "Facts from Google Threat Intelligence's blog (its RSS feed), Google Terms of Service. Each claim links its post; no text is kept."
)

// textClaimFeed reports a prose feed of exploitation claims.
func textClaimFeed(id string) bool {
	return id == chromeFeedID || id == androidFeedID || id == rapid7FeedID || id == gtiFeedID
}

// Bounds: a feed (Chrome's 25 posts are about 2.5 MB), its nesting depth, the posts of a feed, one post's HTML, a title, the text of one
// post read for claims, a bulletin page (about 0.3 MB) and the notes of a page.
const (
	textFeedMaxBytes  = 6 << 20
	textMaxDepth      = 64
	textMaxPosts      = 500
	textMaxPost       = 2 << 20
	textMaxTitle      = 2 << 10
	textMaxClaimText  = 1 << 20
	androidMaxBytes   = 4 << 20
	androidMaxNotes   = 64
	androidMaxNoteLen = 16 << 10
)

// claimProseRE: a sentence of prose that names a CVE and speaks of exploitation as a fact would; one in no known form is counted.
var claimProseRE = regexp.MustCompile(`(?i)in[- ]the[- ]wild|exploited|zero-day|0-day|actively exploit|exploitation of|under limited|exploits? for`)

// The parts of the prose forms (canonical sentence: lower case, CVE lists as {cve}).
const (
	proseBy   = `(?:(?P<o1>.{1,240}) )?`             // who says it (hedge-checked)
	proseTail = `(?P<o2>(?:[ ,;:(]|–|—|-).{0,400})?` // what follows (hedge-checked)
	proseAdj  = `(?:(?:active|ongoing|limited|targeted|widespread|mass|renewed|continued|zero-day|0-day|in-the-wild|real-world|attempted|successful),? )*`
	proseSees = `(?:confirmed|identified|observed|detected|reported|attributes|attributed|(?:is|are|became|was|were) aware of|` +
		`(?:has|have|had) (?:also )?(?:seen|observed|confirmed|identified|detected|reported))`
	proseVuln  = `(?:(?:an?|another) (?P<o3>[^{}()]{1,120})\()?` // "a zero-day vulnerability (" before the id (hedge-checked)
	proseActor = `(?:threat actors?|the actors?|attackers|adversaries|(?:an?|the) (?:[a-z0-9-]+ )?campaign|unc[0-9]{1,6}|apt[0-9]{1,4}|` +
		`\((?:formerly tracked as )?unc[0-9]{1,6}\))`
)

// proseForms: the claiming sentences of the threat research blogs (Rapid7, Google Threat Intelligence), as they wrote them in 2025–2026.
var proseForms = forms(formClaim, false,
	// "Mandiant/Google Threat Intelligence confirmed in-the-wild exploitation of CVE-… by …", "Rapid7 MDR detected exploitation of
	// CVE-… against …", "GTIG attributes the zero-day exploitation of CVE-… to …", "identified active, in-the-wild exploitation of a
	// zero-day vulnerability (CVE-…)"
	proseBy+`(?:the )?`+proseSees+` (?:the )?`+proseAdj+`exploitation (?:in the wild )?of `+proseVuln+`(?P<cve>\{cve\})\)?`+proseTail,
	// "CVE-… is now being actively exploited in the wild against …"
	proseBy+`(?P<cve>\{cve\}),? (?:is|are|was|were|has been|have been|had been)(?: now| also)?(?: being)?(?: actively)? exploited(?: in the wild| in-the-wild| as (?:an? )?(?:zero-days?|0-days?))?`+proseTail,
	// "Additional Ivanti Connect Secure zero-days exploited in the wild (CVE-…, CVE-…)"
	proseBy+`(?:zero-days?|0-days?|vulnerabilit(?:y|ies)|flaws?) (?:actively )?exploited in the wild \((?P<cve>\{cve\})\)`+proseTail,
	// "CVE-…, an exploited-in-the-wild spoofing vulnerability"
	proseBy+`(?P<cve>\{cve\}),? an? (?:actively )?(?:exploited-in-the-wild|exploited in the wild|exploited zero-day)`+proseTail,
	// "… threat actor ARMORY CASTLE (formerly tracked as UNC5221) exploited CVE-…", "a UNC6240 campaign that exploited CVE-… as a
	// zero-day", "The actor exploited a … vulnerability (CVE-…) to …"
	proseBy+proseActor+`(?: (?:that|which|who))?(?: also)?(?: (?:have|has|had))?(?: actively)? exploited `+proseVuln+`(?P<cve>\{cve\})\)?`+proseTail,
	// "threat actors are also actively exploiting a second zero-day vulnerability (CVE-…)"
	proseBy+proseActor+` (?:are|is|were|was|have been|has been)(?: also)? actively exploiting `+proseVuln+`(?P<cve>\{cve\})\)?`+proseTail,
	// "We also observed a threat actor exploit CVE-…"
	proseBy+`(?:we|mandiant|gtig|rapid7)(?: also)? observed (?:an? |the )?threat actors? (?:exploit|exploiting|exploited) (?P<cve>\{cve\})`+proseTail,
)

// chromeForms: the Chrome Releases sentence ("Google is aware that an exploit for CVE-… exists in the wild."), as written since 2019.
var chromeForms = forms(formClaim, false,
	`google is aware (?:that|of reports that) (?:an exploit|exploits) for (?P<cve>\{cve\}) exists? in the wild`,
	`google is aware that knowledge of (?P<cve>\{cve\}) exists in the wild`,
)

// androidForms: the bulletins' note ("There are indications that CVE-… may be under limited, targeted exploitation."), the list form
// read by androidNotes as one sentence ("… the following may be under limited, targeted exploitation: CVE-…, CVE-…").
var androidForms = forms(formClaim, false,
	`(?:note: )?there (?:are|is) (?:indications|an indication) that (?P<cve>\{cve\}) (?:may be|might be|is|are) under limited,? targeted exploitation`,
	`(?:note: )?there (?:are|is) (?:indications|an indication) that the following (?:may be|might be|is|are) under limited,? targeted exploitation: (?P<cve>\{cve\})`,
)

// rapid7Forms, gtiForms: the research blogs' forms.
var (
	rapid7Forms = proseForms
	gtiForms    = proseForms
)

// post is one post of a blog feed as read.
type post struct {
	Link, Title, Date, Body string
}

// parsePostFeed reads a blog's feed, RSS 2.0 (item: link, title, pubDate, description, content:encoded) or Atom (entry: the
// alternate link, title, published, content), into its posts: at most textMaxPosts, each body at most textMaxPost bytes (the rest is
// not read), each title textMaxTitle. who names the feed in errors.
func parsePostFeed(r io.Reader, who string) ([]post, error) {
	dec := xml.NewDecoder(r)
	dec.Entity = xml.HTMLEntity
	var (
		out                           []post
		inPost, seen                  bool
		depth                         int
		link, title, date, body, desc strings.Builder // body: content:encoded or Atom content, preferred to description
		field                         *strings.Builder
		limit                         int
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
			if depth++; depth > textMaxDepth {
				return nil, fail(ErrBadSample, "%s is nested more than %d levels deep.", who, textMaxDepth)
			}
			field = nil
			name := t.Name.Local
			switch {
			case name == "channel" || name == "feed":
				seen = true
			case name == "item" || name == "entry":
				if len(out) == textMaxPosts {
					return nil, fail(ErrBadSample, "%s has more than %s posts.", who, grouped(textMaxPosts))
				}
				inPost = true
				for _, b := range []*strings.Builder{&link, &title, &date, &body, &desc} {
					b.Reset()
				}
			case !inPost:
			case name == "link" && !feedOwn(t.Name.Space):
			case name == "link":
				href, rel := "", ""
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "href":
						href = a.Value
					case "rel":
						rel = a.Value
					}
				}
				if href != "" { // Atom: the alternate link
					if (rel == "" || rel == "alternate") && len(href) <= textMaxTitle {
						link.Reset()
						link.WriteString(href)
					}
				} else {
					field, limit = &link, textMaxTitle
				}
			case !feedOwn(t.Name.Space): // media:title, media:content and the like
				if name == "encoded" && strings.Contains(t.Name.Space, "purl.org/rss/1.0/modules/content") {
					field, limit = &body, textMaxPost
				}
			case name == "title":
				field, limit = &title, textMaxTitle
			case name == "pubDate" || name == "published":
				field, limit = &date, 64
			case name == "content":
				field, limit = &body, textMaxPost
			case name == "description" || name == "summary":
				field, limit = &desc, textMaxPost
			}
		case xml.CharData:
			if field != nil && field.Len() < limit {
				field.Write(t[:min(len(t), limit-field.Len())])
			}
		case xml.EndElement:
			depth--
			field = nil
			if (t.Name.Local == "item" || t.Name.Local == "entry") && inPost {
				inPost = false
				p := post{Link: strings.TrimSpace(link.String()), Title: strings.TrimSpace(title.String()), Date: strings.TrimSpace(date.String()), Body: body.String()}
				if strings.TrimSpace(p.Body) == "" {
					p.Body = desc.String()
				}
				out = append(out, p)
			}
		}
	}
	if !seen {
		return nil, fail(ErrBadSample, "%s is not an RSS or Atom feed.", who)
	}
	return out, nil
}

// feedOwn says whether an element's namespace is the feed's own: none (RSS) or Atom's.
func feedOwn(space string) bool { return space == "" || strings.HasSuffix(space, "/Atom") }

// postTime reads a post's date: RFC 1123 with a zone (RSS) or RFC 3339 (Atom).
func postTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, "Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// proseBlocks are the HTML elements that end a line of text; every other tag is inline (a link, emphasis, a span) and is dropped
// without breaking its sentence.
var proseBlocks = map[string]bool{
	"p": true, "div": true, "li": true, "ul": true, "ol": true, "br": true, "tr": true, "td": true, "th": true, "table": true,
	"thead": true, "tbody": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "pre": true,
	"blockquote": true, "figure": true, "figcaption": true, "section": true, "hr": true, "article": true, "header": true,
	"footer": true, "dt": true, "dd": true, "dl": true, "aside": true, "code": true, "img": true, "iframe": true,
}

// proseText is the text of an HTML fragment, in one pass: HTML white space as one space, block elements as line breaks, inline
// elements dropped, script and style left out, entities decoded, a no-break space as a space.
func proseText(h string) string {
	var b strings.Builder
	b.Grow(len(h))
	gt := -1 // the next '>' at or after the current position, -1 for none left: each '<' is decided in constant time
	for i := 0; i < len(h); {
		c := h[i]
		if c == '<' {
			if gt <= i && gt != -2 {
				if k := strings.IndexByte(h[i+1:], '>'); k >= 0 {
					gt = i + 1 + k
				} else {
					gt = -2 // no '>' in the rest
				}
			}
			if gt > i && gt-i <= 2001 {
				tag := h[i+1 : gt]
				closing := strings.HasPrefix(tag, "/")
				name := strings.TrimLeft(tag, "/")
				if k := strings.IndexAny(name, " \t\r\n/"); k >= 0 {
					name = name[:k]
				}
				name = strings.ToLower(name)
				i = gt + 1
				if !closing && (name == "script" || name == "style") {
					i = closingTag(h, i, name)
					continue
				}
				if proseBlocks[name] {
					b.WriteByte('\n')
				}
				continue
			}
		}
		switch c {
		case '\n', '\r', '\t':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
		i++
	}
	s := b.String()
	if strings.ContainsRune(s, '&') {
		s = html.UnescapeString(s)
	}
	return strings.ReplaceAll(s, " ", " ")
}

// closingTag is where the closing tag of name ("</script", any case) starts at or after i, the end of h when there is none: one pass.
func closingTag(h string, i int, name string) int {
	for {
		k := strings.Index(h[i:], "</")
		if k < 0 {
			return len(h)
		}
		j := i + k + 2
		if len(h)-j >= len(name) && strings.EqualFold(h[j:j+len(name)], name) {
			return i + k
		}
		i = j
	}
}

// proseClaims reads the claims of one post or note: its title and text (already plain), within the scope of the CVE ids they name.
// The text is read in parts of at most maxClaimText bytes, cut at line breaks, up to textMaxClaimText in all.
func proseClaims(ctx context.Context, forms []claimForm, title, text string) ([]string, int, error) {
	var scope []string
	set := map[string]bool{}
	for _, id := range claimCVERE.FindAllString(title+"\n"+text, -1) {
		if id = strings.ToUpper(id); !set[id] {
			set[id] = true
			scope = append(scope, id)
		}
	}
	if len(scope) == 0 {
		return nil, 0, nil
	}
	r := newClaimReader(forms, textMaxClaimText, nil)
	r.prose, r.total = true, len(scope)
	if err := r.read(ctx, title, scope, set); err != nil {
		return nil, 0, err
	}
	for text != "" {
		part := text
		if len(part) > maxClaimText {
			cut := strings.LastIndexByte(part[:maxClaimText], '\n')
			if cut <= 0 {
				cut = maxClaimText
			}
			part = part[:cut]
		}
		text = text[len(part):]
		if err := r.read(ctx, part, scope, set); err != nil {
			return nil, 0, err
		}
		if r.budget < 0 {
			break
		}
	}
	return r.result(), r.unclassified, nil
}

// postClaims turns the posts of a feed into claim documents: a post with no https link or no readable date is rejected; one that
// claims nothing is still a document read (so a claim it took back goes).
func postClaims(ctx context.Context, posts []post, forms []claimForm, read *vendorRead) error {
	tl := newTally()
	for i, p := range posts {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := url.Parse(p.Link)
		day, ok := postTime(p.Date)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(p.Link) > 500 || !ok {
			tl.reject(i+1, "post: %s has no https link or no date", quoteVal(p.Link))
			continue
		}
		cs, unclassified, err := proseClaims(ctx, forms, proseText(p.Title), proseText(p.Body))
		if err != nil {
			return err
		}
		tl.Accepted++
		if unclassified > 0 {
			if read.Unclassified == 0 {
				read.UnclassifiedIn = p.Link
			}
			read.Unclassified += unclassified
		}
		doc := claimDoc{URL: p.Link}
		for _, c := range cs {
			doc.Claims = append(doc.Claims, vendorClaim{CVE: c, Date: day})
		}
		read.Docs = append(read.Docs, doc)
	}
	read.Stats = tl.stats()
	return nil
}

// claimedNow is, for each CVE, the links of the documents read now that claim it.
func claimedNow(docs []claimDoc) map[string][]string {
	out := map[string][]string{}
	for _, d := range docs {
		for _, c := range d.Claims {
			if !slices.Contains(out[c.CVE], d.URL) {
				out[c.CVE] = append(out[c.CVE], d.URL)
			}
		}
	}
	return out
}

// buildTextClaims reads a prose feed: a blog's feed (conditional on its last validators) and the claims of each of its posts, or
// Android's bulletin pages (buildAndroid). On the feed's first good pull the seed's claims of the feed are read with it.
func (s *Service) buildTextClaims(ctx context.Context, src sourceRow, p pullPlan, dec Decoder) (pullPlan, error) {
	if dec == DecoderAndroid {
		return s.buildAndroid(ctx, src, p)
	}
	forms := map[Decoder][]claimForm{DecoderChrome: chromeForms, DecoderRapid7: rapid7Forms, DecoderGTI: gtiForms}[dec]
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	var (
		posts []post
		size  int
	)
	req := Request{URL: src.URL, MaxBytes: textFeedMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		posts, err = parsePostFeed(c, "The blog's feed")
		size += c.n
		return err
	}}
	if src.Status == "ok" && !prevGood(src).IsZero() {
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
	var read vendorRead
	if err := postClaims(ctx, posts, forms, &read); err != nil {
		return p, err
	}
	if err := accepted(read.Stats); err != nil {
		return p, err
	}
	read.Claimed = claimedNow(read.Docs)
	if firstPull(src) {
		read.Docs = append(read.Docs, s.seedDocs(src.ID, read.Docs)...)
	}
	p.out = outcome{OK: true, Bytes: size, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(read.Stats, 0)
	p.out.Note = unclassifiedNote(p.out.Note, read)
	p.vendor, p.hasVendor = read, true
	return p, nil
}

// androidPagePath is the path of a month's bulletin under the feed's address: bulletins since 2026 are under a folder of their year,
// older ones are not (androidPageAlt).
func androidPagePath(month time.Time) string {
	return fmt.Sprintf("%d/%s", month.Year(), month.Format("2006-01-02"))
}

func androidPageAlt(month time.Time) string { return month.Format("2006-01-02") }

// androidPublishedRE: the bulletin's own date ("Published November 2, 2026").
var androidPublishedRE = regexp.MustCompile(`Published\s+((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+[0-9]{1,2},\s+[0-9]{4})`)

// androidNotes reads a bulletin page: its publication date and the text of each of its notes (<aside class="note">), where Android
// states exploitation. A note whose sentence ends in a list of CVE ids ("… may be under limited, targeted exploitation." then one id
// per list item) is read as one sentence: the sentence, a colon, the ids. At most androidMaxNotes notes of androidMaxNoteLen bytes.
func androidNotes(page string) (published time.Time, notes []string) {
	if m := androidPublishedRE.FindStringSubmatch(proseText(page[:min(len(page), 1<<20)])); m != nil {
		published, _ = time.Parse("January 2, 2006", strings.Join(strings.Fields(m[1]), " "))
	}
	rest := page
	for len(notes) < androidMaxNotes {
		i := strings.Index(rest, "<aside")
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := strings.Index(rest, "</aside>")
		if end < 0 {
			end = len(rest)
		}
		block := rest[:end]
		rest = rest[end:]
		open := block[:max(0, strings.IndexByte(block, '>'))]
		if !strings.Contains(open, "note") || len(block) > androidMaxNoteLen {
			continue
		}
		var lines []string
		for _, l := range strings.Split(proseText(block), "\n") {
			if l = strings.Join(strings.Fields(l), " "); l != "" {
				lines = append(lines, l)
			}
		}
		// a sentence followed by lines that are each only CVE ids: one sentence ending in the list
		for k := 0; k < len(lines); k++ {
			j := k + 1
			for j < len(lines) && claimCVERE.ReplaceAllString(strings.Trim(lines[j], " ,;."), "") == "" {
				j++
			}
			if j > k+1 && strings.HasSuffix(lines[k], ".") {
				ids := make([]string, 0, j-k-1)
				for _, l := range lines[k+1 : j] {
					ids = append(ids, strings.Trim(l, " ,;."))
				}
				lines[k] = strings.TrimSuffix(lines[k], ".") + ": " + strings.Join(ids, ", ") + "."
				lines = slices.Delete(lines, k+1, j)
			}
		}
		notes = append(notes, strings.Join(lines, "\n"))
	}
	return published, notes
}

// buildAndroid reads the bulletins of this month and the month before (the month's page under its year's folder, else the older
// address), each with the ETag and Last-Modified it last gave, and the claims of their notes. A month not published yet (404) is
// skipped. Each claim is dated by the bulletin's publication.
func (s *Service) buildAndroid(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	base, err := url.Parse(src.URL)
	if err != nil || base.Host == "" {
		return p, fail(ErrBadConfig, "The feed's address is not valid.")
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	mem := s.recallAdvisories(src)
	now := s.now().UTC()
	this := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	var (
		read  vendorRead
		size  int
		asked int
	)
	tl := newTally()
	for _, month := range []time.Time{this.AddDate(0, -1, 0), this} {
	paths:
		for _, path := range []string{androidPagePath(month), androidPageAlt(month)} {
			if asked++; asked > 1 {
				if err := s.sleep(ctx, vendorPause); err != nil {
					return p, err
				}
			}
			u := base.ResolveReference(&url.URL{Path: path})
			id := month.Format("2006-01")
			mark := mem.marks[id]
			if mark.changed != path {
				mark = advisoryMark{}
			}
			var page []byte
			req := Request{URL: u.String(), MaxBytes: androidMaxBytes, ETag: mark.etag, LastModified: mark.lastModified, Stream: func(r io.Reader) error {
				c := &countReader{r: &transportReader{r: r}}
				var err error
				page, err = io.ReadAll(c)
				size += c.n
				var te transportErr
				if errors.As(err, &te) {
					return te.err
				}
				return err
			}}
			resp, err := s.Fetcher.Fetch(ctx, req)
			var se *StatusError
			switch {
			case errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusGone):
				continue // not under this address
			case errors.Is(err, ErrTooLarge):
				tl.reject(1, "%s: the bulletin is larger than Vedette reads", id)
			case err != nil:
				return p, err
			case resp.NotModified:
				tl.Accepted++
			default:
				published, notes := androidNotes(string(page))
				if published.IsZero() {
					published = month.AddDate(0, 0, 1) // no date on the page: the first Monday is near the 1st
				}
				link := u.String()
				doc := claimDoc{URL: link}
				for _, n := range notes {
					cs, unclassified, err := proseClaims(ctx, androidForms, "", n)
					if err != nil {
						return p, err
					}
					if unclassified > 0 {
						if read.Unclassified == 0 {
							read.UnclassifiedIn = link
						}
						read.Unclassified += unclassified
					}
					for _, c := range cs {
						doc.Claims = append(doc.Claims, vendorClaim{CVE: c, Date: published})
					}
				}
				tl.Accepted++
				read.Docs = append(read.Docs, doc)
				mem.marks[id] = advisoryMark{changed: path, etag: resp.ETag, lastModified: resp.LastModified}
				delete(mem.claims, link)
				for _, c := range doc.Claims {
					mem.claims[link] = append(mem.claims[link], c.CVE)
				}
			}
			break paths
		}
	}
	keep := map[string]bool{this.Format("2006-01"): true, this.AddDate(0, -1, 0).Format("2006-01"): true}
	maps.DeleteFunc(mem.marks, func(id string, _ advisoryMark) bool { return !keep[id] })
	read.Stats = tl.stats()
	if read.Accepted == 0 {
		return p, fail(ErrBadSample, "No Android security bulletin of this month or the month before could be read.")
	}
	read.Claimed = map[string][]string{}
	for link, cves := range mem.claims {
		for _, c := range cves {
			read.Claimed[c] = append(read.Claimed[c], link)
		}
	}
	for _, links := range read.Claimed {
		slices.Sort(links)
	}
	if firstPull(src) {
		read.Docs = append(read.Docs, s.seedDocs(src.ID, read.Docs)...)
	}
	p.out = outcome{OK: true, Bytes: size}
	p.out.fill(read.Stats, 0)
	p.out.Note = unclassifiedNote(p.out.Note, read)
	p.vendor, p.hasVendor, p.vendorMem = read, true, mem
	return p, nil
}
