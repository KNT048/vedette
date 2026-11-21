package feeds

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	signaldata "github.com/knt048/vedette/content/signals"
)

// The seed of exploitation claims (content/signals/seed.json) ships inside each release: the claims Vedette's own decoders read, with
// the same forms, from the sources that keep no history, so a box installed later still holds the claims made before it existed. A
// feed's first good pull (and its first after it was turned off and on) reads the seed's claims of that feed together with what the
// feed holds now (seedDocs), through the same write as every claim: a claim the box sees itself keeps the earlier date, a seed claim
// whose post the box reads now and finds without it is not taken. The release builds the seed (`go run ./scripts/release
// signal-seed`) from the previous seed and the current feeds (MergeSeed); nothing is added by hand.

// SeedClaim is one claim of the seed: facts only.
type SeedClaim struct {
	CVE    string `json:"cve"`
	Source string `json:"source"` // the feed whose decoder read it
	Date   string `json:"date"`   // the date of the claim, RFC 3339 UTC
	URL    string `json:"url"`    // the post, bulletin or advisory that says it
}

// Seed is the seed file.
type Seed struct {
	Claims []SeedClaim `json:"claims"`
}

// seedSources are the feeds the seed holds claims of.
var seedSources = []string{chromeFeedID, androidFeedID, rapid7FeedID, gtiFeedID, ciscoFeedID, fortinetFeedID}

// seedMaxClaims bounds the seed (it grows by about a hundred claims a year).
const seedMaxClaims = 50_000

// check says what is wrong with a claim, "" when nothing.
func (c SeedClaim) check() string {
	u, err := url.Parse(c.URL)
	_, terr := time.Parse(time.RFC3339, c.Date)
	switch {
	case !cveRE.MatchString(c.CVE):
		return "a bad CVE id"
	case !slices.Contains(seedSources, c.Source):
		return "a source that is not a claim feed"
	case terr != nil:
		return "a bad date"
	case err != nil || u.Scheme != "https" || u.Host == "" || len(c.URL) > 500:
		return "a bad link"
	}
	return ""
}

// ParseSeed reads a seed file: every claim must be whole and valid, and no (CVE, source) twice.
func ParseSeed(data []byte) (Seed, error) {
	var s Seed
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Seed{}, fmt.Errorf("feeds: seed: %w", err)
	}
	if len(s.Claims) > seedMaxClaims {
		return Seed{}, fmt.Errorf("feeds: seed: more than %d claims", seedMaxClaims)
	}
	seen := map[[2]string]bool{}
	for i, c := range s.Claims {
		if why := c.check(); why != "" {
			return Seed{}, fmt.Errorf("feeds: seed: claim %d (%s %s): %s", i+1, c.CVE, c.Source, why)
		}
		k := [2]string{c.CVE, c.Source}
		if seen[k] {
			return Seed{}, fmt.Errorf("feeds: seed: %s %s twice", c.CVE, c.Source)
		}
		seen[k] = true
	}
	return s, nil
}

// JSON is the seed file: claims sorted by source, then CVE, one per line, so a release's change reads as lines added.
func (s Seed) JSON() []byte {
	cs := slices.Clone(s.Claims)
	slices.SortFunc(cs, func(a, b SeedClaim) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.CVE, b.CVE))
	})
	var b bytes.Buffer
	b.WriteString("{\"claims\": [")
	for i, c := range cs {
		line, _ := json.Marshal(c) // four strings: never fails
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("\n  ")
		b.Write(line)
	}
	b.WriteString("\n]}\n")
	return b.Bytes()
}

// SeedRead is what a decoder reads of one post, bulletin or advisory now: its link and the claims it makes.
type SeedRead struct {
	URL    string
	Claims []SeedClaim
}

// MergeSeed is the next seed: the previous one, without the claims a document read now no longer makes, plus the claims read now; of
// one (CVE, source), the earliest date and its link.
func MergeSeed(prev Seed, reads []SeedRead) Seed {
	readNow := map[string]map[string]bool{} // link → the CVEs it claims now
	for _, r := range reads {
		if readNow[r.URL] == nil {
			readNow[r.URL] = map[string]bool{}
		}
		for _, c := range r.Claims {
			readNow[r.URL][c.CVE] = true
		}
	}
	best := map[[2]string]SeedClaim{}
	add := func(c SeedClaim) {
		k := [2]string{c.CVE, c.Source}
		if was, ok := best[k]; !ok || c.Date < was.Date {
			best[k] = c
		}
	}
	for _, c := range prev.Claims {
		if claims, read := readNow[c.URL]; read && !claims[c.CVE] {
			continue // the document says it no longer
		}
		add(c)
	}
	for _, r := range reads {
		for _, c := range r.Claims {
			add(c)
		}
	}
	var out Seed
	for _, c := range best {
		out.Claims = append(out.Claims, c)
	}
	slices.SortFunc(out.Claims, func(a, b SeedClaim) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.CVE, b.CVE))
	})
	return out
}

// seedClaim is a claim read now, as the seed holds it.
func seedClaim(source, link string, c vendorClaim) SeedClaim {
	return SeedClaim{CVE: c.CVE, Source: source, Date: c.Date.UTC().Format(time.RFC3339), URL: link}
}

// SeedFromFeed reads a blog feed (Chrome Releases, Rapid7, Google Threat Intelligence) as the box does: one SeedRead per post.
func SeedFromFeed(ctx context.Context, source string, body []byte) ([]SeedRead, error) {
	forms := map[string][]claimForm{chromeFeedID: chromeForms, rapid7FeedID: rapid7Forms, gtiFeedID: gtiForms}[source]
	if forms == nil {
		return nil, fmt.Errorf("feeds: seed: %s is not a blog feed", source)
	}
	posts, err := parsePostFeed(bytes.NewReader(body), "The blog's feed")
	if err != nil {
		return nil, err
	}
	var read vendorRead
	if err := postClaims(ctx, posts, forms, &read); err != nil {
		return nil, err
	}
	return seedReads(source, read.Docs), nil
}

// SeedFromAndroidPage reads one month's Android bulletin page (pageURL, its address) as the box does.
func SeedFromAndroidPage(ctx context.Context, pageURL string, page []byte, month time.Time) (SeedRead, error) {
	published, notes := androidNotes(string(page))
	if published.IsZero() {
		published = month.AddDate(0, 0, 1)
	}
	out := SeedRead{URL: pageURL}
	for _, n := range notes {
		cs, _, err := proseClaims(ctx, androidForms, "", n)
		if err != nil {
			return SeedRead{}, err
		}
		for _, c := range cs {
			out.Claims = append(out.Claims, seedClaim(androidFeedID, pageURL, vendorClaim{CVE: c, Date: published}))
		}
	}
	return out, nil
}

// SeedFromCSAF reads one Cisco or Fortinet CSAF document as the box does (advisories older than the vendor's feed reaches).
func SeedFromCSAF(ctx context.Context, source string, doc []byte) (SeedRead, error) {
	claims, base := ciscoClaims, ciscoAdvisoryURL
	switch source {
	case ciscoFeedID:
	case fortinetFeedID:
		claims, base = fortinetClaims, fortinetAdvisoryURL
	default:
		return SeedRead{}, fmt.Errorf("feeds: seed: %s is not a CSAF feed", source)
	}
	d, err := parseCSAF(bytes.NewReader(doc))
	if err != nil {
		return SeedRead{}, err
	}
	id := strings.TrimSpace(d.ID)
	if source == ciscoFeedID && !ciscoIDRE.MatchString(id) || source == fortinetFeedID && !fortinetIDRE.MatchString(id) {
		return SeedRead{}, fmt.Errorf("feeds: seed: %q is not an advisory id of %s", id, source)
	}
	cs, _, err := claims(ctx, d, nil)
	if err != nil {
		return SeedRead{}, err
	}
	out := SeedRead{URL: base + id}
	for _, c := range cs {
		out.Claims = append(out.Claims, seedClaim(source, out.URL, c))
	}
	return out, nil
}

func seedReads(source string, docs []claimDoc) []SeedRead {
	out := make([]SeedRead, 0, len(docs))
	for _, d := range docs {
		r := SeedRead{URL: d.URL}
		for _, c := range d.Claims {
			r.Claims = append(r.Claims, seedClaim(source, d.URL, c))
		}
		out = append(out, r)
	}
	return out
}

// releaseSeed is the release's seed, read once; a bad file panics (TestSeed_TheReleaseSeedIsValid reads it).
var releaseSeed = sync.OnceValue(func() map[string][]claimDoc {
	s, err := ParseSeed(signaldata.Seed)
	if err != nil {
		panic(fmt.Sprintf("feeds: content/signals/seed.json: %v", err)) // embedded at build time
	}
	return seedDocsOf(s)
})

// seedDocsOf groups a seed's claims into documents per source, by link.
func seedDocsOf(s Seed) map[string][]claimDoc {
	out := map[string][]claimDoc{}
	at := map[[2]string]int{}
	for _, c := range s.Claims {
		day, _ := time.Parse(time.RFC3339, c.Date) // checked by ParseSeed
		k := [2]string{c.Source, c.URL}
		i, ok := at[k]
		if !ok {
			d := claimDoc{URL: c.URL}
			if c.Source == ciscoFeedID || c.Source == fortinetFeedID {
				detail, _ := json.Marshal(map[string]string{"advisory": lastPart(c.URL)})
				d.Detail = string(detail)
			}
			i = len(out[c.Source])
			at[k] = i
			out[c.Source] = append(out[c.Source], d)
		}
		out[c.Source][i].Claims = append(out[c.Source][i].Claims, vendorClaim{CVE: c.CVE, Date: day.UTC()})
	}
	return out
}

// seedDocs is the seed's documents of a feed that are not among the documents read now (those say for themselves what they claim).
func (s *Service) seedDocs(source string, readNow []claimDoc) []claimDoc {
	seed := s.claimSeed
	if seed == nil {
		seed = releaseSeed()
	}
	docs := seed[source]
	read := map[string]bool{}
	for _, d := range readNow {
		read[d.URL] = true
	}
	var out []claimDoc
	for _, d := range docs {
		if !read[d.URL] {
			out = append(out, d)
		}
	}
	return out
}
