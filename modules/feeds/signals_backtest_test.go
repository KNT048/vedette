package feeds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The frozen vendor fixtures of testdata/vendorclaims were read on 21 November 2026 and cut to what the decoders read: Microsoft's
// list of CVEs flagged exploited (id, release date, the revisions that changed the flag); Cisco's CSAF documents of the advisories
// published since June 2025 or changed since 20 November 2025 (338 of them: tracking dates, the revision summaries that speak of
// exploitation, the "Exploitation and Public Announcements" section and the CVE ids); Fortinet's CSAF documents of the 50 advisories
// of its feed that day and of the 13 advisories behind the Fortinet CVEs CISA listed since June 2025 (tracking dates and, per
// vulnerability, only the sentences that speak of exploitation). No other advisory text.

func vendorFixture(t *testing.T, name string) []byte {
	t.Helper()
	return gunzipBytes(t, fixtureBytesIn(t, filepath.Join("testdata", "vendorclaims"), name))
}

// csafFixtureClaims reads every document of a JSON-lines fixture through parseCSAF and the vendor's claim rule: the earliest date per
// CVE, as applyVendorClaims stores them on a first pull.
func csafFixtureClaims(t *testing.T, name string, claims func(context.Context, csafDoc, *claimWork) ([]vendorClaim, int, error)) (map[string]time.Time, []csafDoc, vendorOrigin) {
	t.Helper()
	out := map[string]time.Time{}
	var (
		docs   []csafDoc
		origin vendorOrigin
	)
	sc := bufio.NewScanner(bytes.NewReader(vendorFixture(t, name)))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		d, err := parseCSAF(bytes.NewReader(sc.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		docs = append(docs, d)
		cs, unclassified, err := claims(t.Context(), d, nil)
		if err != nil {
			t.Fatal(err)
		}
		origin.unclassified += unclassified
		for _, c := range cs {
			if c.Flag {
				origin.flag++
			} else {
				origin.form++
			}
			if was, ok := out[c.CVE]; !ok || c.Date.Before(was) {
				out[c.CVE] = c.Date
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out, docs, origin
}

// vendorOrigin is where a source's claims come from: structured fields or sentence forms, and the sentences about exploitation in
// no known form.
type vendorOrigin struct{ flag, form, unclassified int }

// The first measurement's phrase and negation lists, kept for the "before" of the count.
var (
	backtestPhraseRE = regexp.MustCompile(`(?i)(exploited in the wild|in[- ]the[- ]wild exploitation|exploits? for [^.]{0,80}? exists? in the wild|` +
		`actively exploited|active exploitation|under (?:limited,? )?(?:and )?(?:targeted )?exploitation|ha(?:s|ve) been exploited|` +
		`may have been exploited|being exploited|been observed exploit|aware of [^.]{0,100}?(?:exploitation|exploited|attacks? (?:that )?leverag)|` +
		`observed [^.]{0,60}?exploit(?:ation|ed)|attempted exploitation|exploitation (?:attempts? )?(?:has|have) been (?:observed|detected|reported)|` +
		`zero-day exploit|exploited as a zero-day|exploited (?:by|in attacks))`)
	backtestNegationRE = regexp.MustCompile(`(?i)(to stop|can only be|\bif\b|\bwhether\b|not aware|no (?:known|evidence|indication|reports?)|not been|` +
		`unaware|is not|are not|not currently|not observed|nor |without evidence|no public)`)
)

// windowRuleClaims is the first measurement's rule, kept here as the "before" of the count: a CVE within 300 characters of an
// exploitation phrase (cut at the nearest ". "), with only the 90 characters before the phrase checked for a negation, and, when
// that window names no CVE, every CVE of a document that has at most two. It read every text of the document.
func windowRuleClaims(d csafDoc) []string {
	cves := d.cves()
	var texts []string
	for _, n := range d.Notes {
		texts = append(texts, n.Text)
	}
	for _, v := range d.Vulnerabilities {
		for _, n := range v.Notes {
			texts = append(texts, n.Text)
		}
		texts = append(texts, v.References...)
	}
	var out []string
	for _, text := range texts {
		for _, m := range backtestPhraseRE.FindAllStringIndex(text, -1) {
			a := max(strings.LastIndex(text[:m[0]], ". "), m[0]-300, 0)
			b := strings.Index(text[m[1]:], ". ")
			if b < 0 {
				b = len(text)
			} else {
				b += m[1]
			}
			b = min(b, m[1]+300)
			pre := text[max(0, m[0]-90):m[0]]
			if i := strings.LastIndexByte(pre, '.'); i >= 0 {
				pre = pre[i+1:]
			}
			if backtestNegationRE.MatchString(pre) {
				continue
			}
			named := claimCVERE.FindAllString(text[a:b], -1)
			if len(named) == 0 && len(cves) <= 2 {
				named = cves
			}
			for _, c := range named {
				if c = strings.ToUpper(c); !slices.Contains(out, c) {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// vendorCount is what the count test reports per source.
type vendorCount struct {
	pairs, inWindow int // (CVE, date) claims; those dated in the window of the measurement (20 Nov 2025 – 19 Nov 2026)
	before          int // CVEs the window rule flags on the same documents (Cisco, Fortinet)
}

func countIn(claims map[string]time.Time) vendorCount {
	w0, w1 := time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	c := vendorCount{pairs: len(claims)}
	for _, d := range claims {
		if !d.Before(w0) && d.Before(w1) {
			c.inWindow++
		}
	}
	return c
}

// Count test: per vendor source, the (CVE, date) claims extracted from the frozen fixtures, and none of the known false matches of
// the measurement: Cisco's SD-WAN advisory says in its first sentence that CVE-2026-20126 and CVE-2026-20129 are not exploited and
// in the next that three others are; the window rule flagged all five. Checked outside the repository against the CISA list of
// 21 Nov 2026: every one of the 24 Cisco and 7 Fortinet claims is on it, and the 22 Microsoft claims in the window are the 22 the
// measurement found; the window rule's 26 Cisco CVEs are the same 24 and the two false matches.
func TestVendorClaims_CountsOfTheFrozenFixtures(t *testing.T) {
	t.Parallel()
	got := map[string]vendorCount{}

	pg, err := parseMSRCExploited(bytes.NewReader(vendorFixture(t, "msrc.json.gz")))
	if err != nil {
		t.Fatal(err)
	}
	ms := map[string]time.Time{}
	for _, c := range pg.Claims {
		ms[c.CVE] = c.Date
	}
	got[msrcFeedID] = countIn(ms)
	if pg.Rejected != 0 {
		t.Errorf("msrc: %d rows rejected: %+v", pg.Rejected, pg.Reasons)
	}

	before := map[string]map[string]bool{}
	for _, src := range []struct {
		id, file string
		claims   func(context.Context, csafDoc, *claimWork) ([]vendorClaim, int, error)
	}{{ciscoFeedID, "cisco-csaf.jsonl.gz", ciscoClaims}, {fortinetFeedID, "fortinet-csaf.jsonl.gz", fortinetClaims}} {
		claims, docs, origin := csafFixtureClaims(t, src.file, src.claims)
		t.Logf("%s: %d claims from structured fields, %d from the vendor's sentence forms, %d sentences in no known form", src.id, origin.flag, origin.form, origin.unclassified)
		if want := map[string]vendorOrigin{ciscoFeedID: {0, 24, 1}, fortinetFeedID: {0, 7, 0}}[src.id]; origin != want {
			t.Errorf("%s: origin %+v, want %+v", src.id, origin, want)
		}
		c := countIn(claims)
		before[src.id] = map[string]bool{}
		for _, d := range docs {
			for _, cve := range windowRuleClaims(d) {
				before[src.id][cve] = true
			}
		}
		c.before = len(before[src.id])
		got[src.id] = c
		if src.id == ciscoFeedID {
			for _, fp := range []string{"CVE-2026-20126", "CVE-2026-20129"} {
				if _, ok := claims[fp]; ok {
					t.Errorf("%s is flagged; the advisory says it is not exploited", fp)
				}
				if !before[src.id][fp] {
					t.Errorf("%s: the fixture no longer reproduces the window rule's false match", fp)
				}
			}
			for cve, day := range map[string]string{"CVE-2026-20122": "2026-03-05", "CVE-2026-20128": "2026-03-05", "CVE-2026-20133": "2026-04-22",
				"CVE-2025-20281": "2025-07-21", "CVE-2025-20337": "2025-07-21", "CVE-2025-20333": "2025-09-25"} {
				if d := claims[cve]; d.Format(time.DateOnly) != day {
					t.Errorf("%s: %v, want %s", cve, d, day)
				}
			}
		}
		for _, cve := range slices.Sorted(maps.Keys(claims)) {
			t.Logf("%s %s %s", src.id, cve, claims[cve].Format(time.DateOnly))
		}
	}
	want := map[string]vendorCount{
		msrcFeedID:     {191, 22, 0},
		ciscoFeedID:    {24, 19, 26},
		fortinetFeedID: {7, 4, 7},
	}
	for id, c := range got {
		t.Logf("%s: %d claims, %d dated in the window; the window rule flags %d", id, c.pairs, c.inWindow, c.before)
		if c != want[id] {
			t.Errorf("%s: %+v, want %+v", id, c, want[id])
		}
	}
}

// The frozen prose fixtures of testdata/textclaims were read on 21 November 2026 and cut to what the decoders read: Rapid7's and
// Google Threat Intelligence's feeds that day (20 posts each: title, link, date and only the sentences that name a CVE and speak of
// exploitation); Chrome Releases' posts since June 2025 that name a CVE (the sentences that speak of exploitation, and each line that
// names CVE ids reduced to the ids); Android's bulletins of June 2025 to November 2026 (the publication date and the notes); Apple's
// CVE records published since June 2025 as NVD holds them (id, publication, the sentences of the description that speak of
// exploitation, the links of Apple's release pages). No other text.

func textFixture(t *testing.T, name string) []byte {
	t.Helper()
	return gunzipBytes(t, fixtureBytesIn(t, filepath.Join("testdata", "textclaims"), name))
}

// windowRuleProse is the first measurement's rule on prose (the "before" of the count): a CVE within before/after characters of an
// exploitation phrase, cut at the nearest ". " when sentence is set, with only the 90 characters before the phrase checked for a
// negation.
func windowRuleProse(text string, before, after int, sentence bool) []string {
	text = regexp.MustCompile(`[ \t\r\f\v]+`).ReplaceAllString(text, " ")
	var out []string
	for _, m := range backtestPhraseRE.FindAllStringIndex(text, -1) {
		a, b := max(0, m[0]-before), min(len(text), m[1]+after)
		if sentence {
			if i := strings.LastIndex(text[:m[0]], ". "); i > a {
				a = i
			}
			if i := strings.Index(text[m[1]:], ". "); i >= 0 && m[1]+i < b {
				b = m[1] + i
			}
		}
		pre := text[max(0, m[0]-90):m[0]]
		if i := strings.LastIndexByte(pre, '.'); i >= 0 {
			pre = pre[i+1:]
		}
		if backtestNegationRE.MatchString(pre) {
			continue
		}
		for _, c := range claimCVERE.FindAllString(text[a:b], -1) {
			if c = strings.ToUpper(c); !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// Count test of the prose sources: per source, the (CVE, date) claims extracted from the frozen fixtures, those dated in the window of
// the measurement, the CVEs the measurement's window rule flags on the same text, and the sentences in no known form. CVE-2026-123890
// is flagged from Rapid7's post of 19 November 2026. Apple's claims are read from each CVE's own record, so a claim cannot reach the
// CVE of the next entry of a release page (the measurement's two Apple false matches were such neighbours): no CVE that shares a
// release page with a claimed one is flagged unless its own record says it.
func TestTextClaims_CountsOfTheFrozenFixtures(t *testing.T) {
	t.Parallel()
	type count struct {
		vendorCount
		unclassified int
	}
	got := map[string]count{}
	claimsOf := map[string]map[string]time.Time{}
	keep := func(id string, cve string, d time.Time) {
		if claimsOf[id] == nil {
			claimsOf[id] = map[string]time.Time{}
		}
		if was, ok := claimsOf[id][cve]; !ok || d.Before(was) {
			claimsOf[id][cve] = d
		}
	}

	for _, src := range []struct {
		id, file      string
		before, after int
	}{{rapid7FeedID, "rapid7.xml.gz", 250, 450}, {gtiFeedID, "gti.xml.gz", 250, 450}, {chromeFeedID, "chrome.xml.gz", 200, 50}} {
		posts, err := parsePostFeed(bytes.NewReader(textFixture(t, src.file)), src.id)
		if err != nil {
			t.Fatal(err)
		}
		var read vendorRead
		forms := map[string][]claimForm{rapid7FeedID: rapid7Forms, gtiFeedID: gtiForms, chromeFeedID: chromeForms}[src.id]
		if err := postClaims(t.Context(), posts, forms, &read); err != nil {
			t.Fatal(err)
		}
		if read.Rejected != 0 {
			t.Errorf("%s: %d posts rejected: %+v", src.id, read.Rejected, read.Reasons)
		}
		before := map[string]bool{}
		for _, p := range posts {
			for _, c := range windowRuleProse(proseText(p.Title+"\n"+p.Body), src.before, src.after, true) {
				before[c] = true
			}
		}
		for _, d := range read.Docs {
			for _, c := range d.Claims {
				keep(src.id, c.CVE, c.Date)
			}
		}
		c := count{vendorCount: countIn(claimsOf[src.id]), unclassified: read.Unclassified}
		c.before = len(before)
		got[src.id] = c
	}

	sc := bufio.NewScanner(bytes.NewReader(textFixture(t, "android.jsonl.gz")))
	sc.Buffer(nil, 1<<20)
	before := map[string]bool{}
	var android count
	for sc.Scan() {
		var b struct{ Month, URL, Page string }
		if err := json.Unmarshal(sc.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		month, err := time.Parse("2006-01", b.Month)
		if err != nil {
			t.Fatal(err)
		}
		r, err := SeedFromAndroidPage(t.Context(), b.URL, []byte(b.Page), month)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Claims {
			d, _ := time.Parse(time.RFC3339, c.Date)
			keep(androidFeedID, c.CVE, d)
		}
		for _, c := range windowRuleProse(proseText(b.Page), 300, 300, true) {
			before[c] = true
		}
	}
	android.vendorCount = countIn(claimsOf[androidFeedID])
	android.before = len(before)
	got[androidFeedID] = android

	// Apple: each record's own description
	sc = bufio.NewScanner(bytes.NewReader(textFixture(t, "apple.jsonl.gz")))
	sc.Buffer(nil, 1<<20)
	pages := map[string][]string{} // Apple's release page → its CVEs
	stated := map[string]bool{}    // the records whose own description states it
	var apple count
	for sc.Scan() {
		var r struct {
			CVE, Published, Description string
			Advisories                  []string
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		for _, a := range r.Advisories {
			pages[a] = append(pages[a], r.CVE)
		}
		stated[r.CVE] = strings.Contains(r.Description, "may have been exploited")
		ok, err := appleClaimed(t.Context(), r.CVE, r.Description)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			d, err := time.Parse(time.RFC3339, r.Published)
			if err != nil {
				t.Fatal(err)
			}
			keep(appleClaimSource, r.CVE, d)
		}
	}
	apple.vendorCount = countIn(claimsOf[appleClaimSource])
	got[appleClaimSource] = apple
	neighbours := map[string]bool{}
	for _, cves := range pages {
		claimedHere := false
		for _, c := range cves {
			_, ok := claimsOf[appleClaimSource][c]
			claimedHere = claimedHere || ok
		}
		for _, c := range cves {
			if _, ok := claimsOf[appleClaimSource][c]; claimedHere && !ok {
				neighbours[c] = true
			}
		}
	}

	if d := claimsOf[rapid7FeedID]["CVE-2026-123890"]; d.Format(time.DateOnly) != "2026-11-19" {
		t.Errorf("CVE-2026-123890 from Rapid7: %v, want 19 Nov 2026", d)
	}
	for cve, says := range stated {
		if _, claimed := claimsOf[appleClaimSource][cve]; claimed != says {
			t.Errorf("apple %s: claimed %v, its own record says it %v", cve, claimed, says)
		}
	}
	if len(neighbours) != 135 {
		t.Errorf("apple: %d CVEs share a release page with a claimed CVE, want 135 (none of them is flagged)", len(neighbours))
	}
	for id, cs := range claimsOf {
		for _, cve := range slices.Sorted(maps.Keys(cs)) {
			t.Logf("%s %s %s", id, cve, cs[cve].Format(time.DateOnly))
		}
	}
	want := map[string]count{
		rapid7FeedID:     {vendorCount{5, 5, 7}, 6},
		gtiFeedID:        {vendorCount{5, 5, 3}, 10},
		chromeFeedID:     {vendorCount{10, 9, 25}, 0},
		androidFeedID:    {vendorCount{6, 4, 2}, 0},
		appleClaimSource: {vendorCount{5, 3, 0}, 0}, // the window rule read Apple's release pages, which the box does not read
	}
	for id, c := range got {
		t.Logf("%s: %d claims, %d dated in the window; the window rule flags %d; %d sentences in no known form", id, c.pairs, c.inWindow, c.before, c.unclassified)
		if c != want[id] {
			t.Errorf("%s: %+v, want %+v", id, c, want[id])
		}
	}
}
