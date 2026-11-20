package feeds

import (
	"bufio"
	"bytes"
	"maps"
	"path/filepath"
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
func csafFixtureClaims(t *testing.T, name string, claims func(csafDoc) []vendorClaim) (map[string]time.Time, []csafDoc) {
	t.Helper()
	out := map[string]time.Time{}
	var docs []csafDoc
	sc := bufio.NewScanner(bytes.NewReader(vendorFixture(t, name)))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		d, err := parseCSAF(bytes.NewReader(sc.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		docs = append(docs, d)
		for _, c := range claims(d) {
			if was, ok := out[c.CVE]; !ok || c.Date.Before(was) {
				out[c.CVE] = c.Date
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out, docs
}

// windowRuleClaims is the first measurement's rule, kept here as the "before" of the count: a CVE within 300 characters of an
// exploitation phrase (cut at the nearest ". "), with only the 90 characters before the phrase checked for a negation, and, when
// that window names no CVE, every CVE of a document that has at most two. It read every text of the document.
func windowRuleClaims(d csafDoc) []string {
	cves := d.cves()
	var texts []string
	for _, n := range d.Document.Notes {
		texts = append(texts, n.Text)
	}
	for _, v := range d.Vulnerabilities {
		for _, n := range v.Notes {
			texts = append(texts, n.Text)
		}
		for _, r := range v.References {
			texts = append(texts, r.Summary)
		}
	}
	var out []string
	for _, text := range texts {
		for _, m := range exploitPhraseRE.FindAllStringIndex(text, -1) {
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
			if claimNegationRE.MatchString(pre) {
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
		claims   func(csafDoc) []vendorClaim
	}{{ciscoFeedID, "cisco-csaf.jsonl.gz", ciscoClaims}, {fortinetFeedID, "fortinet-csaf.jsonl.gz", fortinetClaims}} {
		claims, docs := csafFixtureClaims(t, src.file, src.claims)
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
