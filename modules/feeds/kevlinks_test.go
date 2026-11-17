package feeds

import (
	"database/sql"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The causes of a link in the KEV notes that would keep a character not its own, each with a note from the published
// catalog (2026.11.13: 122 links ended in ",", 6 in ".", 2 in a quote; 14 links written "(https://…)" were dropped,
// and 1 "https:/host" was dropped).
func TestCleanLink(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ cause, in, want string }{
		{"list separated by commas", "https://support.apple.com/en-us/121752,", "https://support.apple.com/en-us/121752"},
		{"end of a sentence", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a.", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"},
		{"stray quote", `https://nvd.nist.gov/vuln/detail/CVE-2026-41940"`, "https://nvd.nist.gov/vuln/detail/CVE-2026-41940"},
		{"quote and comma", `https://nvd.nist.gov/vuln/detail/CVE-2025-5419",`, "https://nvd.nist.gov/vuln/detail/CVE-2025-5419"},
		{"in parentheses", "(https://www.cisa.gov/news-events/directives/ed-21-04-mitigate-windows-print-spooler-service-vulnerability)", "https://www.cisa.gov/news-events/directives/ed-21-04-mitigate-windows-print-spooler-service-vulnerability"},
		{"in parentheses, then a comma", "(https://example.com/a),", "https://example.com/a"},
		{"in angle brackets", "<https://example.com/a>", "https://example.com/a"},
		{"one slash after the scheme", "https:/forums.ivanti.com/s/article/Security-Advisory", "https://forums.ivanti.com/s/article/Security-Advisory"},
		// kept as they are
		{"parentheses of the path itself", "https://www.draytek.com/about/security-advisory/vigorconnect-(cve-2021-20123-cve-2021-20129)", "https://www.draytek.com/about/security-advisory/vigorconnect-(cve-2021-20123-cve-2021-20129)"},
		{"archived page", "https://web.archive.org/web/20150729014733/https://kb.isc.org/article/AA-01272", "https://web.archive.org/web/20150729014733/https://kb.isc.org/article/AA-01272"},
		{"fragment", "https://docs.wpsquared.com/changelogs/versions/changelog/#13617", "https://docs.wpsquared.com/changelogs/versions/changelog/#13617"},
		{"percent-encoded parenthesis of the path", "https://host.example/a%28b)", "https://host.example/a%28b)"},
		{"percent-encoded bracket of the path", "https://host.example/a%5Bb]", "https://host.example/a%5Bb]"},
		{"nothing but punctuation", "(),", ""},
	} {
		if got := cleanLink(c.in); got != c.want {
			t.Errorf("%s: cleanLink(%q) = %q, want %q", c.cause, c.in, got, c.want)
		}
	}
	got := kevLinks(`Reference CISA's ED 21-04 (https://www.cisa.gov/news-events/directives/ed-21-04) for guidance. https://a.example/x, https://a.example/x ; https:/b.example/y.`)
	if want := []string{"https://www.cisa.gov/news-events/directives/ed-21-04", "https://a.example/x", "https://b.example/y"}; !slices.Equal(got, want) {
		t.Errorf("kevLinks = %q, want %q", got, want)
	}
	// links joined by a comma alone (CVE-2023-38606); a comma inside a URL and an archived page's URL stay whole
	got = kevLinks("https://support.apple.com/en-us/HT213843,https://support.apple.com/en-us/HT213844,HTTPS://support.apple.com/en-us/HT213845 ; " +
		"https://web.archive.org/web/20120324170253/http://www.adobe.com/support/apsb09-15.html#:~:text=CVE%2D2009%2D3459).-,NOTE%3A,-There")
	if want := []string{"https://support.apple.com/en-us/HT213843", "https://support.apple.com/en-us/HT213844", "HTTPS://support.apple.com/en-us/HT213845",
		"https://web.archive.org/web/20120324170253/http://www.adobe.com/support/apsb09-15.html#:~:text=CVE%2D2009%2D3459).-,NOTE%3A,-There"}; !slices.Equal(got, want) {
		t.Errorf("kevLinks of comma-joined links = %q, want %q", got, want)
	}
}

// secondScheme is a scheme inside a link that is not an archived page's own URL (which follows a "/").
var secondScheme = regexp.MustCompile(`(?i)[^/]https?://`)

// junk says why a stored link is not clean, or "" when it is.
func junk(l string) string {
	switch {
	case l == "":
		return "empty"
	case strings.ContainsAny(l[:1], `(<["'`):
		return "opening " + l[:1]
	case strings.ContainsAny(l[len(l)-1:], `.,;:!?"'>`):
		return "trailing " + l[len(l)-1:]
	case strings.HasSuffix(l, ")") && strings.Count(l, "(") < strings.Count(l, ")"):
		return "unmatched )"
	case !strings.HasPrefix(strings.ToLower(l), "https://"):
		return "not https://"
	case secondScheme.MatchString(l[1:]):
		return "two links in one"
	}
	return ""
}

// Every link of every entry comes out clean. The test list is small; KEV_FILE=<known_exploited_vulnerabilities.json>
// runs the same check over the whole published catalog and logs what the old split kept, by cause.
func TestKevLinks_EveryLinkOfTheCatalogIsClean(t *testing.T) {
	t.Parallel()
	file := os.Getenv("KEV_FILE")
	if file == "" {
		file = "testdata/kev.json"
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the test reads the catalog file the developer names
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE   string `json:"cveID"`
			Notes string `json:"notes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	before, links := map[string]int{}, 0
	for _, v := range doc.Vulnerabilities {
		for _, part := range strings.FieldsFunc(v.Notes, func(r rune) bool { return r == ';' || jsIsSpace(r) }) {
			if why := junk(part); why != "" && strings.Contains(part, "https:/") {
				before[why]++
			}
		}
		for _, l := range kevLinks(v.Notes) {
			links++
			if why := junk(l); why != "" {
				t.Errorf("%s: link %q is not clean (%s)", v.CVE, l, why)
			}
		}
	}
	if links == 0 {
		t.Fatal("no link read")
	}
	t.Logf("%d entries, %d links; parts with an https link that the split alone left unclean, by cause: %v", len(doc.Vulnerabilities), links, before)
}

// A row stored before the rule reads clean, and a pull of the same unchanged list does not count it as updated.
func TestStoredLinksReadClean(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	dirty := vuln("CVE-2026-0001", "Apple", "Multiple Products", "2026-11-03")
	dirty.Links = []string{"https://support.apple.com/en-us/121752,", "https://support.apple.com/en-us/121752", "(https://www.cisa.gov/x)",
		"https://support.apple.com/en-us/HT213843,https://support.apple.com/en-us/HT213844"}
	enc, _ := json.Marshal(dirty.Links)
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, description, required_action, links,
date_added, due_date, ransomware, has_template, source_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'cisa-kev', '2026-11-09T08:00:00.000Z')`,
			dirty.CVE, dirty.Vendor, dirty.Product, dirty.Key(), dirty.Name, dirty.Description, dirty.RequiredAction, string(enc), dirty.DateAdded, dirty.DueDate)
		return err
	})
	row, ok, err := s.VulnByCVE(t.Context(), "CVE-2026-0001")
	if err != nil || !ok {
		t.Fatalf("VulnByCVE: %v %v", ok, err)
	}
	if want := []string{"https://support.apple.com/en-us/121752", "https://www.cisa.gov/x", "https://support.apple.com/en-us/HT213843",
		"https://support.apple.com/en-us/HT213844"}; !slices.Equal(row.Links, want) {
		t.Fatalf("stored links read as %q, want %q", row.Links, want)
	}
	if fresh, upd := applyV(t, db, epoch0, "cisa-kev", []Vuln{dirty}, false); len(fresh) != 0 || len(upd) != 0 {
		t.Fatalf("the same list again: %d new, %v updated; want neither", len(fresh), upd)
	}
}
