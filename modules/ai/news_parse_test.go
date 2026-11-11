package ai

import (
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// clean reports whether s is what may go into a data block: valid UTF-8, no control or format character except a line break.
func clean(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return false
		}
	}
	return true
}

func TestSanitizeWeb(t *testing.T) {
	in := "a\u202eb\u200bc\x00d\te  f\r\n\n\n\ng\xff"
	got := sanitizeWeb(in)
	if got != "abcd e f\n\ng�" || !clean(got) {
		t.Fatalf("sanitizeWeb = %q", got)
	}
}

func TestCVEIndexes(t *testing.T) {
	for s, n := range map[string]int{
		"CVE-2024-3400": 1, "cve-2024-3400.": 1, "CVE-2024-34001": 0, "XCVE-2024-3400": 0, "(CVE-2024-3400) and CVE-2024-3400": 2, "": 0,
	} {
		if got := len(cveIndexes(s, "CVE-2024-3400")); got != n {
			t.Errorf("%q: %d, want %d", s, got, n)
		}
	}
}

func TestExcerptKeepsTheMentions(t *testing.T) {
	text := strings.Repeat("start ", 400) + strings.Repeat("filler ", 4000) + "the fix for CVE-2024-3400 is 11.1.2" + strings.Repeat(" tail", 4000)
	got := excerpt(text, "CVE-2024-3400", 6000)
	if len(got) > 6000 || !strings.HasPrefix(got, "start") || !strings.Contains(got, "the fix for CVE-2024-3400 is 11.1.2") || !utf8.ValidString(got) {
		t.Fatalf("excerpt = %d bytes: %q", len(got), got[:min(200, len(got))])
	}
}

func TestHTMLToText(t *testing.T) {
	got := htmlToText(`<html><head><script>evil()</script><style>x{}</style><title>T</title></head><body><nav>menu</nav><p>Fix&nbsp;it &amp; go</p><svg><text>no</text></svg><footer>c</footer><div>x<br>y</div></body></html>`, 1<<20)
	if got != "T\nFix it & go\n\nx\ny" {
		t.Fatalf("htmlToText = %q", got)
	}
	// An unclosed script swallows the rest: less text, never the script.
	if got := htmlToText(`<p>a</p><script>evil()`, 100); got != "a" {
		t.Fatalf("unclosed script = %q", got)
	}
}

func TestParseFeedFormsAndLimits(t *testing.T) {
	latin := []byte("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><rss><channel><item><title>caf\xe9 CVE-2024-3400</title><link>https://x.example/a</link></item></channel></rss>")
	items, err := parseFeed(latin)
	if err != nil || len(items) != 1 || items[0].Title != "café CVE-2024-3400" || items[0].Link != "https://x.example/a" {
		t.Fatalf("latin-1 feed = %v, %v", items, err)
	}
	if _, err := parseFeed([]byte(`<?xml version="1.0" encoding="shift_jis"?><rss></rss>`)); err == nil {
		t.Fatal("an unknown encoding was read")
	}
	if _, err := parseFeed([]byte(`<html><body>not a feed</body></html>`)); err == nil {
		t.Fatal("an HTML page was read as a feed")
	}
	// Entities defined in a DTD are not expanded: the document cannot grow itself.
	laughs := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><rss><channel><item><title>&lol3;</title></item></channel></rss>`
	start := time.Now()
	items, _ = parseFeed([]byte(laughs))
	if time.Since(start) > time.Second || (len(items) == 1 && len(items[0].Title) > 100) {
		t.Fatalf("entities were expanded: %v", items)
	}
	deep := "<rss>" + strings.Repeat("<a>", 10000) + strings.Repeat("</a>", 10000) + "</rss>"
	if _, err := parseFeed([]byte(deep)); err == nil {
		t.Fatal("a feed nested 10000 deep was read")
	}
	var many strings.Builder
	many.WriteString("<rss><channel>")
	for range 500 {
		many.WriteString("<item><title>t</title></item>")
	}
	many.WriteString("</channel></rss>")
	if items, err := parseFeed([]byte(many.String())); err != nil || len(items) != maxFeedItems {
		t.Fatalf("500 items: %d, %v", len(items), err)
	}
}

func TestNewsPublicAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"93.184.216.34": true, "2606:4700::1111": true, "::ffff:93.184.216.34": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false, "::1": false, "169.254.169.254": false,
		"fe80::1": false, "fd00:ec2::254": false, "fc00::1": false, "100.64.0.1": false, "100.100.100.200": false, "0.0.0.0": false,
		"224.0.0.1": false, "255.255.255.255": false, "192.0.2.1": false, "198.18.0.1": false, "240.0.0.1": false, "2001:db8::1": false,
		"64:ff9b::5db8:d822": false, "2002:5db8:d822::": false, "2001::1": false, "::5db8:d822": false,
	} {
		if got := newsPublicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %v, want %v", s, got, want)
		}
	}
}

func TestNewsHostAllowed(t *testing.T) {
	for h, want := range map[string]bool{"services.nvd.nist.gov": true, "API.GITHUB.COM": true, "labs.watchtowr.com": true, "fortiguard.fortinet.com": true,
		"github.com": false, "nvd.nist.gov": false, "evil.fortiguard.fortinet.com": false, "msrc.microsoft.com": false, "": false} {
		if got := newsHostAllowed(h); got != want {
			t.Errorf("%q: %v, want %v", h, got, want)
		}
	}
}

func FuzzParseFeed(f *testing.F) {
	f.Add([]byte(`<rss><channel><item><title>CVE-2024-3400</title><link>https://a.example/x</link><description><![CDATA[<p>x</p>]]></description></item></channel></rss>`))
	f.Add([]byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>t</title><link href="https://a.example"/><content type="xhtml"><div><p>CVE-2024-3400</p></div></content></entry></feed>`))
	f.Add([]byte("<?xml version=\"1.0\" encoding=\"latin1\"?><rss><item><title>\xff\x00</title></item></rss>"))
	f.Fuzz(func(t *testing.T, b []byte) {
		items, _ := parseFeed(b)
		if len(items) > maxFeedItems {
			t.Fatalf("%d items", len(items))
		}
		text, hits := feedMentions(items, "CVE-2024-3400", "a.example")
		if len(hits) > maxFeedMatch || len(text) > maxSourceText || !clean(text) {
			t.Fatalf("mentions: %d hits, %d bytes, clean %v", len(hits), len(text), clean(text))
		}
		for _, it := range items {
			if len(it.Text) > maxItemText || !clean(it.Title) {
				t.Fatalf("item %q", it.Title)
			}
		}
	})
}

func FuzzParseNVD(f *testing.F) {
	f.Add([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-3400","descriptions":[{"lang":"en","value":"x\u202e"}],"references":[{"url":"https://a.example","tags":["Patch"]}]}}]}`))
	f.Add([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := parseNVD(b, "CVE-2024-3400")
		if err != nil {
			return
		}
		if len(info.text) > maxSourceText || !clean(info.text) {
			t.Fatalf("text %d bytes, clean %v", len(info.text), clean(info.text))
		}
		for _, v := range info.vendors {
			if safeLink(v, "") != v {
				t.Fatalf("vendor link %q", v)
			}
		}
	})
}

func FuzzParseGitHubSearch(f *testing.F) {
	f.Add([]byte(`{"total_count":1,"items":[{"full_name":"a/CVE-2024-3400","description":"poc\u0000","stargazers_count":1}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := parseGitHubSearch(b, "CVE-2024-3400")
		if err != nil {
			return
		}
		if len(info.text) > maxSourceText || !clean(info.text) {
			t.Fatalf("text %d bytes, clean %v", len(info.text), clean(info.text))
		}
	})
}

func FuzzHTMLToText(f *testing.F) {
	f.Add(`<p>CVE-2024-3400</p><script>x</script>`, 1000)
	f.Add("<a href='x'>\u202e&#0;&#x202e;</a><br/>", 10)
	f.Fuzz(func(t *testing.T, s string, limit int) {
		if limit < 0 || limit > 1<<20 {
			return
		}
		got := htmlToText(s, limit)
		if len(got) > limit || !clean(got) {
			t.Fatalf("htmlToText: %d bytes (limit %d), clean %v", len(got), limit, clean(got))
		}
		if e := excerpt(got, "CVE-2024-3400", 200); len(e) > 200 || !utf8.ValidString(e) {
			t.Fatalf("excerpt %d bytes", len(e))
		}
	})
}
