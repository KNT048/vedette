package feeds

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

func FuzzParsePostFeed(f *testing.F) {
	f.Add([]byte(rapid7Feed([4]string{"CVE-2026-1001 exploited in the wild (CVE-2026-1001)", "https://example.com/a", "Thu, 19 Nov 2026 21:06:24 GMT", "<p>Rapid7 confirmed exploitation of CVE-2026-1001.</p>"})))
	f.Add([]byte(`<feed xmlns='http://www.w3.org/2005/Atom'><entry><published>2026-11-09T12:52:57.820-08:00</published><content type='html'>&lt;p&gt;Google is aware that an exploit for CVE-2026-1 exists in the wild.&lt;/p&gt;</content><link rel='alternate' href='https://example.com/p'/></entry></feed>`))
	f.Add([]byte(`<rss><channel><item><link>javascript:x</link><pubDate>x</pubDate><description>&lt;script&gt;</description></item></channel></rss>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		posts, err := parsePostFeed(bytes.NewReader(data), "x")
		if err != nil {
			return
		}
		if len(posts) > textMaxPosts {
			t.Fatalf("%d posts", len(posts))
		}
		var read vendorRead
		if err := postClaims(t.Context(), posts, proseForms, &read); err != nil {
			t.Fatal(err)
		}
		for _, d := range read.Docs {
			if !strings.HasPrefix(d.URL, "https://") || len(d.URL) > 500 {
				t.Fatalf("link %q", d.URL)
			}
			for _, c := range d.Claims {
				if !cveRE.MatchString(c.CVE) || c.Date.IsZero() {
					t.Fatalf("claim %+v", c)
				}
			}
		}
	})
}

func FuzzAndroidNotes(f *testing.F) {
	f.Add(androidPage("December 1, 2025", "There are indications that the following may be under limited, targeted exploitation.<ul><li>CVE-2025-48633</li><li>CVE-2025-48572</li></ul>"))
	f.Add(`<aside class="note">There are indications that CVE-2026-1 may be under limited, targeted exploitation.`)
	f.Add(strings.Repeat(`<aside class="note">CVE-2026-1001<li>CVE-2026-1002</li></aside>`, 100))
	f.Fuzz(func(t *testing.T, page string) {
		_, notes := androidNotes(page)
		if len(notes) > androidMaxNotes {
			t.Fatalf("%d notes", len(notes))
		}
		r, err := SeedFromAndroidPage(t.Context(), "https://source.android.com/docs/security/bulletin/2026/2026-01-01", []byte(page), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Claims {
			if c.check() != "" || !strings.Contains(strings.ToUpper(page), c.CVE) {
				t.Fatalf("claim %+v", c)
			}
		}
	})
}

// FuzzProseForms: a prose source claims only CVE ids the text names, and only ones its own sentence names.
func FuzzProseForms(f *testing.F) {
	f.Add("Rapid7 confirmed exploitation of CVE-2026-1001, but not of CVE-2026-1002.")
	f.Add("CVE-2026-1001 is being exploited in the wild. CVE-2026-1002 could be exploited.")
	f.Add("The threat actor (formerly tracked as UNC1) exploited a flaw (CVE-2026-1003) between May 27 and June 9.")
	f.Add(strings.Repeat("Google is aware that an exploit for CVE-2026-1004 exists in the wild. ", 300))
	f.Add("CVE-2026-1111, a patch bypass for CVE-2025-2222, is being actively exploited in the wild.")
	f.Add("Rapid7 MDR has observed exploitation of CVE-2026-1111, and CVE-2026-2222 is a related information disclosure.")
	f.Fuzz(func(t *testing.T, text string) {
		for _, forms := range [][]claimForm{proseForms, chromeForms, androidForms} {
			got, _, err := proseClaims(t.Context(), forms, "", text)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range got {
				if !strings.Contains(strings.ToUpper(text), c) {
					t.Fatalf("%q claims %s, which it does not name", text, c)
				}
			}
		}
		// a sentence that claims names no other CVE than those it claims: the subject is never a guess
		for _, sentence := range claimSentences(text) {
			got, _, err := proseClaims(t.Context(), proseForms, "", sentence)
			if err != nil || len(got) == 0 {
				continue
			}
			for _, id := range claimCVERE.FindAllString(sentence, -1) {
				if !slices.Contains(got, strings.ToUpper(id)) {
					t.Fatalf("%q claims %v but also names %s", sentence, got, id)
				}
			}
		}
		if _, err := appleClaimed(t.Context(), "CVE-2026-1001", text); err != nil {
			t.Fatal(err)
		}
	})
}
