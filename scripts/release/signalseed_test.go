package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
)

func TestSignalSeed_PreviousSeedPlusTheFeedsReadNow(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux) // the seed keeps https links only
	t.Cleanup(srv.Close)
	var chromeStarts []string
	mux.HandleFunc("/chrome", func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("start-index")
		chromeStarts = append(chromeStarts, start)
		if start != "1" { // the second page is empty: the end of the feed
			_, _ = w.Write([]byte(`<feed xmlns='http://www.w3.org/2005/Atom'></feed>`))
			return
		}
		_, _ = w.Write([]byte(`<feed xmlns='http://www.w3.org/2005/Atom'><entry><published>2026-11-09T12:52:57.820-08:00</published>` +
			`<content type='html'>&lt;p&gt;Google is aware that an exploit for CVE-2026-125350 exists in the wild.&lt;/p&gt;&lt;p&gt;High CVE-2026-125351: Use after free in V8.&lt;/p&gt;</content>` +
			`<link rel='alternate' href='https://chromereleases.googleblog.com/2026/11/a.html'/></entry>` +
			`<entry><published>2026-11-02T10:00:00-08:00</published><content type='html'>&lt;p&gt;No claim here.&lt;/p&gt;</content><link rel='alternate' href='https://chromereleases.googleblog.com/2026/11/b.html'/></entry></feed>`))
	})
	rss := func(link, date, body string) string {
		return `<rss version="2.0"><channel><title>t</title><item><title>t</title><link>` + link + `</link><pubDate>` + date + `</pubDate><description><![CDATA[` + body + `]]></description></item></channel></rss>`
	}
	mux.HandleFunc("/rapid7", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(rss("https://www.rapid7.com/blog/post/etr-cve-2026-123890", "Thu, 19 Nov 2026 21:06:24 GMT",
			`<p>Also, Mandiant/Google Threat Intelligence confirmed in-the-wild exploitation of CVE-2026-123890 by a state-linked threat actor.</p>`)))
	})
	mux.HandleFunc("/gti", func(w http.ResponseWriter, _ *http.Request) {
		// the post the previous seed holds a claim of no longer makes it
		_, _ = w.Write([]byte(rss("https://cloud.google.com/blog/topics/threat-intelligence/old/", "Tue, 29 Sep 2026 14:00:00 +0000", `<p>Exploitation of CVE-2026-88772 was not observed.</p>`)))
	})
	mux.HandleFunc("/bulletin/2025-12-01", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<p>Published December 1, 2025</p><aside class="note"><b>Note</b>: There are indications that the following may be under limited, targeted exploitation.<ul><li>CVE-2025-48633</li></ul></aside>`))
	})
	mux.HandleFunc("/bulletin/2026/2026-01-01", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<p>Published January 5, 2026</p><aside class="note">Nothing.</aside>`))
	})
	mux.HandleFunc("/", http.NotFound) // the other addresses of a month (and the months not published)

	dir := t.TempDir()
	prev := feeds.Seed{Claims: []feeds.SeedClaim{
		{CVE: "CVE-2026-88772", Source: "gti-blog", Date: "2026-09-29T14:00:00Z", URL: "https://cloud.google.com/blog/topics/threat-intelligence/old/"},
		{CVE: "CVE-2026-35273", Source: "gti-blog", Date: "2026-09-25T14:00:00Z", URL: "https://cloud.google.com/blog/topics/threat-intelligence/older/"},
		{CVE: "CVE-2026-123890", Source: "rapid7-blog", Date: "2026-11-20T00:00:00Z"}, // Rapid7's claims are kept without a link
	}}
	prevPath, outPath := filepath.Join(dir, "prev.json"), filepath.Join(dir, "seed.json")
	if err := os.WriteFile(prevPath, prev.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	// one Cisco CSAF document, gzipped, one per line
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"document":{"notes":[{"category":"summary","title":"Exploitation and Public Announcements","text":"In March 2026, the Cisco PSIRT became aware of active exploitation of this vulnerability."}],` +
		`"tracking":{"id":"cisco-sa-x-1","initial_release_date":"2026-03-05T16:00:00Z","current_release_date":"2026-03-05T16:00:00Z","revision_history":[{"date":"2026-03-05T16:00:00Z","summary":"Initial public release."}]}},"vulnerabilities":[{"cve":"CVE-2026-20122"}]}` + "\n"))
	_ = zw.Close()
	csaf := filepath.Join(dir, "cisco.jsonl.gz")
	if err := os.WriteFile(csaf, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	r := seedRun{client: srv.Client(), sites: seedSites{chrome: srv.URL + "/chrome?redirect=false", rapid7: srv.URL + "/rapid7", gti: srv.URL + "/gti", android: srv.URL + "/bulletin/"},
		now: time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC), chrome: 1000, months: 2, cisco: csaf, out: &out}
	if err := r.build(t.Context(), prevPath, outPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outPath) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	got, err := feeds.ParseSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []feeds.SeedClaim{
		{CVE: "CVE-2025-48633", Source: "android-bulletin", Date: "2025-12-01T00:00:00Z", URL: "https://source.android.com/docs/security/bulletin/2025-12-01"},
		{CVE: "CVE-2026-125350", Source: "chrome-releases", Date: "2026-11-09T20:52:57Z", URL: "https://chromereleases.googleblog.com/2026/11/a.html"},
		{CVE: "CVE-2026-20122", Source: "cisco-psirt", Date: "2026-03-05T16:00:00Z", URL: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-x-1"},
		{CVE: "CVE-2026-35273", Source: "gti-blog", Date: "2026-09-25T14:00:00Z", URL: "https://cloud.google.com/blog/topics/threat-intelligence/older/"},
		{CVE: "CVE-2026-123890", Source: "rapid7-blog", Date: "2026-11-19T21:06:24Z"},
	}
	if len(got.Claims) != len(want) {
		t.Fatalf("%+v\n%s", got.Claims, out.String())
	}
	for i := range want {
		if got.Claims[i] != want[i] {
			t.Errorf("claim %d: %+v, want %+v", i, got.Claims[i], want[i])
		}
	}
	if strings.Join(chromeStarts, ",") != "1,3" { // the next page starts after the posts the first gave
		t.Errorf("chrome pages %v", chromeStarts)
	}
	if !strings.Contains(out.String(), "wrote "+outPath+": 5 claims") {
		t.Errorf("%s", out.String())
	}
}
