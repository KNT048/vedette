package exposure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

const zapPage = "http://203.0.113.10:18443/"

func zapFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/zap-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// INV-24: the ZAP report of a real shape gives one row per alert of the scanned site, with ZAP's words for risk and confidence, the
// CWE, markup-free text, and at most three sample pages of that site; another host's alerts and a false positive are not rows.
func TestContract_INV24_ParsesTheBaselineReport(t *testing.T) {
	t.Parallel()
	rows, err := ParseZAPReport(zapFixture(t), zapPage)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	a := rows[0]
	if a.PluginID != "10020" || a.Name != "Missing Anti-clickjacking Header" || a.Risk != "medium" || a.Confidence != "medium" || a.CWE != 1021 || a.Count != 5 || a.Site != zapPage {
		t.Fatalf("first row = %+v", a)
	}
	if !slices.Equal(a.URLs, []string{"http://203.0.113.10:18443/", "http://203.0.113.10:18443/a", "http://203.0.113.10:18443/b"}) {
		t.Fatalf("urls = %q", a.URLs)
	}
	if a.Description != "The response does not protect against 'ClickJacking' attacks." || strings.ContainsAny(a.Solution, "<>") {
		t.Fatalf("text = %q / %q", a.Description, a.Solution)
	}
	if rows[1].Risk != "low" || rows[1].Confidence != "high" || rows[1].Name != `Server Leaks Version Information via "Server" HTTP Response Header Field` {
		t.Fatalf("second row = %+v", rows[1])
	}
	if rows[2].Risk != "info" || rows[2].CWE != 0 {
		t.Fatalf("third row = %+v", rows[2])
	}
}

// INV-24: a report that cannot be trusted is refused, never read as "no alerts"; a clean site is a report of zero rows.
func TestContract_INV24_ReportsThatAreRefused(t *testing.T) {
	t.Parallel()
	site := func(alerts string) string {
		return `{"site":[{"@name":"http://203.0.113.10:18443","alerts":[` + alerts + `]}]}`
	}
	deep := strings.Repeat(`{"a":`, 20000) + "1" + strings.Repeat("}", 20000)
	tests := []struct {
		name string
		raw  string
		err  error
	}{
		{"empty", ``, ErrBadReport},
		{"not json", `<html>proxy error</html>`, ErrBadReport},
		{"no site list", `{"@programName":"ZAP"}`, ErrBadReport},
		{"site is not a list", `{"site":{"@name":"x"}}`, ErrBadReport},
		{"trailing data", site(``) + `{}`, ErrBadReport},
		{"huge", `{"pad":"` + strings.Repeat("a", MaxWebReport) + `"}`, ErrBadReport},
		{"nested", `{"site":[],"x":` + deep + `}`, ErrBadReport},
		{"risk is a word", site(`{"pluginid":"1","alert":"x","riskcode":"High","confidence":"2"}`), ErrBadReport},
		{"risk out of range", site(`{"pluginid":"1","alert":"x","riskcode":"4","confidence":"2"}`), ErrBadReport},
		{"risk is a float", site(`{"pluginid":"1","alert":"x","riskcode":2.5,"confidence":"2"}`), ErrBadReport},
		{"risk missing", site(`{"pluginid":"1","alert":"x","confidence":"2"}`), ErrBadReport},
		{"confidence out of range", site(`{"pluginid":"1","alert":"x","riskcode":"1","confidence":"9"}`), ErrBadReport},
		{"name is a number", site(`{"pluginid":"1","alert":7,"riskcode":"1","confidence":"2"}`), ErrBadReport},
		{"no name", site(`{"pluginid":"1","riskcode":"1","confidence":"2"}`), ErrBadReport},
		{"instances is a string", site(`{"pluginid":"1","alert":"x","riskcode":"1","confidence":"2","instances":"all"}`), ErrBadReport},
		{"no entry for the scanned address", `{"site":[{"@name":"http://other.example","alerts":[]}]}`, ErrNoPage},
		{"no site at all", `{"site":[]}`, ErrNoPage},
	}
	for _, tc := range tests {
		if _, err := ParseZAPReport([]byte(tc.raw), zapPage); !errors.Is(err, tc.err) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.err)
		}
	}
	if rows, err := ParseZAPReport([]byte(site(``)), zapPage); err != nil || len(rows) != 0 {
		t.Fatalf("clean site: %v %v", rows, err)
	}
	// unknown fields and the number spelled as a JSON number are fine
	if rows, err := ParseZAPReport([]byte(site(`{"pluginid":1,"alert":"x","riskcode":3,"confidence":2,"surprise":{"a":[1]}}`)), zapPage); err != nil || len(rows) != 1 || rows[0].Risk != "high" {
		t.Fatalf("numbers: %+v %v", rows, err)
	}
	var many []string
	for i := range maxZapAlerts + 1 {
		many = append(many, fmt.Sprintf(`{"pluginid":"%d","alert":"x","riskcode":"1","confidence":"2"}`, i))
	}
	if _, err := ParseZAPReport([]byte(site(strings.Join(many, ","))), zapPage); !errors.Is(err, ErrBadReport) {
		t.Fatalf("too many alerts: %v", err)
	}
}

// INV-24, rules/security.md: text from the target's pages is data. Markup, scripts, control characters and long text cannot reach
// the page as anything but short printable text; a sample URL that is not http(s) on the scanned site is dropped.
func TestContract_INV24_HostileTextIsTamed(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("A", 5000)
	raw := `{"site":[{"@name":"http://203.0.113.10:18443/","alerts":[{"pluginid":"7","alert":"<script>alert(1)</script>Cookie\u0000 <img src=x onerror=y>","riskcode":"3","confidence":"3",
		"desc":"<p onclick='x'>` + long + `</p>","solution":"a\u202eb\u0007c <b>bold</b> > <","cweid":"79",
		"instances":[{"uri":"javascript:alert(1)"},{"uri":"http://203.0.113.10:18443/\u0000x"},{"uri":"http://user:pw@203.0.113.10:18443/"},{"uri":"http://203.0.113.10:18443/ok"},{"uri":"http://203.0.113.10:18443/` + strings.Repeat("p", 400) + `"}]}]}]}`
	rows, err := ParseZAPReport([]byte(raw), zapPage)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	r := rows[0]
	for _, s := range []string{r.Name, r.Description, r.Solution} {
		if strings.ContainsAny(s, "<>\x00\x07\u202e") {
			t.Errorf("markup or control characters survived: %q", s)
		}
	}
	if r.Name != "alert(1) Cookie" {
		t.Errorf("name = %q", r.Name)
	}
	if n := len([]rune(r.Description)); n != maxWebText || !strings.HasSuffix(r.Description, "…") {
		t.Errorf("description has %d characters: %q", n, r.Description[:20])
	}
	if !slices.Equal(r.URLs, []string{"http://203.0.113.10:18443/ok"}) {
		t.Errorf("urls = %q", r.URLs)
	}
}

// FuzzParseZAPReport: whatever bytes arrive, the parser returns rows that pass the storage check or an error, and never panics.
func FuzzParseZAPReport(f *testing.F) {
	b, err := os.ReadFile("testdata/zap-baseline.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"site":[{"@name":"http://203.0.113.10:18443","alerts":[{"pluginid":1,"alert":"<b>x","riskcode":"2","confidence":"2","instances":[{"uri":"http://203.0.113.10:18443/"}]}]}]}`))
	f.Add([]byte(`{"site":[]}`))
	f.Add([]byte(`[[[[`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		rows, err := ParseZAPReport(raw, zapPage)
		if err != nil {
			return
		}
		if len(rows) > maxZapAlerts {
			t.Fatalf("%d rows", len(rows))
		}
		for _, r := range rows {
			if _, ok := cleanWebRow(r); !ok || strings.ContainsAny(r.Name+r.Description+r.Solution, "<>") || len(r.URLs) > maxWebURLs || r.CWE < 0 {
				t.Fatalf("row does not pass the storage check: %+v", r)
			}
			for _, u := range r.URLs {
				if k, ok := pageKey(u); !ok || k != "http://203.0.113.10:18443" || strings.ContainsAny(u, "?#@") || field(u, maxWebURL) != u {
					t.Fatalf("sample URL %q is not a plain path of the scanned site", u)
				}
			}
		}
	})
}

// ---- when to run ----

// fakeWeb is the WebScanner seam with a canned answer per page; it records every page it was asked for. errAt fails the n-th call (from 0).
type fakeWeb struct {
	report func(page string) []byte
	err    error
	errAt  map[int]error
	pages  []WebPage
	asked  []string
	log    *webLog // the probe log it must find rows in before it is called
	logged []int   // how many rows the log held at each call
}

func (f *fakeWeb) Baseline(_ context.Context, _ ScanTarget, p WebPage) (WebScan, error) {
	if f.log != nil {
		f.logged = append(f.logged, len(f.log.rows))
	}
	n := len(f.asked)
	f.pages, f.asked = append(f.pages, p), append(f.asked, p.URL)
	if err := f.errAt[n]; err != nil {
		return WebScan{}, err
	}
	if f.err != nil {
		return WebScan{}, f.err
	}
	return WebScan{Report: f.report(p.URL)}, nil
}

// webLog is the probe log of Config.Probes: it keeps the web probes it is given and can fail.
type webLog struct {
	rows []WebProbe
	err  error
}

func (l *webLog) RecordTemplateProbes(context.Context, []TemplateProbe) error { return l.err }
func (l *webLog) RecordWebProbe(_ context.Context, p WebProbe) error {
	if l.err != nil {
		return l.err
	}
	l.rows = append(l.rows, p)
	return nil
}

// wire gives the service the web scanner and a probe log it can write to.
func (e *env) wire(w *fakeWeb) *webLog {
	l := &webLog{}
	w.log = l
	e.svc.cfg.Web, e.svc.cfg.Probes = w, l
	return l
}

func cleanReport(page string) []byte {
	return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":"10036","alert":"Server Leaks Version","riskcode":"1","confidence":"3","cweid":"200","instances":[{"uri":%q}]}]}]}`, strings.TrimSuffix(page, "/"), page))
}

func webServices() []ServiceRow {
	ip := ipA
	return []ServiceRow{{IP: ip, Port: 22, Name: "ssh"}, {IP: ip, Port: 80, Name: "http"}, {IP: ip, Port: 443, Name: "https"}, {IP: ip, Port: 8443, Name: "tcpwrapped"},
		{IP: ip, Port: 8080, Name: "http-proxy"}, {IP: ip, Port: 18443, Name: "ssl/http"}, {IP: ipB, Port: 8000, Name: "http"}}
}

// INV-24: an IP target's pages are its own web ports that service identification read, one URL per port, TLS by name or port; ssh,
// tcpwrapped, an HTTP proxy and another address are not asked for. The alerts are stored and not counted as exploited CVEs.
func TestContract_INV24_AskedOnlyForTheWebPortsOfTheTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := &fakeWeb{report: cleanReport}
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices(), Ports: 98}}
	e.wire(w)
	s := e.scanIP(Content{})
	want := []string{"http://" + ipA + "/", "https://" + ipA + "/", "https://" + ipA + ":18443/"}
	if !slices.Equal(w.asked, want) {
		t.Fatalf("asked = %q", w.asked)
	}
	if len(s.WebFindings) != 3 || s.WebFindings[0].Risk != "low" || len(s.Vulns) != 0 {
		t.Fatalf("web findings = %+v, vulns = %+v", s.WebFindings, s.Vulns)
	}
	if !slices.Contains(checkKinds(s), "web") {
		t.Fatalf("checks = %+v", s.Checks)
	}
	if e.count(`SELECT count(*) FROM exp_snapshot WHERE web_findings LIKE '%Server Leaks%'`) != 1 {
		t.Fatal("the alerts are not stored")
	}
}

// INV-24: nothing is asked for a target that did not pass the gate: an unverified IP, a paused one, a domain without a commitment.
func TestContract_INV24_NoRequestForATargetThatDidNotPassTheGate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := &fakeWeb{report: cleanReport}
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices()}}
	e.wire(w)
	e.svc.SetRunner(&fakeRunner{content: Content{}})
	ips := e.detect(ipA)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil { // no commitment yet
		t.Fatal("scanned without a commitment")
	}
	dom, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example") // not verified
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID); err == nil {
		t.Fatal("scanned an unverified domain")
	}
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	e.fullAs(ipB) // a full check that no longer sees ipA pauses it (INV-13)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID); err == nil {
		t.Fatal("scanned a paused IP")
	}
	if len(w.asked) != 0 {
		t.Fatalf("asked for %q", w.asked)
	}
}

// INV-24: a domain's pages are its own names (the domain or a name under it) on the ports 80 and 443 the surface scan found open,
// when the name points at a public address; a name of another domain or a private address is never asked for, and at most four pages.
func TestContract_INV24_DomainNamesOnWebPortsOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := &fakeWeb{report: cleanReport}
	e.wire(w)
	dom := e.committedDomain()
	e.svc.SetRunner(&fakeRunner{content: Content{
		Hosts: []HostRow{{"acme.example", ipA}, {"www.acme.example", ipA}, {"evil.example.org", ipA}, {"notacme.example", ipA}, {"intra.acme.example", "10.0.0.5"}, {"mail.acme.example", ipB}, {"a.acme.example", ipB}},
		Ports: []PortRow{{ipA, 80, "http", "", "", 0, false}, {ipA, 443, "https", "", "", 0, false}, {"10.0.0.5", 443, "https", "", "", 0, false}, {ipB, 25, "smtp", "", "", 0, false}, {ipB, 443, "https", "", "", 0, false}},
	}})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://acme.example/", "http://acme.example/", "https://www.acme.example/", "http://www.acme.example/"}
	if !slices.Equal(w.asked, want) {
		t.Fatalf("asked = %q", w.asked)
	}
	for _, p := range w.pages { // H1: ZAP is pinned to the address the surface scan saw the name at, never to one it resolves again
		if p.IP.String() != ipA || p.Port != 80 && p.Port != 443 || strings.Contains(p.URL, ipA) || p.Host == "" {
			t.Errorf("page = %+v", p)
		}
	}
	if len(w.logged) != len(want) || w.logged[0] != 1 || w.logged[3] != 4 { // each page is in the probe log before its scan starts
		t.Errorf("rows in the log at each call = %v", w.logged)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), dom.ID, snap.Date)
	if err != nil {
		t.Fatal(err)
	}
	if n := notChecked(got); !slices.ContainsFunc(n, func(s string) bool { return strings.Contains(s, "2 more web ports not scanned (at most 4 pages") }) {
		t.Fatalf("not checked = %q", n)
	}
}

// INV-24: the seam's wording. No scanner: one "not set up" line. *Unavailable: its reason, one line for the scan. A report that cannot
// be read, a page ZAP did not see, and a failure each say so and keep the rest; none reads as "no alerts".
func TestContract_INV24_SeamWording(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, w *fakeWeb) Snapshot {
		e := newEnv(t)
		if w != nil {
			e.wire(w)
		}
		e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{{IP: ipA, Port: 443, Name: "https"}}, Ports: 98}}
		return e.scanIP(Content{})
	}
	has := func(s Snapshot, sub string) bool {
		return slices.ContainsFunc(notChecked(s), func(n string) bool { return strings.Contains(n, sub) })
	}
	if s := run(t, nil); !slices.Contains(notChecked(s), "Passive web scan (ZAP) is not set up on this box yet.") || slices.Contains(checkKinds(s), "web") {
		t.Fatalf("not set up: %q", notChecked(s))
	}
	if s := run(t, &fakeWeb{err: &Unavailable{Reason: "the ZAP image is not pulled yet"}}); !has(s, "Passive web scan (ZAP) did not run: the ZAP image is not pulled yet") {
		t.Fatalf("unavailable: %q", notChecked(s))
	}
	if s := run(t, &fakeWeb{err: errors.New("podman: exit 1 secret-path")}); !has(s, "failed, so the page was not checked") || has(s, "secret-path") {
		t.Fatalf("failure: %q", notChecked(s))
	}
	if s := run(t, &fakeWeb{report: func(string) []byte { return []byte(`<html>`) }}); !has(s, "could not be read") || len(s.WebFindings) != 0 || slices.Contains(checkKinds(s), "web") {
		t.Fatalf("unreadable: %q", notChecked(s))
	}
	if s := run(t, &fakeWeb{report: func(string) []byte { return []byte(`{"site":[]}`) }}); !has(s, "ZAP reported no page") || slices.Contains(checkKinds(s), "web") {
		t.Fatalf("no page: %q", notChecked(s))
	}
	if s := run(t, &fakeWeb{report: func(p string) []byte {
		return []byte(`{"site":[{"@name":"` + strings.TrimSuffix(p, "/") + `","alerts":[]}]}`)
	}}); slices.ContainsFunc(notChecked(s), func(n string) bool { return strings.Contains(n, "Passive web scan") }) || !slices.Contains(checkKinds(s), "web") {
		t.Fatalf("clean page: %q %v", notChecked(s), checkKinds(s))
	}
}

// INV-24 (LEGAL §3): a page is in the probe log before ZAP starts on it, with its address and port; nothing runs without a probe log
// that can take the row.
func TestContract_INV24_NothingRunsWithoutTheProbeLog(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		wire func(e *env, w *fakeWeb)
	}{
		{"no probe log", func(e *env, w *fakeWeb) { e.svc.cfg.Web = w }},
		{"a probe log that fails", func(e *env, w *fakeWeb) { e.wire(w).err = errors.New("disk full") }},
	} {
		e := newEnv(t)
		w := &fakeWeb{report: cleanReport}
		tc.wire(e, w)
		e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices()}}
		s := e.scanIP(Content{})
		if len(w.asked) != 0 || !slices.Contains(notChecked(s), notWebNoLog) {
			t.Errorf("%s: asked %q, not checked %q", tc.name, w.asked, notChecked(s))
		}
	}
	e := newEnv(t)
	w := &fakeWeb{report: cleanReport}
	l := e.wire(w)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices()}}
	e.scanIP(Content{})
	if len(l.rows) != 3 || l.rows[0].IP != ipA || l.rows[0].Port != 80 || l.rows[0].URL != "http://"+ipA+"/" || l.rows[0].Tool == "" {
		t.Fatalf("probe rows = %+v", l.rows)
	}
	if !slices.Equal(w.logged, []int{1, 2, 3}) {
		t.Fatalf("rows in the log at each call = %v", w.logged)
	}
}

// INV-24: sample URLs keep scheme, host and path; the query string, fragment, path parameters (;jsessionid=) and user info are never
// stored (they hold session ids).
func TestContract_INV24_SampleURLsHaveNoQueryOrFragment(t *testing.T) {
	t.Parallel()
	raw := `{"site":[{"@name":"http://203.0.113.10:18443","alerts":[{"pluginid":"3","alert":"Session ID in URL Rewrite","riskcode":"2","confidence":"2",
		"instances":[{"uri":"http://203.0.113.10:18443/reset?token=SECRET123&password=hunter2"},{"uri":"http://203.0.113.10:18443/reset#access_token=abc"},{"uri":"http://203.0.113.10:18443"},{"uri":"http://203.0.113.10:18443/app;jsessionid=ABC123"}]}]}]}`
	rows, err := ParseZAPReport([]byte(raw), zapPage)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	if !slices.Equal(rows[0].URLs, []string{"http://203.0.113.10:18443/reset", "http://203.0.113.10:18443/", "http://203.0.113.10:18443/app"}) {
		t.Fatalf("urls = %q", rows[0].URLs)
	}
}

// INV-24: a page that cannot run does not wipe the record of the pages already scanned, and the ones not tried are counted.
func TestContract_INV24_AnUnavailablePageKeepsTheEarlierOnes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := &fakeWeb{report: cleanReport, errAt: map[int]error{1: &Unavailable{Reason: "busy"}}}
	e.wire(w)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: webServices()}}
	s := e.scanIP(Content{})
	if len(w.asked) != 2 || len(s.WebFindings) != 1 || !slices.Contains(checkKinds(s), "web") || !strings.Contains(s.Checks[len(s.Checks)-1].Text, "of 1 page: http://"+ipA+"/") {
		t.Fatalf("asked %q, findings %d, checks %+v", w.asked, len(s.WebFindings), s.Checks)
	}
	if n := notChecked(s); !slices.Contains(n, "Passive web scan (ZAP) did not run: busy") || !slices.ContainsFunc(n, func(x string) bool { return strings.Contains(x, "1 more web port not scanned") }) {
		t.Fatalf("not checked = %q", n)
	}
}

// INV-24: HTML from the target is read as text: entities are decoded, a bare "<" in prose does not eat the text after it, and only
// sites (not HTTP proxies, RPC over HTTP or guesses) are scanned.
func TestContract_INV24_PlainTextAndWebServices(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"1 < 2 and 3 > 2 tail":                  "1 2 and 3 2 tail",
		"Use &lt;b&gt; &amp; more":              "Use b & more",
		"<p>Hello</p><!-- x -->World":           "Hello World",
		"&lt;script&gt;alert(1)&lt;/script&gt;": "script alert(1) /script",
	} {
		if got := plainText(in, 100); got != want {
			t.Errorf("plainText(%q) = %q, want %q", in, got, want)
		}
	}
	for name, want := range map[string]bool{"http": true, "https": true, "ssl/http": true, "http-alt": true, "https-alt": true, "http-proxy": false, "http-rpc-epmap": false, "http?": false, "ssh": false, "": false} {
		if isWebService(name) != want {
			t.Errorf("isWebService(%q) = %v", name, !want)
		}
	}
}
