package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// zapAlert is one alert of a test report.
type zapAlert struct {
	PluginID   string              `json:"pluginid"`
	Alert      string              `json:"alert"`
	Risk       string              `json:"riskcode"`
	Confidence string              `json:"confidence"`
	OtherInfo  string              `json:"otherinfo,omitempty"`
	Reference  string              `json:"reference,omitempty"`
	Evidence   string              `json:"evidence,omitempty"`
	Instances  []map[string]string `json:"instances"`
}

func zapReportOf(t *testing.T, page string, alerts ...zapAlert) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"site": []any{map[string]any{"@name": strings.TrimSuffix(page, "/"), "alerts": alerts}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// INV-24, D-565: the rule list applies when a report is read: an IGNORE rule's alert is dropped, a FAIL rule's alert is "fix" and
// comes first, a WARN rule's alert is "hardening"; an unlisted rule is "fix" when ZAP rates it high or medium, else "hardening" (review
// r1 M2); inside each group the riskiest first.
func TestContract_INV24_RulesGroupTheAlerts(t *testing.T) {
	t.Parallel()
	in := func(id, risk string) zapAlert {
		return zapAlert{PluginID: id, Alert: "rule " + id, Risk: risk, Confidence: "2", Instances: []map[string]string{{"uri": zapPage}}}
	}
	raw := zapReportOf(t, zapPage, in("10096", "0"), in("10020", "2"), in("10036", "1"), in("99999", "3"), in("10109", "0"), in("10038", "2"), in("90022", "2"), in("10063", "1"), in("99998", "1"), in("99997", "2"), in("10042", "2"))
	rows, err := parseZAPWithRules(raw, zapPage)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Group+":"+r.PluginID+":"+r.Risk)
		if r.Software == nil {
			t.Fatalf("software is nil: %+v", r)
		}
	}
	want := []string{"fix:99999:high", "fix:90022:medium", "fix:99997:medium", "fix:10042:medium", "fix:10036:low", "hardening:10020:medium", "hardening:10038:medium", "hardening:99998:low"}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %q", got)
	}
	// A snapshot stored before the list (no group, IGNORE alerts kept) reads the same way.
	old := []WebFindingRow{{PluginID: "10109", Risk: "info"}, {PluginID: "10020", Risk: "medium"}, {PluginID: "10105", Risk: "low"}}
	if r, dropped := webOnRead(old); dropped != 1 || len(r) != 2 || r[0].PluginID != "10105" || r[0].Group != webGroupFix || r[1].Group != webGroupHardening || r[1].Software == nil {
		t.Fatalf("on read = %+v", r)
	}
}

// D-565: the CVEs and the library of a 10003 alert are read from Retire.js's own sentence and CVE ids only; markup, look-alikes and
// oversized text give nothing, never a wrong CVE or product.
func TestContract_INV24_RetireCVEs(t *testing.T) {
	t.Parallel()
	const ok = "The identified library jquery, version 3.4.1 is vulnerable.\nCVE-2020-11022\nCVE-2020-11023\n"
	tests := []struct {
		name, other, ref string
		want             []WebSoftware
	}{
		{name: "retire", other: ok, want: []WebSoftware{{Product: "jquery", Version: "3.4.1", CVEs: []string{"CVE-2020-11022", "CVE-2020-11023"}}}},
		{name: "reference CVEs of the one library", other: "The identified library bootstrap, version 3.3.7 is vulnerable.\n", ref: "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
			want: []WebSoftware{{Product: "bootstrap", Version: "3.3.7", CVEs: []string{"CVE-2019-8331"}}}},
		{name: "no sentence", other: "CVE-2020-11023", want: []WebSoftware{}},
		{name: "markup in the name", other: "The identified library <img src=x>, version 1 is vulnerable. CVE-2020-11023", want: []WebSoftware{}},
		{name: "look-alike ids", other: "The identified library jquery, version 1.8.1 is vulnerable. XCVE-2020-11023 CVE-2020-110231234 CVE-1899-1234 cve-2020-11023 CVE-2020-123",
			want: []WebSoftware{{Product: "jquery", Version: "1.8.1", CVEs: []string{}}}},
		{name: "version with a path", other: "The identified library jquery, version ../../etc is vulnerable. CVE-2020-11023", want: []WebSoftware{}},
		{name: "oversized", other: strings.Repeat("A", maxZapEvidence*4+1) + ok, want: []WebSoftware{}},
		{name: "duplicates", other: ok + ok + "CVE-2020-11022", want: []WebSoftware{{Product: "jquery", Version: "3.4.1", CVEs: []string{"CVE-2020-11022", "CVE-2020-11023"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := zapReportOf(t, zapPage, zapAlert{PluginID: "10003", Alert: "Vulnerable JS Library", Risk: "2", Confidence: "2", Reference: tc.ref,
				Instances: []map[string]string{{"uri": zapPage + "js/jquery.js", "otherinfo": tc.other}}})
			rows, err := parseZAPWithRules(raw, zapPage)
			if err != nil || len(rows) != 1 {
				t.Fatalf("%+v %v", rows, err)
			}
			if fmt.Sprint(rows[0].Software) != fmt.Sprint(tc.want) {
				t.Fatalf("software = %+v, want %+v", rows[0].Software, tc.want)
			}
		})
	}
}

// D-565: the product/version tokens of a Server (10036) or X-Powered-By (10037) header.
func TestContract_INV24_HeaderVersions(t *testing.T) {
	t.Parallel()
	tests := []struct{ evidence, want string }{
		{"Apache/2.4.49 (Unix)", "[{Apache 2.4.49 [] }]"},
		{"Apache/2.4.49 (Unix) OpenSSL/1.1.1d PHP/7.4.3", "[{Apache 2.4.49 [] } {OpenSSL 1.1.1d [] } {PHP 7.4.3 [] }]"},
		{"X-Powered-By: PHP/7.4.3", "[{PHP 7.4.3 [] }]"},
		{"Apache/2.4.41 (Ubuntu)", "[{Apache 2.4.41 [] Ubuntu}]"},
		{"Microsoft-IIS/10.0", "[{Microsoft-IIS 10.0 [] }]"},
		{"nginx", "[]"},
		{"ASP.NET", "[]"},
		{"Apache/2.4.49<script>alert(1)</script>", "[]"},
		{"Apache/../../2", "[]"},
		{"Apache/2.4.49.1.2", "[]"},
		{"A/1 B/2 C/3 D/4 E/5", "[{A 1 [] } {B 2 [] } {C 3 [] } {D 4 [] }]"},
		{strings.Repeat("x", maxZapEvidence) + " Apache/2.4.49", "[]"},
		// a distribution build (review r1 L4): the upstream version, and the distribution its suffix names; an unknown suffix is not read
		{"X-Powered-By: PHP/7.4.3-4ubuntu2.24", "[{PHP 7.4.3 [] Ubuntu}]"},
		{"PHP/8.2.7-1~deb12u1", "[{PHP 8.2.7 [] Debian}]"},
		{"Apache/2.4.37-62.el8 (Red Hat)", "[{Apache 2.4.37 [] Red Hat}]"},
		{"PHP/7.4.3-custom1", "[]"},
		{"PHP/7.4.3-" + strings.Repeat("u", 41), "[]"},
	}
	for _, tc := range tests {
		raw := zapReportOf(t, zapPage, zapAlert{PluginID: "10036", Alert: "Server Leaks Version", Risk: "1", Confidence: "3",
			Instances: []map[string]string{{"uri": zapPage, "evidence": tc.evidence}}})
		rows, err := parseZAPWithRules(raw, zapPage)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%q: %+v %v", tc.evidence, rows, err)
		}
		if got := fmt.Sprint(rows[0].Software); got != tc.want {
			t.Errorf("%q: software = %s, want %s", tc.evidence, got, tc.want)
		}
	}
	// Only the three rules carry software; a stored row of another rule loses any it claims.
	if r, _ := webOnRead([]WebFindingRow{{PluginID: "10020", Software: []WebSoftware{{Product: "Apache", Version: "2.4.49"}}}}); len(r[0].Software) != 0 {
		t.Fatalf("%+v", r)
	}
}

// fakeLookupMatcher is a Matcher that also looks CVE ids up (ExploitedLookup), and answers Match by the CPE it is asked about.
type fakeLookupMatcher struct {
	listed  map[string]VulnRow
	byCPE   map[string][]string
	asked   [][]ServiceRow
	looked  [][]string
	lookErr error
}

func (f *fakeLookupMatcher) Match(_ context.Context, s []ServiceRow) (Matches, error) {
	f.asked = append(f.asked, s)
	out := Matches{}
	for _, r := range s {
		for _, c := range f.byCPE[r.CPE] {
			out.Vulns = append(out.Vulns, VulnRow{IP: r.IP, Port: r.Port, CVE: c, Basis: "version", Summary: r.IP + " runs " + r.Product + " " + r.Version + "."})
		}
	}
	return out, nil
}

func (f *fakeLookupMatcher) Exploited(_ context.Context, cves []string) (map[string]KEVEntry, error) {
	f.looked = append(f.looked, cves)
	out := map[string]KEVEntry{}
	for _, c := range cves {
		if v, ok := f.listed[c]; ok {
			out[c] = KEVEntry{Name: v.Name, DateAdded: v.DateAdded, Ransomware: v.Ransomware}
		}
	}
	return out, f.lookErr
}

// D-565: when a snapshot is read, a CVE Retire.js names that CISA lists becomes a "js_library" row; a header version goes through the
// Matcher unless nmap read a version of the same product on that port, and its row says which header; nothing replaces a row that is
// already there.
func TestContract_INV24_ZAPVersionsBecomeExploitedRows(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	added := "2025-01-23"
	m := &fakeLookupMatcher{
		listed: map[string]VulnRow{"CVE-2020-11023": {CVE: "CVE-2020-11023", Name: "JQuery Cross-Site Scripting (XSS) Vulnerability", DateAdded: &added}},
		byCPE: map[string][]string{
			"cpe:/a:apache:http_server:2.4.49": {"CVE-2021-41773"},
			"cpe:/a:php:php:7.4.3":             {"CVE-2099-0002"},
		},
	}
	e.svc.cfg.Matcher = m
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{
		{IP: ipA, Port: 80, Name: "http"}, // nmap read no product: the header version counts
		{IP: ipA, Port: 18443, Name: "ssl/http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"},
	}}}
	page80, page18443 := "http://"+ipA+"/", "https://"+ipA+":18443/"
	w := &fakeWeb{report: func(page string) []byte {
		js := zapAlert{PluginID: "10003", Alert: "Vulnerable JS Library", Risk: "2", Confidence: "2",
			Instances: []map[string]string{{"uri": page + "js/jquery.js", "otherinfo": "The identified library jquery, version 3.4.1 is vulnerable.\nCVE-2020-11022\nCVE-2020-11023\n"}}}
		server := zapAlert{PluginID: "10036", Alert: "Server Leaks Version", Risk: "1", Confidence: "3", Instances: []map[string]string{{"uri": page, "evidence": "Apache/2.4.49 (Unix)"}}}
		powered := zapAlert{PluginID: "10037", Alert: "X-Powered-By", Risk: "1", Confidence: "2", Instances: []map[string]string{{"uri": page, "evidence": "X-Powered-By: PHP/7.4.3"}}}
		noise := zapAlert{PluginID: "10096", Alert: "Timestamp Disclosure", Risk: "0", Confidence: "1", Instances: []map[string]string{{"uri": page}}}
		return zapReportOf(t, page, js, server, powered, noise)
	}}
	e.wire(w)
	s := e.scanIP(Content{})
	if !slices.Equal(w.asked, []string{page80, page18443}) {
		t.Fatalf("asked %q", w.asked)
	}
	for _, r := range s.WebFindings {
		if r.PluginID == "10096" || (r.Group != webGroupFix) {
			t.Fatalf("web finding %+v", r)
		}
	}
	got := map[string]VulnRow{}
	for _, v := range s.Vulns {
		k := fmt.Sprintf("%d:%s", v.Port, v.CVE)
		if _, dup := got[k]; dup {
			t.Fatalf("two rows for %s: %+v", k, s.Vulns)
		}
		got[k] = v
	}
	if v := got["80:CVE-2020-11023"]; v.Basis != "js_library" || v.Name == "" || v.DateAdded == nil || !strings.Contains(v.Summary, "jquery 3.4.1") ||
		!strings.Contains(v.Summary, "does not show that the site uses the affected function; the risk is to visitors' browsers, not the server") { // review r1 M3
		t.Fatalf("js row = %+v (all %+v)", v, s.Vulns)
	}
	if _, ok := got["80:CVE-2020-11022"]; ok {
		t.Fatal("a CVE CISA does not list became a row")
	}
	if v := got["80:CVE-2021-41773"]; v.Basis != "version" || !strings.HasSuffix(v.Summary, "seen in the Server header by ZAP.") {
		t.Fatalf("server row = %+v", v)
	}
	if v := got["18443:CVE-2099-0002"]; !strings.HasSuffix(v.Summary, "seen in the X-Powered-By header by ZAP.") {
		t.Fatalf("php row = %+v", v)
	}
	if v := got["18443:CVE-2021-41773"]; strings.Contains(v.Summary, "ZAP") {
		t.Fatalf("nmap's row was replaced: %+v", v)
	}
	for _, a := range m.asked {
		for _, r := range a {
			if r.Port == 18443 && r.Product == "Apache" {
				t.Fatalf("the Server header was compared where nmap read a version: %+v", r)
			}
		}
	}
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool { return strings.HasPrefix(c.Text, "Versions ZAP read on the web pages compared") }) {
		t.Fatalf("checks = %+v", s.Checks)
	}

	// The list cannot be read: a "Not checked" line, never "no exploited CVE"; a reason the page may show is said as is, since trying
	// again does not help while the Feeds module is off (review r1 L1).
	m.lookErr = &Unavailable{Reason: "the Feeds module is off."}
	snap := s
	e.svc.withVulns(e.ctx(), &snap)
	if n := notChecked(snap); !slices.Contains(n, "Versions ZAP read on the web pages were not compared with exploited vulnerabilities: the Feeds module is off.") || slices.Contains(n, notWebVersionsFail) {
		t.Fatalf("not checked = %q", n)
	}
	m.lookErr = errors.New("disk")
	snap = s
	e.svc.withVulns(e.ctx(), &snap)
	if !slices.Contains(notChecked(snap), notWebVersionsFail) {
		t.Fatalf("not checked = %q", notChecked(snap))
	}
}

// Review r1 L5: at the cap the "Fix this" rows are kept before any hardening row, even a riskier one.
func TestContract_INV24_CapKeepsFixFirst(t *testing.T) {
	t.Parallel()
	var in []WebFindingRow
	for i := range maxWebFindings + 50 {
		in = append(in, WebFindingRow{Site: zapPage, PluginID: "10038", Name: fmt.Sprint("csp ", i), Risk: "medium", Confidence: "high", Group: webGroupHardening})
	}
	for i := range 3 {
		in = append(in, WebFindingRow{Site: zapPage, PluginID: "10036", Name: fmt.Sprint("server ", i), Risk: "low", Confidence: "high", Group: webGroupFix})
	}
	out := sanitizeWeb(in)
	if len(out) != maxWebFindings || out[0].PluginID != "10036" || out[2].PluginID != "10036" || out[3].PluginID != "10038" {
		t.Fatalf("kept %d, first %+v", len(out), out[:4])
	}
}

// Review r1 L6: a snapshot stored before the list counted alerts the page no longer shows; its "web" line says how many are hidden.
func TestContract_INV24_OldSnapshotSaysWhatIsHidden(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	snap := Snapshot{Content: Content{
		WebFindings: []WebFindingRow{{Site: zapPage, PluginID: "10109", Risk: "info"}, {Site: zapPage, PluginID: "10096", Risk: "low"}, {Site: zapPage, PluginID: "10020", Risk: "medium"}},
		Checks:      []CheckRow{{Kind: "web", Text: "Passive web scan (ZAP baseline: spider and passive rules, no form sent) of 1 page: " + zapPage + ". 3 alerts."}},
	}}
	e.svc.withVulns(e.ctx(), &snap)
	if len(snap.WebFindings) != 1 || !strings.HasSuffix(snap.Checks[0].Text, "3 alerts. 2 of them hidden: Vedette's rule list treats them as noise.") {
		t.Fatalf("findings %+v, checks %+v", snap.WebFindings, snap.Checks)
	}
}
