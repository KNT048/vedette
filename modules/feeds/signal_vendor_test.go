package feeds

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClaimedCVEs_SameSentenceNegationsAndScope(t *testing.T) {
	t.Parallel()
	const a, b, c = "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"
	for _, tc := range []struct {
		name  string
		text  string
		scope []string
		want  []string
	}{
		{"a sentence before says two CVEs are not exploited; line breaks end sentences",
			"The PSIRT is not aware of any public announcements or malicious use of the vulnerabilities that are described in " + a + " and " + b + ".\r\n\r\n" +
				"In March 2026, the PSIRT became aware of active exploitation of the vulnerability that is described in " + c + " only. The vulnerabilities " +
				"that are described in the other CVEs in this advisory are not known to have been compromised.",
			[]string{a, b, c}, []string{c}},
		{"one vulnerability, named by the section", "The PSIRT is aware of attempted exploitation of this vulnerability.", []string{a}, []string{a}},
		{"this vulnerability of several is not one of them", "The PSIRT is aware of attempted exploitation of this vulnerability.", []string{a, b}, nil},
		{"these vulnerabilities are all of them", "The PSIRT is aware of limited exploitation of these vulnerabilities.", []string{a, b}, []string{a, b}},
		{"not aware", "The PSIRT is not aware of any public announcements or malicious use of the vulnerability that is described in this advisory.", []string{a}, nil},
		{"proof of concept is not exploitation", "The PSIRT is aware that proof-of-concept exploit code is available for the vulnerabilities described in this advisory.", []string{a}, nil},
		{"two clauses", "The PSIRT is not aware of malicious use of " + a + ", but is aware of active exploitation of " + b + ".", []string{a, b}, []string{b}},
		{"a vendor's own words with a no-break space", "An overflow in the daemon.\n\nPlease note that reports show this is being exploited in the wild.", []string{a}, []string{a}},
		{"html", "<p>Fortinet has observed this to be exploited in the wild&nbsp;on FortiWeb.</p>", []string{a}, []string{a}},
		{"a condition", "If exploited in the wild, this could allow an attacker to take over the device.", []string{a}, nil},
		{"another advisory's CVE", "Exploitation of CVE-2023-20198 has been observed in the wild.", []string{a}, nil},
		{"the next entry's CVE is another sentence", "Apple is aware of a report that this issue may have been exploited. " + b + ": a memory issue.", []string{a, b}, nil},
		{"exploiting another flaw first is not this one", "This vulnerability can only be abused as a consequence of a threat actor exploiting a known vulnerability.", []string{a}, nil},
	} {
		if got := claimedCVEs(tc.text, tc.scope); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMSRC_DatesFlagsAndShapes(t *testing.T) {
	t.Parallel()
	page := `{"@odata.context":"x","@odata.count":4,"value":[
{"cveNumber":"CVE-2026-0001","releaseDate":"2026-11-10T08:00:00-08:00","exploited":"Yes","revisions":[{"version":1,"revisionDate":"2026-11-10T08:00:00-08:00","unformattedDescription":"Information published."}]},
{"cveNumber":"CVE-2026-0002","releaseDate":"2026-07-14T07:00:00-07:00","exploited":"Yes","revisions":[{"revisionDate":"2026-07-14T07:00:00-07:00","unformattedDescription":"Information published."},
 {"revisionDate":"2026-07-16T07:00:00-07:00","unformattedDescription":"Corrected the Exploitability Index, Exploited flag and CVSS vector."},
 {"revisionDate":"2026-07-15T07:00:00-07:00","unformattedDescription":"CVSS vector modified to correct the temporal Exploit Code Maturity setting."}]},
{"cveNumber":"CVE-2026-0003","releaseDate":"2026-07-14T07:00:00-07:00","exploited":"No"},
{"cveNumber":"not a cve","releaseDate":"2026-07-14T07:00:00-07:00","exploited":"Yes"},
{"cveNumber":"CVE-2026-0004","releaseDate":12,"exploited":"Yes"}]}`
	pg, err := parseMSRCExploited(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(pg.Claims)
	want := "[{CVE-2026-0001 2026-11-10 16:00:00 +0000 UTC} {CVE-2026-0002 2026-07-16 14:00:00 +0000 UTC}]"
	if got != want || pg.Accepted != 2 || pg.Rejected != 2 {
		t.Errorf("%s %+v", got, pg.Stats)
	}
	for _, bad := range []string{`[]`, `{"value":[`, `{"value":[]} x`, `{"@odata.count":1}`, `{"value":{}}`} {
		if _, err := parseMSRCExploited(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

const msrcPath = "/sug/v2.0/en-US/vulnerability"

func msrcList(rows ...string) string {
	return `{"value":[` + strings.Join(rows, ",") + `]}`
}

func msrcRow(cve, released string) string {
	return fmt.Sprintf(`{"cveNumber":%q,"releaseDate":%q,"exploited":"Yes","revisions":[]}`, cve, released)
}

func vendorRows(t *testing.T, e *env, source string) map[string]string {
	t.Helper()
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve, first_seen, url, COALESCE(detail, ''), qualifies FROM feeds_signal WHERE source = ? AND kind = 'exploited'`, source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var cve, first, url, detail string
		var q int
		if err := rows.Scan(&cve, &first, &url, &detail, &q); err != nil {
			t.Fatal(err)
		}
		out[cve] = fmt.Sprintf("%s %s %s %d", first[:16], url, detail, q)
	}
	return out
}

func TestMSRC_PullsKeepTheBoxsFirstSighting(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(msrcFeedID)
	e.mirror(msrcFeedID, o.url(msrcPath)+"?$filter=exploited%20eq%20%27Yes%27")
	o.body(msrcPath, `"m1"`, msrcList(msrcRow("CVE-2026-0001", "2026-11-10T08:00:00-08:00"), msrcRow("CVE-2025-0002", "2025-03-11T07:00:00-07:00")))
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(msrcFeedID); st.Status != "ok" || st.Records == nil || *st.Records != 2 {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	got := vendorRows(t, e, msrcFeedID)
	if got["CVE-2026-0001"] != `2026-11-10T16:00 https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001 {"exploited":"Yes"} 1` ||
		!strings.HasPrefix(got["CVE-2025-0002"], "2025-03-11T14:00") {
		t.Fatalf("%v", got)
	}
	if q := o.all()[0].query; !strings.Contains(q, "filter=exploited") {
		t.Errorf("query %q", q)
	}

	// a day later: a CVE flagged since (dated by Microsoft at its old release: the flag came later), one no longer flagged
	e.setNow(e.clock().Add(24 * time.Hour))
	o.body(msrcPath, `"m2"`, msrcList(msrcRow("CVE-2026-0001", "2026-11-10T08:00:00-08:00"), msrcRow("CVE-2026-0003", "2026-10-13T07:00:00-07:00"),
		msrcRow("CVE-2026-0004", "2026-11-21T18:00:00Z")))
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	got = vendorRows(t, e, msrcFeedID)
	if len(got) != 3 || !strings.HasPrefix(got["CVE-2026-0001"], "2026-11-10T16:00") || !strings.HasPrefix(got["CVE-2026-0003"], "2026-11-22T06:00") ||
		!strings.HasPrefix(got["CVE-2026-0004"], "2026-11-21T18:00") {
		t.Errorf("second pull: %v", got)
	}

	// a next page at another address is refused; nothing changes
	e.setNow(e.clock().Add(24 * time.Hour))
	o.body(msrcPath, `"m3"`, `{"@odata.nextLink":"https://example.com/x","value":[]}`)
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(msrcFeedID); st.Status != "error" || !strings.Contains(deref(st.Error), "another address") || len(vendorRows(t, e, msrcFeedID)) != 3 {
		t.Errorf("%+v %q", st, deref(st.Error))
	}
}

func TestMSRC_ShrinkGuard(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(msrcFeedID)
	e.mirror(msrcFeedID, o.url(msrcPath))
	var rows []string
	for i := range 150 {
		rows = append(rows, msrcRow(fmt.Sprintf("CVE-2025-%04d", 1000+i), "2025-03-11T07:00:00-07:00"))
	}
	o.body(msrcPath, `"m1"`, msrcList(rows...))
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	o.body(msrcPath, `"m2"`, msrcList(rows[:10]...))
	e.setNow(e.clock().Add(24 * time.Hour))
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(msrcFeedID); st.Status != "error" || !strings.Contains(deref(st.Error), "fewer than half of the 150") || len(vendorRows(t, e, msrcFeedID)) != 150 {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	for _, body := range []string{`{"enabled":false}`, `{"enabled":true}`} {
		if c, b := e.put(msrcFeedID, body); c != 200 {
			t.Fatalf("%s: %d %v", body, c, b)
		}
	}
	if err := e.svc.Fetch(t.Context(), msrcFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(msrcFeedID); st.Status != "ok" || len(vendorRows(t, e, msrcFeedID)) != 10 {
		t.Fatalf("after off and on: %+v %q", st, deref(st.Error))
	}
}

const ciscoFeedPath = "/security/center/psirtrss20/CiscoSecurityAdvisory.xml"

// ciscoFeed is Cisco's advisory feed with items of (id, last change as the feed writes it).
func ciscoFeed(entries ...[2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8" ?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>Cisco Security Advisory</title>`)
	for _, x := range entries {
		fmt.Fprintf(&b, `<item><!-- c --><title>t</title><link>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/%s?vs_f=Cisco%%20Security%%20Advisory</link><description>&lt;p&gt;exploited in the wild&lt;/p&gt;</description><pubDate>%s</pubDate><guid>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/%s</guid></item>`, x[0], x[1], x[0])
	}
	b.WriteString(`</channel></rss>`)
	return b.String()
}

func ciscoDocPath(id string) string {
	return "/security/center/contentjson/CiscoSecurityAdvisory/" + id + "/csaf/" + id + ".json"
}

func ciscoDoc(id, released, exploitation string, revs []string, cves ...string) string {
	var vs []string
	for _, c := range cves {
		vs = append(vs, fmt.Sprintf(`{"cve":%q}`, c))
	}
	return fmt.Sprintf(`{"document":{"tracking":{"id":%q,"initial_release_date":%q,"revision_history":[%s]},
"notes":[{"category":"summary","title":"Summary","text":"Attackers have exploited this vulnerability in the wild."},
{"category":"general","title":"Exploitation and Public Announcements","text":%q}]},"product_tree":{"branches":[]},"vulnerabilities":[%s]}`,
		id, released, strings.Join(revs, ","), exploitation, strings.Join(vs, ","))
}

func TestCisco_ChangedAdvisoriesClaimsAndRetraction(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(ciscoFeedID)
	e.mirror(ciscoFeedID, o.url(ciscoFeedPath))
	const one, two, gone, old = "cisco-sa-one-AbC12345", "cisco-sa-two-XyZ98765", "cisco-sa-gone-Qq111111", "cisco-sa-old-Zz000000"
	o.body(ciscoFeedPath, `"i1"`, ciscoFeed(
		[2]string{one, "2026-11-20 16:00:00.0"},
		[2]string{two, "2026-10-01 16:00:00.0"},
		[2]string{gone, "2026-09-01 16:00:00.0"},
		[2]string{"bad id", "2026-09-01 16:00:00.0"},
		[2]string{old, "2026-06-01 16:00:00.0"},
	))
	o.body(ciscoDocPath(old), `"d0"`, ciscoDoc(old, "2026-06-01T16:00:00+00:00", "The Cisco PSIRT is not aware of any malicious use of this vulnerability.", nil, "CVE-2026-2000"))
	o.body(ciscoDocPath(one), `"d1"`, ciscoDoc(one, "2026-11-18T16:00:00+00:00",
		"The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerability that is described in CVE-2026-2001.\r\n\r\nIn November 2026, the Cisco PSIRT became aware of active exploitation of the vulnerability that is described in CVE-2026-2002.",
		[]string{`{"date":"2026-11-18T16:00:00+00:00","summary":"Initial public release."}`, `{"date":"2026-11-20T16:00:00+00:00","summary":"Added information about active exploitation of CVE-2026-2002."}`},
		"CVE-2026-2001", "CVE-2026-2002"))
	o.body(ciscoDocPath(two), `"d2"`, ciscoDoc(two, "2026-09-25T16:00:00+00:00", "The Cisco PSIRT is aware of attempted exploitation of this vulnerability.", nil, "CVE-2026-2003"))
	o.serve(ciscoDocPath(gone), func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(ciscoFeedID)
	if st.Status != "ok" || st.Records == nil || *st.Records != 2 {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	got := vendorRows(t, e, ciscoFeedID)
	if len(got) != 2 || got["CVE-2026-2002"] != `2026-11-20T16:00 https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/`+one+` {"advisory":"`+one+`"} 1` ||
		!strings.HasPrefix(got["CVE-2026-2003"], "2026-09-25T16:00") {
		t.Fatalf("%v", got)
	}
	if o.count(ciscoDocPath(old)) != 1 || o.count(ciscoFeedPath) != 1 {
		t.Errorf("a first pull reads every advisory of the feed: %d, %d", o.count(ciscoDocPath(old)), o.count(ciscoFeedPath))
	}

	// six hours later only "two" changed: it no longer claims its CVE (a correction); "one" is not read again
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(ciscoFeedPath, `"i2"`, ciscoFeed([2]string{two, "2026-11-21 10:00:00.0"}, [2]string{one, "2026-11-20 16:00:00.0"}, [2]string{old, "2026-06-01 16:00:00.0"}))
	o.body(ciscoDocPath(two), `"d3"`, ciscoDoc(two, "2026-09-25T16:00:00+00:00", "The Cisco PSIRT is not aware of any malicious use of this vulnerability.", nil, "CVE-2026-2003"))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, ciscoFeedID); len(got) != 1 || got["CVE-2026-2002"] == "" || o.count(ciscoDocPath(one)) != 1 || o.count(ciscoDocPath(two)) != 2 || o.count(ciscoDocPath(old)) != 1 {
		t.Fatalf("after the correction: %v; %d, %d reads", got, o.count(ciscoDocPath(one)), o.count(ciscoDocPath(two)))
	}

	// a document that is another advisory's is skipped and counted, not stored
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(ciscoFeedPath, `"i3"`, ciscoFeed([2]string{two, "2026-11-21 15:00:00.0"}))
	o.body(ciscoDocPath(two), `"d4"`, ciscoDoc(one, "2026-09-25T16:00:00+00:00", "The Cisco PSIRT is aware of attempted exploitation of this vulnerability.", nil, "CVE-2026-2009"))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(ciscoFeedID); st.Status != "ok" || len(vendorRows(t, e, ciscoFeedID)) != 1 {
		t.Fatalf("%+v %q %v", st, deref(st.Error), vendorRows(t, e, ciscoFeedID))
	}
}

const fortiFeedPath = "/fortiguard/rss/ir.xml"

func fortiFeed(items ...[2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version='1.0' encoding='UTF-8'?><rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf" version="2.0"><channel><title>t</title>`)
	for _, it := range items {
		fmt.Fprintf(&b, `<item><title>x</title><link>https://fortiguard.fortinet.com/psirt/%s</link><description><![CDATA[<p>exploited in the wild CVE-2026-9</p>]]></description><pubDate>Fri, 20 Nov 2026 00:00:00 -0800</pubDate><csaf:link>%s</csaf:link></item>`, it[0], it[1])
	}
	b.WriteString(`</channel></rss>`)
	return b.String()
}

func fortiDoc(id, released string, vulns ...[2]string) string {
	var vs []string
	for _, v := range vulns {
		vs = append(vs, fmt.Sprintf(`{"cve":%q,"threats":[{"category":"impact","details":"Execute unauthorized code or commands"}],"references":[{"url":"https://fortiguard.fortinet.com/psirt/%s","summary":%q}]}`, v[0], id, v[1]))
	}
	return fmt.Sprintf(`{"document":{"title":"t","csaf_version":"2.0","tracking":{"id":%q,"initial_release_date":%q,"revision_history":[{"number":"1","date":%q,"summary":"Initial Publication"}]}},"vulnerabilities":[%s]}`,
		id, released, released, strings.Join(vs, ","))
}

func TestFortinet_FeedDocumentsAndConditionalReads(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(fortinetFeedID)
	e.mirror(fortinetFeedID, o.url(fortiFeedPath))
	const p1, p2 = "/fortiguard/psirt/csaf_one_fg-ir-26-100.json", "/fortiguard/psirt/csaf_two_fg-ir-25-910.json"
	o.body(fortiFeedPath, `"r1"`, fortiFeed(
		[2]string{"FG-IR-26-100", "https://filestore.fortinet.com" + p1},
		[2]string{"FG-IR-25-910", "https://filestore.fortinet.com" + p2},
		[2]string{"FG-IR-26-279", ""},                                                     // under investigation: no document
		[2]string{"FG-IR-26-101", "https://filestore.fortinet.com/../../etc/passwd.json"}, // a bad link is rejected
	))
	modified := map[string]bool{}
	doc := func(path, body string) {
		o.serve(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-Modified-Since") != "" && !modified[path] {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(body))
		})
	}
	doc(p1, fortiDoc("FG-IR-26-100", "2026-04-14T00:00:00", [2]string{"CVE-2026-3001", "<p>An OS command injection may allow an attacker to run commands.</p>"}))
	doc(p2, fortiDoc("FG-IR-25-910", "2025-11-14T00:00:00",
		[2]string{"CVE-2025-3002", "A path confusion vulnerability in GUI.\n\nFortinet has observed this to be exploited in the wild."},
		[2]string{"CVE-2025-3002", "A path confusion vulnerability in GUI.\n\nFortinet has observed this to be exploited in the wild."}))
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(fortinetFeedID)
	if st.Status != "ok" || st.Records == nil || *st.Records != 1 {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	if got := vendorRows(t, e, fortinetFeedID); got["CVE-2025-3002"] != `2025-11-14T00:00 https://fortiguard.fortinet.com/psirt/FG-IR-25-910 {"advisory":"FG-IR-25-910"} 1` {
		t.Fatalf("%v", got)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "passwd") || (h.path == p1 && h.header.Get("If-Modified-Since") != "") {
			t.Errorf("request %s %v", h.path, h.header)
		}
	}

	// the feed changed: the first advisory now says it is exploited (Fortinet keeps its first date: the box's own sighting is the
	// date); the second did not change and answers 304
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(fortiFeedPath, `"r2"`, fortiFeed([2]string{"FG-IR-26-100", "https://filestore.fortinet.com" + p1}, [2]string{"FG-IR-25-910", "https://filestore.fortinet.com" + p2}))
	modified[p1] = true
	doc(p1, fortiDoc("FG-IR-26-100", "2026-04-14T00:00:00", [2]string{"CVE-2026-3001", "<p>An OS command injection. This has been reported to be exploited in the wild.</p>"}))
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	got := vendorRows(t, e, fortinetFeedID)
	if len(got) != 2 || !strings.HasPrefix(got["CVE-2026-3001"], "2026-11-21T12:00") || !strings.HasPrefix(got["CVE-2025-3002"], "2025-11-14T00:00") {
		t.Fatalf("%v", got)
	}
	ims := ""
	for _, h := range o.all() {
		if h.path == p2 {
			ims = h.header.Get("If-Modified-Since")
		}
	}
	if ims != "Sat, 21 Nov 2026 05:00:00 GMT" {
		t.Errorf("If-Modified-Since %q", ims)
	}
	// the feed itself unchanged: 304, nothing read
	before := len(o.all())
	e.setNow(e.clock().Add(6 * time.Hour))
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	if n := len(o.all()) - before; n != 1 || e.feed(fortinetFeedID).Status != "ok" {
		t.Errorf("%d requests after an unchanged feed", n)
	}
}

func TestFortiGuardFeed_Shapes(t *testing.T) {
	t.Parallel()
	refs, st, err := parseFortiGuardFeed(strings.NewReader(fortiFeed(
		[2]string{"FG-IR-26-100", "https://filestore.fortinet.com/fortiguard/psirt/csaf_a_fg-ir-26-100.json"},
		[2]string{"FG-IR-26-101", "http://filestore.fortinet.com/fortiguard/psirt/csaf_a_fg-ir-26-101.json"},
		[2]string{"FG-IR-26-102", "https://filestore.fortinet.com/fortiguard/psirt/csaf_a.json?x=1"},
		[2]string{"not-an-id", "https://filestore.fortinet.com/fortiguard/psirt/csaf_b.json"},
	)))
	if err != nil || len(refs) != 1 || refs[0] != (csafRef{ID: "FG-IR-26-100", Path: "/fortiguard/psirt/csaf_a_fg-ir-26-100.json"}) || st.Rejected != 3 {
		t.Fatalf("%v %+v %v", refs, st, err)
	}
	for _, bad := range []string{`<html><body/></html>`, `<rss><channel><item>`, `not xml`} {
		if _, _, err := parseFortiGuardFeed(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCSAF_ShapesAndDates(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{`[]`, `{"document":{}}`, `{"document":{"tracking":{"id":"x"}}}`, `{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01"}}} {}`} {
		if _, err := parseCSAF(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	d, err := parseCSAF(strings.NewReader(`{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01T00:00:00Z","revision_history":[
{"date":"2026-01-05T00:00:00Z","summary":"Updated to indicate active exploitation attempts in the wild."},
{"date":"2026-01-03T00:00:00Z","summary":"Added active exploitation of CVE-2026-0002."},
{"date":"2025-12-01T00:00:00Z","summary":"Exploitation seen (a date before the release is not used)."},
{"date":"2026-01-02T00:00:00Z","summary":"Updated to say the PSIRT is not aware of exploitation."}]}},
"vulnerabilities":[{"cve":"CVE-2026-0001","threats":[{"category":"exploit_status","details":"Publicly Disclosed:No;Exploited:Yes"}]},{"cve":"cve-2026-0002"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(ciscoClaims(d)); got != "[{CVE-2026-0001 2026-01-05 00:00:00 +0000 UTC}]" {
		t.Errorf("claims %s", got)
	}
	if d.claimDate("CVE-2026-0002").Day() != 3 {
		t.Errorf("date of a named CVE: %v", d.claimDate("CVE-2026-0002"))
	}
}

func TestCiscoFeed_Shapes(t *testing.T) {
	t.Parallel()
	refs, st, err := parseCiscoFeed(strings.NewReader(ciscoFeed([2]string{"cisco-sa-a-12345678", "2026-11-20 16:00:00.0"},
		[2]string{"cisco-sa-..", "2026-11-20 16:00:00.0"}, [2]string{"cisco-sa-b-12345678", "yesterday"})))
	if err != nil || len(refs) != 1 || refs[0].Path != ciscoDocPath("cisco-sa-a-12345678") || !refs[0].Changed.Equal(time.Date(2026, 11, 20, 16, 0, 0, 0, time.UTC)) || st.Rejected != 2 {
		t.Fatalf("%v %+v %v", refs, st, err)
	}
	for _, bad := range []string{`{}`, `<rss><channel><item>`, `<html/>`} {
		if _, _, err := parseCiscoFeed(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
