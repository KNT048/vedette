package feeds

import (
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// readForms reads one text against a vendor's forms within a scope: the CVEs claimed and the sentences in no known form.
func readForms(t *testing.T, forms []claimForm, text string, scope []string) ([]string, int) {
	t.Helper()
	set := map[string]bool{}
	for _, c := range scope {
		set[c] = true
	}
	r := newClaimReader(forms, csafMaxClaimText, nil)
	r.total = len(scope)
	if err := r.read(t.Context(), text, scope, set); err != nil {
		t.Fatal(err)
	}
	got := r.result()
	return got, r.unclassified
}

func TestClaimForms_VendorsOwnSentencesOnly(t *testing.T) {
	t.Parallel()
	const a, b, c = "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"
	one, three := []string{a}, []string{a, b, c}
	// the vendors' claiming sentences, as their advisories write them
	for _, tc := range []struct {
		name  string
		forms []claimForm
		text  string
		scope []string
		want  []string
	}{
		{"Cisco attempted", ciscoForms, "The Cisco PSIRT is aware of attempted exploitation of this vulnerability.", one, one},
		{"Cisco long name, in the wild", ciscoForms, "The Cisco Product Security Incident Response Team (PSIRT) is aware of attempted exploitation of this vulnerability in the wild.", one, one},
		{"Cisco month, limited", ciscoForms, "In March 2026, the Cisco PSIRT became aware of limited exploitation of this vulnerability.", one, one},
		{"Cisco issue", ciscoForms, "The Cisco PSIRT is aware of active exploitation of this issue.", one, one},
		{"Cisco successful", ciscoForms, "The Cisco Product Security Incident Response Team (PSIRT) became aware of successful exploitation of this vulnerability in the wild after local Administrator credentials were compromised.", one, one},
		{"Cisco malicious use", ciscoForms, "The Cisco PSIRT is aware of malicious use of the vulnerability that is described in this advisory.", one, one},
		{"Cisco named, in the wild", ciscoForms, "In July 2025, the Cisco PSIRT became aware of attempted exploitation of " + a + " and " + c + " in the wild.", three, []string{a, c}},
		{"Cisco named only", ciscoForms, "The PSIRT note.\r\nIn March 2026, the Cisco PSIRT became aware of active exploitation of the vulnerabilities that are described in " + b + " and " + a + " only.", three, []string{b, a}},
		{"Cisco these", ciscoForms, "The Cisco PSIRT is aware of attempted exploitation of these vulnerabilities.", three, three},
		{"Cisco SD-WAN: a denial, then a claim", ciscoForms, "The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerabilities that are described in " + a + " and " + b + ".\r\n\r\n" +
			"In March 2026, the Cisco PSIRT became aware of active exploitation of the vulnerability that is described in " + c + " only.", three, []string{c}},
		{"Cisco: a denial in a later sentence narrows a claim about the section", ciscoForms,
			"The Cisco PSIRT is aware of attempted exploitation of the vulnerabilities that are described in this advisory.\nThe Cisco PSIRT is not aware of any malicious use of " + b + ".", three, []string{a, c}},
		{"Cisco: except as otherwise noted leaves the claims before it", ciscoForms,
			"In March 2026, the Cisco PSIRT became aware of active exploitation of the vulnerability that is described in " + c + ".\nExcept as otherwise noted previously, the Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerabilities that are described in this advisory.", three, []string{c}},
		{"Fortinet observed", fortinetForms, "A path confusion vulnerability.\n\nFortinet has observed this to be exploited in the wild.", one, one},
		{"Fortinet product", fortinetForms, "Fortinet has observed this to be exploited in the wild on FortiWeb.", one, one},
		{"Fortinet reported", fortinetForms, "<p>This has been reported to be exploited in the wild, customers are urged to apply the workaround below.</p>", one, one},
		{"Fortinet found", fortinetForms, "This vulnerability was found being exploited in the wild by two malicious FortiCloud accounts, which were locked out on 2026-01-22.", one, one},
		{"Fortinet please note", fortinetForms, "Please note that reports show this is being exploited in the wild.", one, one},
	} {
		got, unclassified := readForms(t, tc.forms, tc.text, tc.scope)
		if !slices.Equal(got, tc.want) || unclassified != 0 {
			t.Errorf("%s: %v (%d unclassified), want %v", tc.name, got, unclassified, tc.want)
		}
	}

	// Never a claim: each sentence below is a denial, a possibility, a question, a later negation or another vendor's wording. Read
	// as Cisco's section and as Fortinet's description, none claims a CVE; "known" ones are forms that claim nothing, the others are
	// counted as unclassified.
	for _, tc := range []struct {
		text  string
		known bool // a known form that claims nothing (else: unclassified)
	}{
		{"The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerability that is described in this advisory.", true},
		{"The Cisco PSIRT is aware that proof-of-concept exploit code is available for the vulnerability described in this advisory.", true},
		// a denial or a neutral note that goes on into a claim is unclassified, never swallowed by the denial's form
		{"The Cisco PSIRT is not aware of malicious use of " + a + ", but is aware of active exploitation of " + b + ".", false},
		{"The Cisco PSIRT is not aware of any malicious use of " + a + ", but is aware of active exploitation of " + b + " in the wild.", false},
		{"The Cisco PSIRT is aware that proof-of-concept exploit code is available for this vulnerability and is aware of active exploitation in the wild.", false},
		{"Exploitation requires an authenticated session, and Fortinet has observed this to be exploited in the wild.", false},
		{"The vulnerability can be exploited via the GUI and has been exploited in the wild on FortiOS.", false},
		{"The PSIRT became aware of attempted exploitation of " + a + " and is not aware of malicious use of " + b + ".", false},
		{"The Cisco PSIRT is aware of attempted exploitation of " + a + " and is not aware of malicious use of " + b + ".", false},
		{"The Cisco PSIRT is aware of attempted exploitation of one of the vulnerabilities that are described in this advisory.", false},
		{"The Cisco PSIRT is aware of attempted exploitation of the vulnerabilities that are described in this advisory, and Cisco is not aware of malicious use of " + c + ".", false},
		{"This vulnerability was not exploited in the wild.", false},
		{"The issue hasn't been exploited in the wild.", false},
		{"This vulnerability has never been exploited in the wild.", false},
		{"There are no indications that this vulnerability has been exploited in the wild.", false},
		{"There are no indications that " + a + " and the related " + b + " have been exploited in the wild.", false},
		{"Microsoft has not seen " + a + " and its variant " + b + " exploited in the wild.", false},
		{"There is no sign that this has been exploited in attacks.", false},
		{"Fortinet has observed no exploitation of this issue.", false},
		{"Exploited in the wild: No", false},
		{"Exploited in the wild - No", false},
		{"Exploited in the wild: Not yet observed", false},
		{"Exploited in the wild: Unconfirmed", false},
		{"Known to be exploited in the wild: No.", false},
		{"Exploitation in the wild has not been observed.", false},
		{"Active exploitation has not been reported at this time.", false},
		{"In-the-wild exploitation has not been observed by Fortinet.", false},
		{"This vulnerability could be exploited by a remote unauthenticated attacker.", false},
		{"The vulnerability can be exploited by sending a crafted request.", false},
		{"Apply the update to prevent the vulnerability from being exploited in the wild.", false},
		{"The PSIRT is aware of public proof-of-concept code that could enable exploitation of this vulnerability.", false},
		{"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code.", false},
		{"What might an attacker gain from successful exploitation of this vulnerability?", false},
		{"Repeated attempts to exploit this vulnerability could cause the device to reload.", false},
		{"Exploitation attempts are blocked by IPS signature 1234.", false},
		{"Rapid7 is monitoring for exploitation attempts against this flaw.", false},
		{"We expect widespread exploitation of this vulnerability in the coming days.", false},
		{"The risk of active exploitation is low.", false},
		{"Organizations are at risk of active exploitation.", false},
		{"Has " + a + " been exploited in the wild?", false},
		{"Is this vulnerability known to be exploited in the wild?", false},
		// wordings other vendors use for a real claim: not Cisco's or Fortinet's forms, so they are counted, never read
		{"The flaw was exploited in-the-wild in October.", false},
		{"The flaw was exploited as a 0-day.", false},
		{"The vulnerability has been exploited by a state actor.", false},
		{"We observed exploitation of " + a + " across several sectors.", false},
		{"Microsoft is aware of limited, targeted attacks that attempt to exploit this vulnerability.", false},
		{"Exploitation Detected", false},
		{"In devices with no patch applied, active exploitation has been observed.", false},
	} {
		for _, f := range []struct {
			name  string
			forms []claimForm
		}{{"cisco", ciscoForms}, {"fortinet", fortinetForms}} {
			got, unclassified := readForms(t, f.forms, tc.text, three)
			if len(got) != 0 {
				t.Errorf("%s: %q claims %v", f.name, tc.text, got)
			}
			if f.name == "cisco" && tc.known != (unclassified == 0) {
				t.Errorf("%s: %q: %d unclassified, known form %v", f.name, tc.text, unclassified, tc.known)
			}
			if f.name == "fortinet" && unclassified != 1 && !strings.HasPrefix(tc.text, "The Cisco") {
				t.Errorf("%s: %q: %d unclassified", f.name, tc.text, unclassified)
			}
		}
	}
	// "this vulnerability" in a section of several CVEs names none of them, and a CVE id inside a link target is not the subject
	for _, text := range []string{
		"The Cisco PSIRT is aware of attempted exploitation of this vulnerability.",
		"The Cisco PSIRT is aware of attempted exploitation of this vulnerability [\"https://www.cve.org/CVERecord?id=" + b + "\"].",
	} {
		if got, unclassified := readForms(t, ciscoForms, text, three); len(got) != 0 || unclassified != 1 {
			t.Errorf("%q in a section of three: %v, %d", text, got, unclassified)
		}
	}
	// a claim about the section and a denial about the section contradict each other: no claim, counted
	if got, unclassified := readForms(t, ciscoForms, "The Cisco PSIRT is aware of attempted exploitation of these vulnerabilities.\n"+
		"The Cisco PSIRT is not aware of any malicious use of the vulnerabilities that are described in this advisory.", three); len(got) != 0 || unclassified != 1 {
		t.Errorf("claimed and denied as a whole: %v, %d", got, unclassified)
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
	want := "[{CVE-2026-0001 2026-11-10 16:00:00 +0000 UTC true} {CVE-2026-0002 2026-07-16 14:00:00 +0000 UTC true}]"
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
	if st := e.feed(msrcFeedID); st.Status != "error" || !strings.Contains(deref(st.Error), "fewer than the 150 of the last good list") || len(vendorRows(t, e, msrcFeedID)) != 150 {
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
	return fmt.Sprintf(`{"document":{"tracking":{"id":%q,"initial_release_date":%q,"current_release_date":"2026-11-21T23:59:59+00:00","revision_history":[%s]},
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
	const one, two, gone, old, three = "cisco-sa-one-AbC12345", "cisco-sa-two-XyZ98765", "cisco-sa-gone-Qq111111", "cisco-sa-old-Zz000000", "cisco-sa-three-Tt333333"
	o.body(ciscoFeedPath, `"i1"`, ciscoFeed(
		[2]string{one, "2026-11-20 16:00:00.0"},
		[2]string{three, "2026-11-20 18:00:00.0"},
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
	o.body(ciscoDocPath(three), `"d5"`, ciscoDoc(three, "2026-11-20T18:00:00+00:00", "The Cisco PSIRT is aware of attempted exploitation of CVE-2026-2002 in the wild.", nil, "CVE-2026-2002"))
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

	// six hours later "two" and "one" changed, the feed dating both changes before the box's last pull (a change that reached the
	// feed late is still read: the box compares the feed's own times); "two" no longer claims its CVE (a correction) and goes;
	// "one" no longer claims CVE-2026-2002, which "three" (not read again) still claims, so the row stays with that link
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(ciscoFeedPath, `"i2"`, ciscoFeed([2]string{two, "2026-11-21 01:00:00.0"}, [2]string{one, "2026-11-21 02:00:00.0"}, [2]string{three, "2026-11-20 18:00:00.0"},
		[2]string{old, "2026-06-01 16:00:00.0"}))
	o.body(ciscoDocPath(two), `"d3"`, ciscoDoc(two, "2026-09-25T16:00:00+00:00", "The Cisco PSIRT is not aware of any malicious use of this vulnerability.", nil, "CVE-2026-2003"))
	o.body(ciscoDocPath(one), `"d6"`, ciscoDoc(one, "2026-11-18T16:00:00+00:00", "The Cisco PSIRT is not aware of any malicious use of the vulnerabilities that are described in this advisory.", nil,
		"CVE-2026-2001", "CVE-2026-2002"))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	got = vendorRows(t, e, ciscoFeedID)
	if len(got) != 1 || got["CVE-2026-2002"] != `2026-11-20T16:00 https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/`+three+` {"advisory":"`+three+`"} 1` ||
		o.count(ciscoDocPath(one)) != 2 || o.count(ciscoDocPath(two)) != 2 || o.count(ciscoDocPath(three)) != 1 || o.count(ciscoDocPath(old)) != 1 {
		t.Fatalf("after the corrections: %v; %d, %d, %d reads", got, o.count(ciscoDocPath(one)), o.count(ciscoDocPath(two)), o.count(ciscoDocPath(three)))
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
	// as filestore.fortinet.com: 304 only to the exact Last-Modified it gave
	doc := func(path, lastModified, body string) {
		o.serve(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-Modified-Since") == lastModified {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", lastModified)
			_, _ = w.Write([]byte(body))
		})
	}
	const lm1, lm2 = "Tue, 14 Apr 2026 00:00:00 GMT", "Fri, 14 Nov 2025 08:00:00 GMT"
	doc(p1, lm1, fortiDoc("FG-IR-26-100", "2026-04-14T00:00:00", [2]string{"CVE-2026-3001", "<p>An OS command injection may allow an attacker to run commands.</p>"}))
	doc(p2, lm2, fortiDoc("FG-IR-25-910", "2025-11-14T00:00:00",
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
	doc(p1, "Sat, 21 Nov 2026 09:00:00 GMT", fortiDoc("FG-IR-26-100", "2026-04-14T00:00:00", [2]string{"CVE-2026-3001", "<p>An OS command injection. This has been reported to be exploited in the wild.</p>"}))
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
	if ims != lm2 {
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
	if cs, _, _ := ciscoClaims(t.Context(), d, nil); fmt.Sprint(cs) != "[{CVE-2026-0001 2026-01-05 00:00:00 +0000 UTC true}]" {
		got := fmt.Sprint(cs)
		t.Errorf("claims %s", got)
	}
	if got := d.claimDates([]string{"CVE-2026-0002"}, nil)["CVE-2026-0002"]; got.Day() != 3 {
		t.Errorf("date of a named CVE: %v", got)
	}
}

func TestCiscoFeed_Shapes(t *testing.T) {
	t.Parallel()
	refs, st, err := parseCiscoFeed(strings.NewReader(ciscoFeed([2]string{"cisco-sa-a-12345678", "2026-11-20 16:00:00.0"},
		[2]string{"cisco-sa-..", "2026-11-20 16:00:00.0"}, [2]string{"cisco-sa-b-12345678", "yesterday"})))
	if err != nil || len(refs) != 1 || refs[0].Path != ciscoDocPath("cisco-sa-a-12345678") || refs[0].Changed != "2026-11-20 16:00:00.0" || st.Rejected != 2 {
		t.Fatalf("%v %+v %v", refs, st, err)
	}
	for _, bad := range []string{`{}`, `<rss><channel><item>`, `<html/>`} {
		if _, _, err := parseCiscoFeed(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// allocated is how many bytes f allocates.
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// Every count bound holds while a document is read, before anything is kept: a document of millions of empty elements under the
// byte cap is refused having allocated little (a decode into slices allocated gigabytes before checking).
func TestVendorParsers_BoundsHoldWhileReading(t *testing.T) { //nolint:paralleltest // measures allocations
	elems := func(n int) string { return strings.TrimSuffix(strings.Repeat("{},", n), ",") }
	const n = (csafMaxBytes - 200) / 3 // about 1.4 million empty elements
	for name, doc := range map[string]string{
		"vulnerabilities": `{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01"}},"vulnerabilities":[` + elems(n) + `]}`,
		"notes":           `{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01"},"notes":[` + elems(n) + `]}}`,
		"revisions":       `{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01","revision_history":[` + elems(n) + `]}}}`,
		"threats":         `{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01"}},"vulnerabilities":[{"cve":"CVE-2026-1","threats":[` + elems(n) + `]}]}`,
	} {
		var err error
		if a := allocated(func() { _, err = parseCSAF(strings.NewReader(doc)) }); err == nil || !strings.Contains(err.Error(), "more than") || a > 256<<20 {
			t.Errorf("%s: %v, %d MB allocated", name, err, a>>20)
		}
	}
	row := `{"value":[{"cveNumber":"CVE-2026-1","releaseDate":"2026-01-01T00:00:00Z","exploited":"Yes","revisions":[` + elems((msrcMaxBytes-200)/3) + `]}]}`
	var err error
	if a := allocated(func() { _, err = parseMSRCExploited(strings.NewReader(row)) }); err == nil || !strings.Contains(err.Error(), "more than 500 revisions") || a > 256<<20 {
		t.Errorf("msrc: %v, %d MB allocated", err, a>>20)
	}

	// long revision summaries are cut as they are read, and each revision is read once for all the CVEs a document claims
	var revs, vulns []string
	long := strings.Repeat("Updated to indicate active exploitation attempts in the wild of CVE-2026-0001 ", 200) // 16 KB
	for i := range csafMaxVulns {
		revs = append(revs, fmt.Sprintf(`{"date":"2026-01-%02dT00:00:00Z","summary":%q}`, 1+i%28, long))
		vulns = append(vulns, fmt.Sprintf(`{"cve":"CVE-2026-%04d","threats":[{"category":"exploit_status","details":"Exploited:Yes"}]}`, 1000+i))
	}
	d, err := parseCSAF(strings.NewReader(`{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01T00:00:00Z","revision_history":[` +
		strings.Join(revs, ",") + `]}},"vulnerabilities":[` + strings.Join(vulns, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Revisions[0].Summary) != csafMaxRevSummary {
		t.Errorf("summary of %d bytes kept", len(d.Revisions[0].Summary))
	}
	if got, _, _ := ciscoClaims(t.Context(), d, nil); len(got) != csafMaxVulns || got[0].Date.Day() != 1 {
		t.Errorf("%d claims, first %+v", len(got), got[:min(1, len(got))])
	}
}

// slowShapes are the documents that once cost minutes: a section of many CVEs claimed again and again by plural sentences, the
// same with sentences in no known form, and many revisions that each name many CVEs. k scales the document.
func slowShapes(k int) map[string]string {
	cves := func(n, from int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("CVE-2026-%05d", from+i)
		}
		return out
	}
	vulns := func(ids []string) string {
		var b []string
		for _, c := range ids {
			b = append(b, fmt.Sprintf(`{"cve":%q}`, c))
		}
		return strings.Join(b, ",")
	}
	doc := func(note string, revs []string, ids []string) string {
		return fmt.Sprintf(`{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01T00:00:00Z","revision_history":[%s]},`+
			`"notes":[{"title":"Exploitation and Public Announcements","text":%q}]},"vulnerabilities":[%s]}`, strings.Join(revs, ","), note, vulns(ids))
	}
	ids := cves(csafMaxVulns, 10000)
	named := strings.Join(cves(140, 90000), " ")
	var revs []string
	for i := range 4 * k {
		revs = append(revs, fmt.Sprintf(`{"date":"2026-02-%02dT00:00:00Z","summary":"exploited %s"}`, 1+i%28, named))
	}
	return map[string]string{
		"plural claims":   doc(strings.Repeat("The Cisco PSIRT is aware of attempted exploitation of these vulnerabilities. ", 40*k), nil, ids),
		"unclassified":    doc(strings.Repeat("These vulnerabilities are exploited in the wild. ", 40*k), nil, ids),
		"named revisions": doc("The Cisco PSIRT is aware of attempted exploitation of these vulnerabilities.", revs, ids),
		"named unclaimed": doc(strings.Repeat("Cisco notes "+named+" exploited elsewhere. ", 4*k), nil, ids),
	}
}

// The work of reading a document's claims (sentences, CVE ids, revisions, claims) grows with the document's size only: doubling a
// slow shape at most doubles the steps, and the steps stay within a small multiple of the document's bytes. Counted, not timed.
func TestCSAFClaims_WorkIsLinearInTheDocument(t *testing.T) {
	t.Parallel()
	small, large := slowShapes(8), slowShapes(16)
	for name := range small {
		steps := func(doc string) int {
			d, err := parseCSAF(strings.NewReader(doc))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var w claimWork
			if _, _, err := ciscoClaims(t.Context(), d, &w); err != nil {
				t.Fatal(err)
			}
			return w.steps
		}
		s, l := steps(small[name]), steps(large[name])
		t.Logf("%s: %d steps for %d bytes, %d for %d", name, s, len(small[name]), l, len(large[name]))
		if l > 2*s+csafMaxVulns || l > len(large[name])/4 {
			t.Errorf("%s: %d steps for %d bytes, %d for %d", name, s, len(small[name]), l, len(large[name]))
		}
	}
}

// A document cut by the connection fails the pull (it is asked again next time), where a bad document is only counted.
func TestFortinet_ACutConnectionFailsThePull(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(fortinetFeedID)
	e.mirror(fortinetFeedID, o.url(fortiFeedPath))
	const p1, p2 = "/fortiguard/psirt/csaf_one_fg-ir-26-100.json", "/fortiguard/psirt/csaf_two_fg-ir-25-910.json"
	o.body(fortiFeedPath, `"r1"`, fortiFeed([2]string{"FG-IR-26-100", "https://filestore.fortinet.com" + p1}, [2]string{"FG-IR-25-910", "https://filestore.fortinet.com" + p2}))
	o.body(p1, `"d1"`, `{"document": not json`)
	o.serve(p2, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "5000")
		_, _ = w.Write([]byte(`{"document":{"tracking":{"id":"FG-IR-25-910"`))
	})
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(fortinetFeedID); st.Status != "error" || st.Records != nil {
		t.Fatalf("a cut document: %+v %q", st, deref(st.Error))
	}
	o.serve(p2, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fortiDoc("FG-IR-25-910", "2025-11-14T00:00:00", [2]string{"CVE-2025-3002", "Fortinet has observed this to be exploited in the wild."})))
	})
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(fortinetFeedID); st.Status != "ok" || st.Records == nil || *st.Records != 1 || !strings.Contains(deref(st.Error), "1 of 2") {
		t.Fatalf("the bad document counted, the other read: %+v %q", st, deref(st.Error))
	}
}

// An exploit_status threat in no known form does not make a document "structured": its text is still read, and the value is counted.
func TestCSAF_UnknownExploitStatusStillReadsTheText(t *testing.T) {
	t.Parallel()
	d, err := parseCSAF(strings.NewReader(`{"document":{"tracking":{"id":"FG-IR-26-1","initial_release_date":"2026-01-01T00:00:00"}},"vulnerabilities":[
{"cve":"CVE-2026-0001","threats":[{"category":"exploit_status","details":"Exploitation: Detected"}]},
{"cve":"CVE-2026-0002","references":[{"summary":"Fortinet has observed this to be exploited in the wild."}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cs, unclassified, err := fortinetClaims(t.Context(), d, nil)
	if err != nil || len(cs) != 1 || cs[0].CVE != "CVE-2026-0002" || cs[0].Flag || unclassified != 1 {
		t.Errorf("%+v %d %v", cs, unclassified, err)
	}
}

// A Cisco copy older than the change its feed announced is read again at the next pull, until the document catches up.
func TestCisco_ADocumentOlderThanItsFeedIsReadAgain(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(ciscoFeedID)
	e.mirror(ciscoFeedID, o.url(ciscoFeedPath))
	const id = "cisco-sa-lag-Ab123456"
	o.body(ciscoFeedPath, `"f"`, ciscoFeed([2]string{id, "2026-11-21 05:00:00.0"}))
	doc := func(current string) string {
		return strings.Replace(ciscoDoc(id, "2026-11-01T16:00:00+00:00", "The Cisco PSIRT is aware of attempted exploitation of this vulnerability.", nil, "CVE-2026-4001"),
			`"current_release_date":"2026-11-21T23:59:59+00:00"`, `"current_release_date":"`+current+`"`, 1)
	}
	for i, c := range []struct {
		current string
		reads   int
	}{
		{"2026-11-20T00:00:00+00:00", 1}, // the old copy: read, not marked
		{"2026-11-20T00:00:00+00:00", 2}, // read again
		{"2026-11-21T05:00:00+00:00", 3}, // the change arrived: read and marked
		{"2026-11-21T05:00:00+00:00", 3}, // not read again
	} {
		o.body(ciscoDocPath(id), fmt.Sprintf(`"d%d"`, i), doc(c.current))
		e.setNow(e.clock().Add(6 * time.Hour))
		if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
			t.Fatal(err)
		}
		if n := o.count(ciscoDocPath(id)); n != c.reads {
			t.Errorf("pull %d: %d reads, want %d", i+1, n, c.reads)
		}
	}
}

// A row whose advisory no longer claims its CVE moves to the advisory that now does, read in the same pull; when that one takes
// it back too, the row goes. A sentence in no known form is told on the pull's note, never as a rejected row.
func TestCisco_ALinkMovesToTheClaimingDocument(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(ciscoFeedID)
	e.mirror(ciscoFeedID, o.url(ciscoFeedPath))
	const a, b, x = "cisco-sa-aaa-Aa111111", "cisco-sa-bbb-Bb222222", "CVE-2026-5001"
	claim := "The Cisco PSIRT is aware of attempted exploitation of " + x + " in the wild."
	deny := "The Cisco PSIRT is not aware of any malicious use of " + x + "."
	o.body(ciscoFeedPath, `"f1"`, ciscoFeed([2]string{a, "2026-11-20 10:00:00.0"}))
	o.body(ciscoDocPath(a), `"a1"`, ciscoDoc(a, "2026-11-20T10:00:00+00:00", claim+"\nCisco has seen this vulnerability used by a botnet exploit kit.", nil, x))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(ciscoFeedID)
	if got := vendorRows(t, e, ciscoFeedID)[x]; !strings.Contains(got, a) || st.Status != "ok" ||
		!strings.Contains(deref(st.Error), "1 sentence about exploitation in no form Vedette knows (first in "+a+")") || strings.Contains(deref(st.Error), "rejected") {
		t.Fatalf("%q; %+v %q", got, st, deref(st.Error))
	}

	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(ciscoFeedPath, `"f2"`, ciscoFeed([2]string{b, "2026-11-21 08:00:00.0"}, [2]string{a, "2026-11-21 07:00:00.0"}))
	o.body(ciscoDocPath(a), `"a2"`, ciscoDoc(a, "2026-11-20T10:00:00+00:00", deny, nil, x))
	o.body(ciscoDocPath(b), `"b1"`, ciscoDoc(b, "2026-11-21T08:00:00+00:00", claim, nil, x))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, ciscoFeedID)[x]; !strings.Contains(got, "/"+b+` {"advisory":"`+b+`"}`) || !strings.HasPrefix(got, "2026-11-20T10:00") {
		t.Fatalf("moved: %q", got)
	}

	e.setNow(e.clock().Add(6 * time.Hour))
	o.body(ciscoFeedPath, `"f3"`, ciscoFeed([2]string{b, "2026-11-21 13:00:00.0"}, [2]string{a, "2026-11-21 07:00:00.0"}))
	o.body(ciscoDocPath(b), `"b2"`, ciscoDoc(b, "2026-11-21T08:00:00+00:00", deny, nil, x))
	if err := e.svc.Fetch(t.Context(), ciscoFeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, ciscoFeedID); len(got) != 0 || o.count(ciscoDocPath(a)) != 2 {
		t.Fatalf("taken back: %v, %d reads of a", got, o.count(ciscoDocPath(a)))
	}
}

// A document whose compressed body is corrupt is a bad document (counted), not a failed pull.
func TestFortinet_ACorruptCompressedDocumentIsCounted(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(fortinetFeedID)
	e.mirror(fortinetFeedID, o.url(fortiFeedPath))
	const p1, p2 = "/fortiguard/psirt/csaf_one_fg-ir-26-100.json", "/fortiguard/psirt/csaf_two_fg-ir-25-910.json"
	o.body(fortiFeedPath, `"r1"`, fortiFeed([2]string{"FG-IR-26-100", "https://filestore.fortinet.com" + p1}, [2]string{"FG-IR-25-910", "https://filestore.fortinet.com" + p2}))
	o.serve(p1, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("this is not a gzip stream"))
	})
	o.body(p2, `"d2"`, fortiDoc("FG-IR-25-910", "2025-11-14T00:00:00", [2]string{"CVE-2025-3002", "Fortinet has observed this to be exploited in the wild."}))
	if err := e.svc.Fetch(t.Context(), fortinetFeedID); err != nil {
		t.Fatal(err)
	}
	if st := e.feed(fortinetFeedID); st.Status != "ok" || st.Records == nil || *st.Records != 1 || !strings.Contains(deref(st.Error), "1 of 2") {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
}
