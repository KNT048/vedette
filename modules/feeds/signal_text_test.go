package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	signaldata "github.com/knt048/vedette/content/signals"
)

// readProse reads one text (title "", plain or HTML) against a prose source's forms: the CVEs claimed and the sentences counted.
func readProse(t *testing.T, forms []claimForm, text string) ([]string, int) {
	t.Helper()
	got, n, err := proseClaims(t.Context(), forms, "", proseText(text))
	if err != nil {
		t.Fatal(err)
	}
	return got, n
}

func TestProseForms_ClaimsOnlyWhatASentenceStatesAsAFact(t *testing.T) {
	t.Parallel()
	const a, b = "CVE-2026-1001", "CVE-2026-1002"
	for _, tc := range []struct {
		name  string
		forms []claimForm
		text  string
		want  []string
		count int // sentences in no known form
	}{
		// the sources' own claiming sentences
		{"Rapid7 relays a confirmation", rapid7Forms, "Also, Mandiant/Google Threat Intelligence confirmed in-the-wild exploitation of <a href=\"https://www.cve.org/CVERecord?id=" + a + "\">" + a + "</a> by a state-linked threat actor as early as September 2026.", []string{a}, 0},
		{"Rapid7 detected", rapid7Forms, "On November 13, 2026, Rapid7 MDR detected exploitation of " + a + " against a wiki server at a customer.", []string{a}, 0},
		{"Rapid7 now exploited", rapid7Forms, a + " is now being actively exploited in the wild against both affected products.", []string{a}, 0},
		{"Rapid7 title list", rapid7Forms, "More VPN zero-days exploited in the wild (" + a + ", " + b + ")", []string{a, b}, 0},
		{"Rapid7 Patch Tuesday", rapid7Forms, "Next up is " + a + ", an exploited-in-the-wild spoofing vulnerability.", []string{a}, 0},
		{"GTI attributes", gtiForms, "GTIG attributes the zero-day exploitation of " + a + " and the subsequent deployment of SAWFLY to the suspected PRC-nexus espionage actor ARMORY CASTLE (formerly tracked as UNC5221).", []string{a}, 0},
		{"GTI identified a zero-day", gtiForms, "In late September 2026, Mandiant Consulting and Google Threat Intelligence Group (GTIG) identified active, in-the-wild exploitation of a zero-day vulnerability (" + a + ") affecting Citrix NetScaler ADC.", []string{a}, 0},
		{"GTI actor exploited", gtiForms, "Mandiant published a post in which the suspected PRC-nexus threat actor ARMORY CASTLE (formerly tracked as UNC5221) exploited " + a + ", a zero-day vulnerability in BeyondTrust Remote Support.", []string{a}, 0},
		{"GTI campaign, the month May", gtiForms, "In June 2026, we reported a UNC6240 campaign that exploited " + a + " as a zero-day between May 27 and June 9, 2026.", []string{a}, 0},
		{"GTI actively exploiting", gtiForms, "According to vendor disclosures, threat actors are also actively exploiting a second zero-day vulnerability (" + a + ").", []string{a}, 0},
		{"Chrome", chromeForms, "<p>Google is aware that an exploit for <a href=\"https://www.cve.org/CVERecord?id=" + a + "\">" + a + "</a>&nbsp;exists in the wild.</p>", []string{a}, 0},
		{"Chrome reports", chromeForms, "Google is aware of reports that an exploit for " + a + " exists in the wild.", []string{a}, 0},
		{"Android", androidForms, "<aside class=\"note\"><b>Note</b>: There are indications that " + a + " may be under limited, targeted exploitation.</aside>", []string{a}, 0},

		// only the subject is claimed, never another id of the sentence
		{"another CVE in the tail: no guess", rapid7Forms, "Rapid7 confirmed exploitation of " + a + ", which attackers chain with " + b + ".", nil, 1},
		{"an apposition before the verb", rapid7Forms, a + ", a patch bypass for " + b + ", is being actively exploited in the wild.", nil, 1},
		{"a new clause after the list", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " is a related information disclosure fixed in the same release.", nil, 1},
		{"a new clause after and", gtiForms, "Mandiant observed exploitation of " + a + " and " + b + " is a separate unrelated bug.", nil, 1},
		{"or is doubt", rapid7Forms, "Rapid7 has observed exploitation of " + a + " or " + b + ", but we are still determining which.", nil, 1},
		{"or alone is doubt", rapid7Forms, "Rapid7 has observed exploitation of " + a + " or " + b + ".", nil, 1},
		{"a parenthesis between the ids", rapid7Forms, a + " (patched in March) and " + b + " were exploited in the wild.", nil, 1},
		{"a list both claimed", rapid7Forms, a + " and " + b + " were exploited in the wild.", []string{a, b}, 0},
		{"a list, then a preposition", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + " against Confluence servers.", []string{a, b}, 0},
		{"a list by an actor", rapid7Forms, "Rapid7 has observed exploitation of " + a + " and " + b + " by a state-sponsored actor.", []string{a, b}, 0},
		{"a list, in a component, then allows", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " in a separate component allows an authenticated attacker to read files.", nil, 1},
		{"a list, in the web interface, then allows", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + " in the web interface allows privilege escalation.", nil, 1},
		{"a list, in the same release, then is", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " in the same release is a separate unrelated bug.", nil, 1},
		{"a list, on an appliance, then affects", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " on the same appliance affects every release.", nil, 1},
		{"a list, since a version, then enables", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " since version 2.0 enables remote code execution.", nil, 1},
		{"a list, from a researcher, then lets", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " from the same researcher lets an attacker read files.", nil, 1},
		{"a list, via a request, then allows", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + " via a crafted request allows file reads.", nil, 1},
		{"a list, against servers, then allows", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + " against servers in the region allows file reads.", nil, 1},
		{"a list as zero-days", rapid7Forms, a + " and " + b + " have been exploited in the wild as zero-days.", []string{a, b}, 0},
		{"a list, then allows", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " allows an authenticated attacker to read files.", nil, 1},
		{"a list, then affects", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " affects the same release.", nil, 1},
		{"a list, then enables", gtiForms, "Mandiant observed exploitation of " + a + " and " + b + " enables privilege escalation.", nil, 1},
		{"a list, then exists", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + " exists in the same release.", nil, 1},
		{"a list, then also exists", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + ", and " + b + " also exists in the same component.", nil, 1},
		{"a list, then which", rapid7Forms, "Rapid7 MDR has observed exploitation of " + a + " and " + b + ", which is a separate unrelated bug.", nil, 1},
		{"a bypass of an older one", rapid7Forms, "Rapid7 has observed exploitation of a bypass of the fix for an older vulnerability (" + a + ").", nil, 1},
		{"a related one", gtiForms, "Attackers exploited a vulnerability related to (" + a + ").", nil, 1},
		{"the vulnerability part denied", rapid7Forms, "Rapid7 has observed exploitation of an older flaw, but has not seen exploitation of the newly disclosed vulnerability (" + a + ").", nil, 1},
		{"not this vulnerability", gtiForms, "Attackers exploited a different vulnerability, not the recently disclosed authentication bypass (" + a + "), to gain access.", nil, 1},
		{"a CVE line next to a claim", chromeForms, "<p>" + b + ": Use after free in V8.</p><p>Google is aware that an exploit for " + a + " exists in the wild.</p>", []string{a}, 0},

		// a negation or a hedge in an open part: no claim, and counted
		{"has not observed", rapid7Forms, "Rapid7 has not observed exploitation of " + a + ".", nil, 1},
		{"not aware, but aware", rapid7Forms, "Rapid7 is not aware of exploitation of " + a + ", but is aware of exploitation of " + b + ".", nil, 1},
		{"claim, but not the other", rapid7Forms, a + " is being exploited in the wild, but " + b + " is not.", nil, 1},
		{"no evidence", rapid7Forms, "There is no evidence that " + a + " has been exploited in the wild.", nil, 1},
		{"if", rapid7Forms, "If " + a + " is exploited in the wild, attackers gain root.", nil, 1},
		{"a lab", rapid7Forms, a + " has been exploited in our lab.", nil, 1},
		{"we believe", rapid7Forms, "We think this is " + a + ", which was reported last month as being exploited in-the-wild as a zero-day.", nil, 1},
		{"should monitor", gtiForms, "Organizations should monitor for observed exploitation of " + a + ".", nil, 1},
		{"Chrome denied", chromeForms, "Google is not aware that an exploit for " + a + " exists in the wild.", nil, 1},
		{"Android none", androidForms, "There are no indications that " + a + " may be under limited, targeted exploitation.", nil, 1},

		// refutation, speculation, a contest, a failure
		{"were incorrect", rapid7Forms, "Initial reports that " + a + " was exploited in the wild were incorrect.", nil, 1},
		{"turned out to be wrong", rapid7Forms, "The report that " + a + " had been exploited in the wild turned out to be wrong.", nil, 1},
		{"speculation", rapid7Forms, "There is speculation that " + a + " is being exploited in the wild.", nil, 1},
		{"reportedly", rapid7Forms, "Reportedly, " + a + " has been exploited in the wild.", nil, 1},
		{"in a CTF", rapid7Forms, "Security researchers reported exploitation of " + a + " in a CTF competition.", nil, 1},
		{"all of which failed", rapid7Forms, "Rapid7 observed attempted exploitation of " + a + ", all of which failed.", nil, 1},

		// words that are no hedge where they stand
		{"but a patch", rapid7Forms, a + " is being actively exploited in the wild, but a patch is available.", []string{a}, 0},
		{"but limited", rapid7Forms, "Rapid7 has observed exploitation of " + a + ", but exploitation appears limited so far.", []string{a}, 0},
		{"quiet but", rapid7Forms, "The vendor stayed quiet but Rapid7 MDR has observed exploitation of " + a + " against several customers.", []string{a}, 0},
		{"contrary to claims", rapid7Forms, "Rapid7 has confirmed exploitation of " + a + ", contrary to the vendor's claims.", []string{a}, 0},
		{"failed logins", rapid7Forms, "Rapid7 MDR detected exploitation of " + a + " following failed login attempts.", []string{a}, 0},
		{"the wrong hands", rapid7Forms, a + " has been exploited in the wild to put sensitive data in the wrong hands.", []string{a}, 0},
		{"claims that", rapid7Forms, "One forum post claims that " + a + " has been exploited in the wild.", nil, 1},
		{"a forum user claims", rapid7Forms, "A forum user claims " + a + " is being exploited in the wild.", nil, 1},
		{"the seller claimed", rapid7Forms, "The seller claimed " + a + " had been exploited in the wild as a zero-day.", nil, 1},
		{"posts claim", rapid7Forms, "Several posts on X claim " + a + " has been exploited in the wild.", nil, 1},
		{"someone says", gtiForms, "A broker says threat actors exploited " + a + ".", nil, 1},
		{"which failed", rapid7Forms, "Rapid7 observed attempted exploitation of " + a + ", which failed.", nil, 1},
		{"the attempts failed", rapid7Forms, "Rapid7 observed attempted exploitation of " + a + "; the attempts failed.", nil, 1},
		{"every attempt failed", rapid7Forms, "Rapid7 observed attempted exploitation of " + a + ", but every attempt failed.", nil, 1},
		// the usual way these blogs name an exploited zero-day
		{"previously unknown", gtiForms, "Mandiant identified exploitation of a previously unknown vulnerability (" + a + ") in Ivanti Connect Secure.", []string{a}, 0},
		{"previously undisclosed zero-day", gtiForms, "GTIG identified in-the-wild exploitation of a previously undisclosed zero-day vulnerability (" + a + ").", []string{a}, 0},
		{"authentication bypass vulnerability", gtiForms, "Mandiant observed exploitation of an authentication bypass vulnerability (" + a + ") against VPN appliances.", []string{a}, 0},
		{"authentication bypass", gtiForms, "Attackers exploited an authentication bypass (" + a + ").", []string{a}, 0},
		{"another zero-day", gtiForms, "Threat actors exploited another zero-day vulnerability (" + a + ") to gain access.", []string{a}, 0},
		{"a different zero-day", gtiForms, "UNC5221 exploited a different zero-day vulnerability (" + a + ").", []string{a}, 0},

		// wording no form holds: counted, never read
		{"could be exploited", rapid7Forms, a + " could be exploited by a remote attacker.", nil, 1},
		{"was not exploited", rapid7Forms, a + " was not exploited in the wild.", nil, 1},
		{"successful exploitation could", rapid7Forms, "Successful exploitation of " + a + " could allow code execution.", nil, 1},
		{"researchers exploited", gtiForms, "Researchers exploited " + a + " in a demonstration.", nil, 1},
		{"could have exploited", gtiForms, "The threat actor could have exploited " + a + ".", nil, 1},
		{"not actively exploiting", gtiForms, "Threat actors are not actively exploiting " + a + ".", nil, 1},
		{"a question", rapid7Forms, "Has " + a + " been exploited in the wild?", nil, 1},
		{"CISA added", rapid7Forms, "CISA added " + a + " to its Known Exploited Vulnerabilities (KEV) catalog, citing evidence of active exploitation.", nil, 1},

		// passed over: no CVE id, or not about exploitation as a fact
		{"no CVE", rapid7Forms, "This vulnerability is being actively exploited in the wild.", nil, 0},
		{"may exploit", rapid7Forms, "A malicious actor may exploit " + a + " without credentials.", nil, 0},
	} {
		got, n := readProse(t, tc.forms, tc.text)
		if !slices.Equal(got, tc.want) || n != tc.count {
			t.Errorf("%s: claims %v (%d in no form), want %v (%d)", tc.name, got, n, tc.want, tc.count)
		}
	}
}

func TestAppleForms_TheRecordsOwnCVEOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"An out-of-bounds write. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.", true},
		{"Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.", true},
		{"Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 17.", true},
		{"Apple is not aware of a report that this issue may have been exploited.", false},
		{"Apple is aware of a report that this issue may have been exploited in a lab.", false},
		{"A logic issue was addressed with improved checks. An attacker may be able to cause unexpected app termination.", false},
		{"", false},
	} {
		got, err := appleClaimed(t.Context(), "CVE-2026-1001", tc.text)
		if err != nil || got != tc.want {
			t.Errorf("%q: %v %v", tc.text, got, err)
		}
	}
}

func TestProseText_InlineTagsKeepTheSentence(t *testing.T) {
	t.Parallel()
	in := "<h2>Overview</h2><p>On <b>November&nbsp;19</b>, a <a href=\"x\">vendor</a>\nsaid it.<br/>Next</p><script>var a = '<p>no</p>';</script><style>p{}</style><p>Last &amp; done</p>"
	want := "\nOverview\n\nOn November 19, a vendor said it.\nNext\n\nLast & done\n"
	if got := proseText(in); got != want {
		t.Errorf("%q\nwant %q", got, want)
	}
	if got := proseText("a < b and <unclosed"); got != "a < b and <unclosed" {
		t.Errorf("%q", got)
	}
}

func TestPostFeed_RSSAndAtom(t *testing.T) {
	t.Parallel()
	rss := `<?xml version="1.0"?><rss xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:media="http://search.yahoo.com/mrss/" xmlns:atom="http://www.w3.org/2005/Atom" version="2.0"><channel><title>t</title>` +
		`<atom:link href="https://example.com/rss" rel="self"/>` +
		`<item><title><![CDATA[CVE-2026-1001 exploited]]></title><link>https://example.com/a</link><pubDate>Thu, 19 Nov 2026 21:06:24 GMT</pubDate>` +
		`<description><![CDATA[<p>short</p>]]></description><content:encoded><![CDATA[<p>long body</p>]]></content:encoded><media:content url="https://example.com/i.png"/><media:title>no</media:title></item>` +
		`<item><title>two</title><link>https://example.com/b</link><pubDate>Fri, 20 Nov 2026 10:30:36 +0000</pubDate><description>&lt;p&gt;only&amp;nbsp;this&lt;/p&gt;</description></item></channel></rss>`
	got, err := parsePostFeed(strings.NewReader(rss), "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Link != "https://example.com/a" || got[0].Title != "CVE-2026-1001 exploited" || got[0].Body != "<p>long body</p>" ||
		got[1].Body != "<p>only&nbsp;this</p>" || got[1].Date != "Fri, 20 Nov 2026 10:30:36 +0000" {
		t.Fatalf("%+v", got)
	}
	atom := `<?xml version='1.0' encoding='UTF-8'?><feed xmlns='http://www.w3.org/2005/Atom'><title>c</title><entry><published>2026-11-09T12:52:57.820-08:00</published>` +
		`<title type='text'>Stable</title><content type='html'>&lt;p&gt;x&lt;/p&gt;</content><link rel='replies' href='https://example.com/r'/><link rel='edit' href='https://example.com/e'/>` +
		`<link rel='alternate' type='text/html' href='https://example.com/post.html' title='Stable'/></entry></feed>`
	got, err = parsePostFeed(strings.NewReader(atom), "x")
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := postTime(got[0].Date); len(got) != 1 || got[0].Link != "https://example.com/post.html" || got[0].Body != "<p>x</p>" || !ok || d.Format(time.RFC3339) != "2026-11-09T20:52:57Z" {
		t.Fatalf("%+v", got)
	}
	for name, bad := range map[string]string{"not a feed": `<html><body>x</body></html>`, "broken": `<rss><channel><item><title>x</item>`} {
		if _, err := parsePostFeed(strings.NewReader(bad), "x"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	many := `<rss><channel>` + strings.Repeat(`<item></item>`, textMaxPosts+1) + `</channel></rss>`
	if _, err := parsePostFeed(strings.NewReader(many), "x"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("many posts: %v", err)
	}
	long := `<rss><channel><item><title>` + strings.Repeat("t", 3*textMaxTitle) + `</title></item></channel></rss>`
	if got, err := parsePostFeed(strings.NewReader(long), "x"); err != nil || len(got[0].Title) != textMaxTitle {
		t.Errorf("long title: %v", err)
	}
}

func TestAndroidNotes_TheNoteAndItsList(t *testing.T) {
	t.Parallel()
	page := `<p><em>Published  December 1,
2025 | Updated December 3, 2025</em></p><aside class="caution">There are indications that CVE-2026-1009 may be under limited, targeted exploitation.</aside>
<aside class="note">
    <b>Note</b>: There are indications that the following may be under limited,
    targeted exploitation.
    <ul>
        <li>CVE-2025-48633</li>
        <li>CVE-2025-48572</li>
    </ul>
</aside><aside class="note"><b>Note</b>: There are indications that CVE-2026-21385 may be under limited, targeted exploitation.</aside>`
	day, notes := androidNotes(page)
	if day.Format(time.DateOnly) != "2025-12-01" || len(notes) != 2 {
		t.Fatalf("%v %q", day, notes)
	}
	var got []string
	for _, n := range notes {
		cs, un, err := proseClaims(t.Context(), androidForms, "", n)
		if err != nil || un != 0 {
			t.Fatalf("%q: %v %d", n, err, un)
		}
		got = append(got, cs...)
	}
	if !slices.Equal(got, []string{"CVE-2025-48633", "CVE-2025-48572", "CVE-2026-21385"}) { // a caution box is not a note
		t.Errorf("%v", got)
	}
	if day, notes := androidNotes(`<aside class="note">x`); !day.IsZero() || len(notes) != 1 {
		t.Errorf("unclosed: %v %q", day, notes)
	}
}

func rapid7Feed(items ...[4]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><rss version="2.0"><channel><title>Rapid7</title>`)
	for _, it := range items {
		fmt.Fprintf(&b, `<item><title><![CDATA[%s]]></title><link>%s</link><pubDate>%s</pubDate><description><![CDATA[%s]]></description></item>`, it[0], it[1], it[2], it[3])
	}
	b.WriteString(`</channel></rss>`)
	return b.String()
}

func TestRapid7_PullsClaimsKeepsTheFirstSightingAndRetracts(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC))
	e.only(rapid7FeedID)
	e.mirror(rapid7FeedID, o.url("/rss.xml"))
	const p1, p2 = "https://www.rapid7.com/blog/post/etr-one", "https://www.rapid7.com/blog/post/etr-two"
	o.body("/rss.xml", `"a"`, rapid7Feed(
		[4]string{"CVE-2026-123890: authentication bypass in a virtualization manager", p1, "Thu, 19 Nov 2026 21:06:24 GMT",
			`<p>A malicious actor may exploit <a href="x">CVE-2026-123890</a> without credentials.</p><p>Also, Mandiant/Google Threat Intelligence confirmed in-the-wild exploitation of <a href="https://www.cve.org/CVERecord?id=CVE-2026-123890">CVE-2026-123890</a> by a state-linked threat actor as early as September 2026.</p>`},
		[4]string{"Patch notes", p2, "Tue, 10 Nov 2026 21:55:37 GMT", `<p>Exploitation of CVE-2026-2002 could allow code execution.</p>`},
		[4]string{"no date", "https://www.rapid7.com/blog/post/x", "", `<p>x</p>`},
	))
	if err := e.svc.Fetch(t.Context(), rapid7FeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(rapid7FeedID)
	// Rapid7's claims are kept without a link to the post: the row says only the CVE, the source and the date (the detail tells the
	// post apart by a digest, so a post that takes a claim back still removes it); the note names the post by its date
	if st.Status != "ok" || st.Records == nil || *st.Records != 1 || !strings.Contains(deref(st.Error), "1 sentence about exploitation in no form Vedette knows (first in the post of 10 Nov 2026)") ||
		strings.Contains(deref(st.Error), "rapid7.com") {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	d1, d2 := unlinkedDoc(p1).Detail, unlinkedDoc(p2).Detail
	if got := vendorRows(t, e, rapid7FeedID); got["CVE-2026-123890"] != "2026-11-19T21:06  "+d1+" 1" || len(got) != 1 {
		t.Fatalf("%v", got)
	}

	// unchanged: a 304, nothing read; then the post is edited to take the claim back and another post makes it
	before := len(o.all())
	e.setNow(e.clock().Add(6 * time.Hour))
	if err := e.svc.Fetch(t.Context(), rapid7FeedID); err != nil || len(o.all()) != before+1 || o.all()[before].header.Get("If-None-Match") != `"a"` {
		t.Fatalf("%v %d", err, len(o.all())-before)
	}
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body("/rss.xml", `"b"`, rapid7Feed(
		[4]string{"edited", p1, "Thu, 19 Nov 2026 21:06:24 GMT", `<p>Exploitation of CVE-2026-123890 has not been confirmed.</p>`},
		[4]string{"later", p2, "Fri, 20 Nov 2026 10:00:00 GMT", `<p>CVE-2026-123890 is now being actively exploited in the wild.</p><p>Rapid7 detected exploitation of CVE-2026-2003 against a customer.</p>`},
	))
	if err := e.svc.Fetch(t.Context(), rapid7FeedID); err != nil {
		t.Fatal(err)
	}
	got := vendorRows(t, e, rapid7FeedID)
	if got["CVE-2026-123890"] != "2026-11-19T21:06  "+d2+" 1" || got["CVE-2026-2003"] != "2026-11-20T10:00  "+d2+" 1" || len(got) != 2 {
		t.Fatalf("the row moves to the post that claims it, with its first date: %v %+v %q", got, e.feed(rapid7FeedID), deref(e.feed(rapid7FeedID).Error))
	}
	// both take it back: the row goes
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body("/rss.xml", `"c"`, rapid7Feed([4]string{"later", p2, "Fri, 20 Nov 2026 10:00:00 GMT", `<p>Rapid7 detected exploitation of CVE-2026-2003 against a customer.</p>`}))
	if err := e.svc.Fetch(t.Context(), rapid7FeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, rapid7FeedID); len(got) != 1 || got["CVE-2026-2003"] == "" {
		t.Fatalf("%v", got)
	}
}

func TestTextFeeds_AFirstPullLoadsTheSeed(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(gtiFeedID, ciscoFeedID)
	e.mirror(gtiFeedID, o.url("/gti.xml"))
	e.mirror(ciscoFeedID, o.url("/cisco.xml"))
	const now, old = "https://cloud.google.com/blog/topics/threat-intelligence/now/", "https://cloud.google.com/blog/topics/threat-intelligence/old/"
	e.svc.claimSeed = seedDocsOf(Seed{Claims: []SeedClaim{
		{CVE: "CVE-2026-3001", Source: gtiFeedID, Date: "2026-07-16T14:00:00Z", URL: old},
		{CVE: "CVE-2026-3002", Source: gtiFeedID, Date: "2026-09-29T14:00:00Z", URL: now}, // the post read now no longer says it
		{CVE: "CVE-2026-3003", Source: gtiFeedID, Date: "2026-09-29T14:00:00Z", URL: now},
		{CVE: "CVE-2025-20352", Source: ciscoFeedID, Date: "2025-09-24T16:00:00Z", URL: ciscoAdvisoryURL + "cisco-sa-snmp-x"},
	}})
	o.body("/gti.xml", `"g"`, rapid7Feed([4]string{"t", now, "Tue, 29 Sep 2026 14:00:00 +0000", `<p>GTIG identified active exploitation of CVE-2026-3003 by UNC1.</p>`}))
	o.body("/cisco.xml", `"c"`, ciscoFeed([2]string{"cisco-sa-a-1", "2026-11-20 20:37:16.0"}))
	o.body(ciscoDocPath("cisco-sa-a-1"), `"d"`, ciscoDoc("cisco-sa-a-1", "2026-11-20T16:00:00Z", "", nil, "CVE-2026-20999"))
	for _, id := range []string{gtiFeedID, ciscoFeedID} {
		if err := e.svc.Fetch(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	got := vendorRows(t, e, gtiFeedID)
	if len(got) != 2 || got["CVE-2026-3001"] != "2026-07-16T14:00 "+old+"  1" || !strings.HasPrefix(got["CVE-2026-3003"], "2026-09-29T14:00 "+now) {
		t.Fatalf("%v", got)
	}
	if got := vendorRows(t, e, ciscoFeedID); got["CVE-2025-20352"] != `2025-09-24T16:00 `+ciscoAdvisoryURL+`cisco-sa-snmp-x {"advisory":"cisco-sa-snmp-x"} 1` {
		t.Fatalf("%v", got)
	}
	// a later pull does not read the seed again: a seed claim the box dropped stays dropped
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_signal WHERE cve = 'CVE-2026-3001'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body("/gti.xml", `"g2"`, rapid7Feed([4]string{"t", now, "Tue, 29 Sep 2026 14:00:00 +0000", `<p>GTIG identified active exploitation of CVE-2026-3003 by UNC1.</p>`}))
	if err := e.svc.Fetch(t.Context(), gtiFeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, gtiFeedID); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

func TestRapid7_TheSeedsClaimsCarryNoLink(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(rapid7FeedID)
	e.mirror(rapid7FeedID, o.url("/rss.xml"))
	e.svc.claimSeed = seedDocsOf(Seed{Claims: []SeedClaim{
		{CVE: "CVE-2026-90436", Source: rapid7FeedID, Date: "2026-11-16T18:14:14Z"},
		{CVE: "CVE-2026-123890", Source: rapid7FeedID, Date: "2026-11-19T21:06:24Z"},
	}})
	const p1 = "https://www.rapid7.com/blog/post/p1"
	o.body("/rss.xml", `"a"`, rapid7Feed([4]string{"t", p1, "Fri, 20 Nov 2026 10:00:00 GMT", `<p>CVE-2026-123890 is now being actively exploited in the wild.</p>`}))
	if err := e.svc.Fetch(t.Context(), rapid7FeedID); err != nil {
		t.Fatal(err)
	}
	got := vendorRows(t, e, rapid7FeedID)
	if len(got) != 2 || got["CVE-2026-90436"] != "2026-11-16T18:14   1" || got["CVE-2026-123890"] != "2026-11-19T21:06  "+unlinkedDoc(p1).Detail+" 1" {
		t.Fatalf("%v", got)
	}
	if _, err := ParseSeed([]byte(`{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":""}]}`)); err != nil {
		t.Errorf("a Rapid7 claim without a link: %v", err)
	}
	for _, bad := range []string{
		`{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"https://www.rapid7.com/blog/post/p1"}]}`,
		`{"claims":[{"cve":"CVE-2026-1001","source":"gti-blog","date":"2026-11-19T21:06:24Z","url":""}]}`,
	} {
		if _, err := ParseSeed([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func androidPage(published, note string) string {
	return `<html><body><p><em>Published ` + published + `</em></p><aside class="note"><b>Note</b>: ` + note + `</aside><table><tr><td>CVE-2026-0999</td></tr></table></body></html>`
}

func TestAndroid_ThisMonthAndLastConditionalAndOlderAddress(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 1, 5, 6, 0, 0, 0, time.UTC))
	e.only(androidFeedID)
	e.mirror(androidFeedID, o.url("/docs/security/bulletin/"))
	// last month only under the older address; this month under its year's folder, answering 304 to its own ETag
	o.serve("/docs/security/bulletin/2025/2025-12-01", http.NotFound)
	o.body("/docs/security/bulletin/2025-12-01", `"dec"`, androidPage("December 1, 2025", "There are indications that the following may be under limited, targeted exploitation.<ul><li>CVE-2025-48633</li><li>CVE-2025-48572</li></ul>"))
	o.body("/docs/security/bulletin/2026/2026-01-01", `"jan"`, androidPage("January 5, 2026", "There are no indications that CVE-2026-0001 may be under limited, targeted exploitation."))
	if err := e.svc.Fetch(t.Context(), androidFeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(androidFeedID)
	if st.Status != "ok" || st.Records == nil || *st.Records != 2 {
		t.Fatalf("%+v %q", st, deref(st.Error))
	}
	got := vendorRows(t, e, androidFeedID)
	if got["CVE-2025-48633"] != "2025-12-01T00:00 "+o.url("/docs/security/bulletin/2025-12-01")+"  1" || len(got) != 2 {
		t.Fatalf("%v", got)
	}
	// the next pull asks each page with its ETag: both unchanged, the claims stand
	n := len(o.all())
	e.setNow(e.clock().Add(6 * time.Hour))
	if err := e.svc.Fetch(t.Context(), androidFeedID); err != nil {
		t.Fatal(err)
	}
	for _, h := range o.all()[n:] {
		if h.path == "/docs/security/bulletin/2026/2026-01-01" && h.header.Get("If-None-Match") != `"jan"` {
			t.Errorf("%s %v", h.path, h.header)
		}
	}
	if got := vendorRows(t, e, androidFeedID); len(got) != 2 || e.feed(androidFeedID).Status != "ok" {
		t.Fatalf("%v", got)
	}
	// December's note is taken back: the rows go
	e.setNow(e.clock().Add(6 * time.Hour))
	o.body("/docs/security/bulletin/2025-12-01", `"dec2"`, androidPage("December 1, 2025", "Corrected."))
	if err := e.svc.Fetch(t.Context(), androidFeedID); err != nil {
		t.Fatal(err)
	}
	if got := vendorRows(t, e, androidFeedID); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestApple_ClaimsComeFromTheCatalogueDescriptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	// write replaces descriptions as the CVE records and NVD writers do: Apple's claims are reconciled at the end of the write
	write := func(descs ...[3]string) map[string]string {
		t.Helper()
		if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
			added := map[string]bool{}
			for _, d := range descs {
				if err := appleNoteAdded(t.Context(), tx, d[0], d[2], added); err != nil {
					return err
				}
				if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, description, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET description = excluded.description`, d[0], d[1], d[2], "2026-11-21T06:00:00.000Z"); err != nil {
					return err
				}
			}
			return applyAppleClaims(t.Context(), tx, now, added)
		}); err != nil {
			t.Fatal(err)
		}
		return vendorRows(t, e, appleClaimSource)
	}
	const claim = "Processing a file may lead to code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26."
	got := write(
		[3]string{"CVE-2026-20700", "2026-02-11T00:00:00.000Z", claim + " CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report."},
		[3]string{"CVE-2026-20701", "2026-02-11T00:00:00.000Z", "A use-after-free issue was addressed with improved memory management. Apple is aware of the report above."},
		[3]string{"CVE-2026-20702", "2026-11-22T00:00:00.000Z", claim}, // published in the future: dated now
		// Apple's sentence in parentheses, as in CVE-2025-24201's record
		[3]string{"CVE-2025-24201", "2025-03-11T00:00:00.000Z", "This is a supplementary fix for an attack that was blocked in iOS 17.2. (Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 17.2.)"},
		[3]string{"CVE-2026-20703", "2026-03-01T00:00:00.000Z", "A logic issue was addressed. Apple is aware of the issue."},
	)
	if len(got) != 3 || got["CVE-2026-20700"] != "2026-02-11T00:00 "+cveRecordPage+"CVE-2026-20700  1" || !strings.HasPrefix(got["CVE-2026-20702"], "2026-11-21T06:00") ||
		!strings.HasPrefix(got["CVE-2025-24201"], "2025-03-11T00:00") {
		t.Fatalf("%v", got)
	}
	// a description the catalogue held without the claim gains it months after publication: dated by this sighting, as Cisco's and
	// Fortinet's late claims; a description that no longer says it loses its row; a row held keeps its date when written again
	got = write(
		[3]string{"CVE-2026-20703", "2026-03-01T00:00:00.000Z", claim},
		[3]string{"CVE-2026-20702", "2026-11-22T00:00:00.000Z", "Apple is aware of a report that this issue was fixed."},
		[3]string{"CVE-2026-20700", "2026-02-11T00:00:00.000Z", claim},
	)
	if len(got) != 3 || !strings.HasPrefix(got["CVE-2026-20703"], "2026-11-21T06:00") || !strings.HasPrefix(got["CVE-2026-20700"], "2026-02-11T00:00") || got["CVE-2026-20702"] != "" {
		t.Fatalf("%v", got)
	}
}

func TestSeed_TheReleaseSeedAndTheMerge(t *testing.T) {
	t.Parallel()
	s, err := ParseSeed(signaldata.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Claims) == 0 || string(s.JSON()) != string(signaldata.Seed) {
		t.Errorf("the release's seed is not in the generator's form (%d claims)", len(s.Claims))
	}
	if docs := releaseSeed(); len(docs[rapid7FeedID]) == 0 {
		t.Errorf("no Rapid7 claims in the seed")
	}
	for name, bad := range map[string]string{
		"a bad id":       `{"claims":[{"cve":"CVE-26-1","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"https://example.com/a"}]}`,
		"another source": `{"claims":[{"cve":"CVE-2026-1001","source":"cisa-kev","date":"2026-11-19T21:06:24Z","url":"https://example.com/a"}]}`,
		"a bad date":     `{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"19 Nov","url":"https://example.com/a"}]}`,
		"http":           `{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"http://example.com/a"}]}`,
		"another host":   `{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"https://cloud.google.com/blog/x"}]}`,
		"twice":          `{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"https://example.com/a"},{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-18T21:06:24Z","url":"https://example.com/b"}]}`,
		"text":           `{"claims":[{"cve":"CVE-2026-1001","source":"rapid7-blog","date":"2026-11-19T21:06:24Z","url":"https://example.com/a","text":"x"}]}`,
	} {
		if _, err := ParseSeed([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	prev := Seed{Claims: []SeedClaim{
		{CVE: "CVE-2026-1001", Source: rapid7FeedID, Date: "2026-11-01T00:00:00Z", URL: "https://example.com/old"},
		{CVE: "CVE-2026-1002", Source: rapid7FeedID, Date: "2026-11-02T00:00:00Z", URL: "https://example.com/taken-back"},
	}}
	next := MergeSeed(prev, []SeedRead{
		{URL: "https://example.com/taken-back"},
		{URL: "https://example.com/new", Claims: []SeedClaim{
			{CVE: "CVE-2026-1001", Source: rapid7FeedID, Date: "2026-11-10T00:00:00Z", URL: "https://example.com/new"},
			{CVE: "CVE-2026-1003", Source: rapid7FeedID, Date: "2026-11-10T00:00:00Z", URL: "https://example.com/new"},
		}},
	})
	want := []SeedClaim{
		{CVE: "CVE-2026-1001", Source: rapid7FeedID, Date: "2026-11-01T00:00:00Z", URL: "https://example.com/old"},
		{CVE: "CVE-2026-1003", Source: rapid7FeedID, Date: "2026-11-10T00:00:00Z", URL: "https://example.com/new"},
	}
	if !slices.Equal(next.Claims, want) {
		t.Errorf("%+v", next.Claims)
	}
}

// The hostile shapes of the review, at the bounds: each was minutes of CPU (tags × size, or quadratic joins) and must now be one
// pass. The bound is generous (each takes milliseconds), so it fails only on a return of the old cost.
func TestProseParsers_HostileShapesStayLinear(t *testing.T) { //nolint:paralleltest // times its own work
	const limit = 3 * time.Second
	timed := func(name string, f func()) {
		t.Helper()
		start := time.Now()
		f()
		if d := time.Since(start); d > limit {
			t.Errorf("%s took %v", name, d)
		}
	}
	for name, body := range map[string]string{
		"script tags":       strings.Repeat("<script></script>", textMaxPost/17),
		"style tags, upper": strings.Repeat("<STYLE>x</Style >", textMaxPost/17),
		"open brackets":     strings.Repeat("<", textMaxPost),
		"far brackets":      strings.Repeat("<"+strings.Repeat("a", 3000), textMaxPost/3001) + ">",
		"script never shut": strings.Repeat("<script>", textMaxPost/8),
	} {
		timed(name, func() { _ = proseText(body) })
	}
	split := `<rss><channel><item><link>https://example.com/a</link><description>` + strings.Repeat("a<!---->", textFeedMaxBytes/8) + `</description></item></channel></rss>`
	timed("text split by comments", func() {
		posts, err := parsePostFeed(strings.NewReader(split), "x")
		if err != nil || len(posts) != 1 || len(posts[0].Body) != min(textMaxPost, textFeedMaxBytes/8) {
			t.Errorf("%v %d", err, len(posts))
		}
	})
	deep := `<rss><channel>` + strings.Repeat("<a>", textFeedMaxBytes/3)
	timed("nested tags", func() {
		if _, err := parsePostFeed(strings.NewReader(deep), "x"); err == nil || !strings.Contains(err.Error(), "nested more than 64") {
			t.Errorf("%v", err)
		}
	})
	if _, err := parsePostFeed(strings.NewReader(`<rss><channel>`+strings.Repeat("<a>", textMaxDepth-2)+strings.Repeat("</a>", textMaxDepth-2)+`</channel></rss>`), "x"); err != nil {
		t.Errorf("64 levels: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var read vendorRead
	if err := postClaims(ctx, []post{{Link: "https://example.com/a", Date: "Thu, 19 Nov 2026 21:06:24 GMT", Body: "x"}}, proseForms, false, &read); err == nil {
		t.Error("a cancelled pull read its posts")
	}
}
