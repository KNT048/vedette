package feeds

import (
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

var vcNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// vcEntryJSON is one entry as VulnCheck writes it (cve is an array).
func vcEntryJSON(cve, vendor, product, added, cisa string) string {
	c := ""
	if cisa != "" {
		c = fmt.Sprintf(`,"cisa_date_added":%q`, cisa)
	}
	return fmt.Sprintf(`{"vendorProject":%q,"product":%q,"shortDescription":"d","vulnerabilityName":"%s flaw","required_action":"Apply updates.","knownRansomwareCampaignUse":"Unknown","cve":[%q],"vulncheck_reported_exploitation":[{"url":"https://example.org/%s","date_added":"2026-10-30T00:00:00.000Z"},{"url":"http://plain.example/x","date_added":"2026-10-31T00:00:00.000Z"}],"date_added":%q%s}`,
		vendor, product, product, cve, cve, added+"T00:00:00.000Z", c)
}

func vcPage(totalPages int, entries ...string) string {
	return fmt.Sprintf(`{"_benchmark":0.01,"_meta":{"timestamp":"2026-11-05T12:00:00Z","index":"vulncheck-kev","limit":100,"total_pages":%d,"page":1},"data":[%s]}`, totalPages, strings.Join(entries, ","))
}

// D-557: only recent entries CISA does not list become vulncheck-kev entries; a bad entry is rejected and counted.
func TestParseVulnCheckPage(t *testing.T) {
	t.Parallel()
	res, err := ParseVulnCheckPage([]byte(vcPage(3,
		vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""),
		vcEntryJSON("CVE-2026-1002", "Acme", "Router", "2026-10-30", "2026-11-01"), // CISA lists it
		vcEntryJSON("CVE-2024-1003", "Acme", "Old", "2024-01-30", ""),              // older than the window
		vcEntryJSON("not-a-cve", "Acme", "Bad", "2026-10-30", ""),
		`{"cve":["CVE-2026-1004"],"vendorProject":"Acme","product":"P","date_added":"yesterday"}`,
		`{"cve":["CVE-2026-1005"],"vendorProject":7,"product":"P"}`,
		`{"cve":["CVE-2026-1006"],"vendorProject":"Acme\u0000x","product":"P","date_added":"2026-10-30T00:00:00Z"}`,
	)), vcNow, nil)
	if err != nil || res.TotalPages != 3 || res.FirstCVE != "CVE-2026-1001" || len(res.Vulns) != 1 || res.Accepted != 3 || res.Rejected != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	v := res.Vulns[0]
	if v.CVE != "CVE-2026-1001" || v.DateAdded != "2026-10-30" || !slices.Equal(v.Links, []string{"https://example.org/CVE-2026-1001"}) || // the http link is dropped
		!strings.HasPrefix(v.RequiredAction, vulnCheckAction+" First reported exploited 2026-10-30. Apply updates.") {
		t.Errorf("vuln = %+v", v)
	}
	for name, body := range map[string]string{
		"html": `<html>sign in</html>`, "no data": `{"_meta":{}}`, "data not a list": `{"data":{"x":1}}`,
		"too large": `{"data":[` + strings.Repeat(" ", MaxBodyBytes) + `]}`,
	} {
		if _, err := ParseVulnCheckPage([]byte(body), vcNow, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a page claiming more than twice the page size is cut: the rest is not trusted
	many := make([]string, vulnCheckPage*2+50)
	for i := range many {
		many[i] = vcEntryJSON(fmt.Sprintf("CVE-2026-%05d", 2000+i), "Acme", "P", "2026-10-30", "")
	}
	if res, err := ParseVulnCheckPage([]byte(vcPage(1, many...)), vcNow, nil); err != nil || len(res.Vulns) != vulnCheckPage*2 || !res.Truncated {
		t.Errorf("oversize: %d %v %v", len(res.Vulns), res.Truncated, err)
	}
}

func TestVulnCheckPageURL(t *testing.T) {
	t.Parallel()
	u, err := VulnCheckPageURL("https://api.vulncheck.com/v3/index/vulncheck-kev", 2)
	if err != nil || u != "https://api.vulncheck.com/v3/index/vulncheck-kev?limit=100&page=2" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"https://api.vulncheck.com/v3?token=abc", "http://example.com/x", "https://u:p@example.com/x"} {
		if _, err := VulnCheckPageURL(bad, 1); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// D-557: OFF means no request; the key is stored sealed and shown as its last four characters; the feed sends it only as
// the bearer header; its CVEs become exploited entries next to CISA's (CISA wins), get CVE.org ranges, and everything
// goes when the key is removed.
func TestContract_VulnCheckKEV_BYOK(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()                                // every feed off; VulnCheck KEV stays off until a key is saved
	e.setURL("vulncheck-kev", o.url("/vc")) // no mirror through the API (L3): the test points the address itself
	if c, b := e.put("vulncheck-kev", `{"url":"https://example.net/vc"}`); c != 400 || code(b) != "invalid_url" {
		t.Fatalf("an address for the key to follow: %d %v", c, b)
	}
	const key = "vckey-ABCDEF123456"
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-1002", "Acme", "Router", "2026-11-01")}, false)
	o.serve("/vc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(vcPage(2, vcEntryJSON("CVE-2026-1003", "Initech", "Portal", "2026-11-02", ""))))
			return
		}
		_, _ = w.Write([]byte(vcPage(2,
			vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""),
			vcEntryJSON("CVE-2026-1002", "Acme", "Router", "2026-10-30", "2026-11-01"))))
	})

	// off, and no key: no request, and it cannot be turned on
	if c, b := e.put("vulncheck-kev", `{"enabled":true}`); c != 400 || code(b) != "invalid_auth" {
		t.Fatalf("on without a key: %d %v", c, b)
	}
	if c, _ := e.fetch("vulncheck-kev"); c == 200 || len(o.all()) != 0 {
		t.Fatalf("fetched while off: %d, %d requests", c, len(o.all()))
	}
	if c, b := e.put("vulncheck-kev", `{"api_key":"short"}`); c != 400 || code(b) != "invalid_auth" {
		t.Fatalf("short key: %d %v", c, b)
	}
	if c, b := e.put("ipsum", `{"api_key":"`+key+`"}`); c != 400 {
		t.Fatalf("a key on another feed: %d %v", c, b)
	}

	// saving the key turns it on
	c, b := e.put("vulncheck-kev", `{"api_key":"`+key+`"}`)
	if c != 200 || at(b, "enabled") != true || at(b, "auth", "type") != "bearer" || at(b, "auth", "secret_last4") != "3456" || strings.Contains(fmt.Sprint(b), "ABCDEF") {
		t.Fatalf("save key: %d %v", c, b)
	}
	if _, list := e.get("/feeds/sources"); strings.Contains(fmt.Sprint(list), "ABCDEF") {
		t.Fatal("the key is in the feed list")
	}
	var plain int
	_ = e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM feeds_source WHERE id = 'vulncheck-kev' AND secret_id IS NOT NULL AND (url || coalesce(error, '') || coalesce(secret_last4, '')) NOT LIKE '%ABCDEF%'`).Scan(&plain)
	if plain != 1 {
		t.Fatal("the key is not held by core/secrets or leaks into the row")
	}
	c, b = e.fetch("vulncheck-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "records") != 2.0 {
		t.Fatalf("fetch: %d %v", c, b)
	}
	for _, h := range o.all() {
		if strings.Contains(h.query, "ABCDEF") || strings.Contains(h.query, "token") {
			t.Fatalf("the key is in the address: %s", h.query)
		}
	}
	if strings.Contains(e.auditText(), "ABCDEF") {
		t.Fatal("the key is in the audit log")
	}
	rows, err := e.svc.st.KevVulns(t.Context())
	owners := map[string]string{}
	for _, r := range rows {
		owners[r.CVE] = r.SourceID
	}
	if err != nil || len(owners) != 3 || owners["CVE-2026-1001"] != "vulncheck-kev" || owners["CVE-2026-1003"] != "vulncheck-kev" || owners["CVE-2026-1002"] != "cisa-kev" {
		t.Fatalf("owners = %v %v", owners, err)
	}
	if base := e.pub.named(EventSyncBaseline); len(base) != 1 || base[0] != (SyncBaselineEvent{Source: "vulncheck-kev", Count: 2}) {
		t.Errorf("first fill: %v", base)
	}
	if keys, err := e.svc.st.KevCVEsByKeys(t.Context(), []string{"acme|gateway"}); err != nil || !slices.Equal(keys, []string{"CVE-2026-1001"}) {
		t.Errorf("matching by product: %v %v", keys, err)
	}
	// its CVEs are among those CVE.org is asked for ranges (NVD has none)
	todo, err := e.svc.st.cveOrgTodo(t.Context(), vcNow, 10)
	if err != nil || len(todo) != 3 {
		t.Errorf("CVE.org todo: %v %v", todo, err)
	}

	// a new entry later is news, not baseline
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vcPage(1, vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""), vcEntryJSON("CVE-2026-1009", "Acme", "Gateway", "2026-11-05", ""))))
	})
	if c, _ := e.fetch("vulncheck-kev"); c != 200 {
		t.Fatal(c)
	}
	if news := e.pub.named(EventNewKEV); len(news) != 1 || news[0].(NewKEVEvent).CVE != "CVE-2026-1009" {
		t.Errorf("new_kev: %v", news)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 2 { // 1003 is no longer listed
		t.Errorf("%d rows", n)
	}

	// a refused key is the customer's to fix; the text never has the key
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	e.fetch("vulncheck-kev")
	if f := e.feed("vulncheck-kev"); f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "did not accept the API key") || strings.Contains(*f.Error, "ABCDEF") {
		t.Fatalf("feed = %+v", f)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 2 {
		t.Errorf("a refused pull changed the data: %d rows", n)
	}

	// removing the key: off, data gone, key gone; the CISA entry stays
	c, b = e.put("vulncheck-kev", `{"api_key":""}`)
	if c != 200 || at(b, "enabled") != false || at(b, "auth", "type") != "none" || at(b, "auth", "secret_last4") != nil || at(b, "status") != "never" {
		t.Fatalf("remove key: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 0 {
		t.Errorf("%d rows left", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'cisa-kev'`); n != 1 {
		t.Errorf("CISA rows: %d", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_secret WHERE purpose = 'feeds_source.secret'`); n != 0 {
		t.Errorf("%d secrets left", n)
	}

	// saving a key again is a first fill again: quiet, however many entries come back (review L2)
	before := len(e.pub.named(EventNewKEV))
	e.setNow(e.clock().Add(time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vcPage(1, vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""))))
	})
	if c, _ := e.put("vulncheck-kev", `{"api_key":"`+key+`"}`); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.fetch("vulncheck-kev"); c != 200 || len(e.pub.named(EventNewKEV)) != before || len(e.pub.named(EventSyncBaseline)) != 2 {
		t.Errorf("a key saved again alerted: new_kev %d -> %d, baselines %d", before, len(e.pub.named(EventNewKEV)), len(e.pub.named(EventSyncBaseline)))
	}
}

func (e *env) setURL(id, url string) {
	e.t.Helper()
	write(e.t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), `UPDATE feeds_source SET url = ? WHERE id = ?`, url, id)
		return err
	})
}

// Review M1: a list that is not provably complete fails the pull and the rows loaded before stay.
func TestVulnCheckPull_FailsClosedWhenTheListIsNotComplete(t *testing.T) {
	t.Parallel()
	for name, serve := range map[string]func(page string) string{
		"no page count": func(string) string {
			return `{"data":[` + vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", "") + `]}`
		},
		"too many pages": func(string) string {
			return vcPage(61, vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""))
		},
		"page ignored": func(string) string {
			return vcPage(3, vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""))
		},
		"an empty page": func(p string) string {
			if p == "2" {
				return vcPage(3)
			}
			return vcPage(3, vcEntryJSON("CVE-2026-100"+p, "Acme", "Gateway", "2026-10-30", ""))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, o := pullEnv(t)
			e.only()
			e.setURL("vulncheck-kev", o.url("/vc"))
			if c, b := e.put("vulncheck-kev", `{"api_key":"vckey-ABCDEF123456"}`); c != 200 {
				t.Fatalf("%d %v", c, b)
			}
			applyV(t, e.db, epoch0, "vulncheck-kev", []Vuln{vuln("CVE-2026-1099", "Acme", "Old", "2026-10-01")}, false)
			o.serve("/vc", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(serve(r.URL.Query().Get("page")))) })
			e.fetch("vulncheck-kev")
			f := e.feed("vulncheck-kev")
			if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "could not be read completely") {
				t.Fatalf("feed = %+v", f)
			}
			if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev' AND cve = 'CVE-2026-1099'`); n != 1 {
				t.Fatal("the rows loaded before were deleted")
			}
		})
	}
}

// Review M2, L1, L2, L4: a held entry stays past 180 days while VulnCheck lists it; VulnCheck takes a custom feed's CVE but
// never CISA's; CISA takes VulnCheck's over (announced as KEV); an entry with several CVEs gives each its row; a CVE
// that is new after every row went is news, not a baseline.
func TestVulnCheckEntries_OwnershipAndWindow(t *testing.T) {
	t.Parallel()
	old := vcEntryJSON("CVE-2025-2001", "Acme", "Gateway", "2025-01-30", "")
	res, err := ParseVulnCheckPage([]byte(vcPage(1, old)), vcNow, nil)
	if err != nil || len(res.Vulns) != 0 {
		t.Fatalf("old, not held: %v %v", res.Vulns, err)
	}
	if res, err = ParseVulnCheckPage([]byte(vcPage(1, old)), vcNow, map[string]bool{"CVE-2025-2001": true}); err != nil || len(res.Vulns) != 1 {
		t.Fatalf("old, held: %v %v", res.Vulns, err)
	}
	multi := strings.Replace(vcEntryJSON("CVE-2026-3001", "Acme", "Gateway", "2026-10-30", ""), `["CVE-2026-3001"]`, `["CVE-2026-3001","cve-2026-3002","junk","CVE-2026-3001"]`, 1)
	if res, err = ParseVulnCheckPage([]byte(vcPage(1, multi)), vcNow, nil); err != nil || len(res.Vulns) != 2 || res.Vulns[1].CVE != "CVE-2026-3002" || res.Accepted != 1 {
		t.Fatalf("several CVEs: %+v %v", res, err)
	}

	e := newEnv(t)
	applyV(t, e.db, epoch0, "ipsum", nil, false) // keeps the helper honest: the source row exists
	_ = e
	db := e.db
	// another feed's CVE is taken over by VulnCheck, a CISA one is not
	applyV(t, db, epoch0, "nuclei-templates", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-01")}, false)
	applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-4002", "Acme", "B", "2026-11-01")}, false)
	fresh, _ := applyV(t, db, epoch0, "vulncheck-kev", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-01"), vuln("CVE-2026-4002", "Acme", "B", "2026-11-01")}, false)
	owner := func(c string) string {
		var s string
		_ = db.Reader().QueryRowContext(t.Context(), `SELECT source_id FROM feeds_vuln WHERE cve = ?`, c).Scan(&s)
		return s
	}
	if owner("CVE-2026-4001") != "vulncheck-kev" || owner("CVE-2026-4002") != "cisa-kev" || len(fresh) != 1 {
		t.Fatalf("owners %s %s, fresh %d", owner("CVE-2026-4001"), owner("CVE-2026-4002"), len(fresh))
	}
	// CISA takes VulnCheck's row over: its first sighting as KEV
	if fresh, _ = applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-02")}, false); len(fresh) != 1 || owner("CVE-2026-4001") != "cisa-kev" {
		t.Fatalf("CISA take-over: %v %s", fresh, owner("CVE-2026-4001"))
	}
}
